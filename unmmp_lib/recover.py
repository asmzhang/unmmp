# -*- coding: utf-8 -*-
"""Recover native boundaries and symbols by executing the APK's own code."""
import os
import struct

from .dex import Dex
from .emulate import NativeRuntime, EmulationError
from .pools import Pools
from .lifter import parse_tries, type_words
from unicorn import arm64_const as aa, x86_const as xx
from .decoder import decode, shorty_of


class Recovery:
    def __init__(self, nm, vm, dexes, log=print):
        self.nm, self.vm, self.log = nm, vm, log
        self.dexes = [Dex(d) for d in dexes]
        self.definitions = {key: val for dex in self.dexes for key, val in dex.definitions.items()}
        self.runtime = NativeRuntime(nm, vm)
        self.methods = []
        self.blobs = {}
        self.sessions = {}

    def extract(self):
        self.bind()
        self.capture()
        return self

    def bind(self):
        r = self.runtime
        entry = r.symbols.get('JNI_OnLoad')
        if not entry:
            raise EmulationError('JNI_OnLoad export missing')
        r.call(entry, [r.jvm, 0])
        registrars = list(r.registrations)
        r.registrations = []
        for init in registrars:
            key = (init['class'], init['name'], init['sig'])
            indices = sorted({idx for d in self.dexes for idx in d.registration_calls(key)})
            self.log('[*] registrar %s.%s: %d calls' % (init['class'], init['name'], len(indices)))
            for idx in indices:
                r.call(init['entry'], [r.env, r.handle('class', init['class']), idx])
        seen = set()
        for m in r.registrations:
            key = (m['class'], m['name'], m['sig'])
            if key in seen:
                continue
            if key not in self.definitions or not (self.definitions[key][0] & 0x100):
                raise EmulationError('registered native does not match dex: %s' % (key,))
            seen.add(key)
            self.methods.append(dict(m, thunk=m['entry'] - r.BASES[0]))
        if not self.methods:
            raise EmulationError('no protected methods registered from dex call sites')
        self.log('[*] native bindings validated: %d' % len(self.methods))
        return self


    def _reset_flag(self, entry):
        """Clear the one-shot decrypt flag in front of a lazy thunk.

        Each wrapper is guarded by a per-method flag: the first call runs an XOR
        decrypt stub that writes the real body into a scratch buffer and falls
        through into the implementation; later calls jump straight to the
        implementation and reuse whatever the buffer holds.  A capture run must
        therefore force the flag back to 0 for every method, otherwise a thunk
        shared by several dex methods (or one already touched by an earlier
        probe) hands back a stale or still-encrypted buffer.
        """
        import capstone
        r = self.runtime
        try:
            code = bytes(r.uc.mem_read(entry, 4 * 24))
        except Exception:
            return None
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        base = None
        for ins in md.disasm(code, entry):
            if ins.mnemonic == 'adrp' and ins.op_str.startswith('x8,'):
                base = int(ins.op_str.split('#', 1)[1], 0)
            elif base is not None and ins.mnemonic == 'add' and ins.op_str.startswith('x8, x8, #'):
                base += int(ins.op_str.rsplit('#', 1)[1], 0)
            elif base is not None and ins.mnemonic in ('ldar', 'ldr') and '[x8]' in ins.op_str:
                r.uc.mem_write(base, b'\0\0\0\0')
                return base
        return None

    def capture(self):
        r = self.runtime
        self.failures = []
        r.capture_vm = True
        this_handle = r.handle('object', 'this')
        temporary = r.heap_next
        for i, m in enumerate(self.methods):
            r.heap_next = temporary
            # PATCH(mmpfit): several dex methods can share one wrapper thunk, and
            # the shell decrypts each body into a *shared* scratch buffer that is
            # only rewritten while the per-method flag is still 0. Calling a thunk
            # a second time therefore re-reads whatever the previous method left
            # behind (ciphertext or a foreign body), so capture each thunk once.
            self._reset_flag(m['entry'])
            # PATCH(mmpfit): a single unmapped method must not abort a
            # 1500-method run; UNMMP_CAPTURE_TOLERANT records and skips.
            try:
                r.vm_call = None
                # Also survives jboolean/jbyte/jchar/jshort argument narrowing.
                marker = 0x5b
                marker64 = marker | marker << 32
                if r.machine == 183:
                    for j in range(8):
                        r.uc.reg_write(getattr(aa, 'UC_ARM64_REG_D%d' % j), marker64)
                elif r.machine == 62:
                    for j in range(8):
                        r.uc.reg_write(getattr(xx, 'UC_X86_REG_XMM%d' % j), marker64)
                params = m['sig'][1:m['sig'].index(')')]
                static = bool(self.definitions[(m['class'], m['name'], m['sig'])][0] & 8)
                ins_words = type_words(params) + int(not static)
                r.call(m['entry'], [r.env, this_handle] + [marker] * max(32, ins_words + 4))
                if r.vm_call is None:
                    raise EmulationError('native method did not reach VM entry: %s' % m['name'])
                args = r.vm_call
                code, resolver = args[2:4] if r.ptr == 4 else args[1:3]
                insns = r.read_ptr(code)
                size = int.from_bytes(r.uc.mem_read(code + r.ptr, 4), 'little')
                regs = r.read_ptr(code + 2 * r.ptr)
                flags = r.read_ptr(code + 3 * r.ptr)
                tries = r.read_ptr(code + 4 * r.ptr)
                nregs = (flags-regs)//8 if flags > regs and (flags-regs)%8 == 0 else None
                if ins_words and nregs is None:
                    region_end = r.STACK + 0x200000 if r.STACK <= regs < r.STACK + 0x200000 else r.heap_next
                    limit = min(65536, (region_end-regs)//8)
                    frame = bytes(r.uc.mem_read(regs, 8*limit))
                    parameter_marker = marker if static else this_handle
                    found = next((j for j in range(limit)
                                  if struct.unpack_from('<I', frame, 8*j)[0] == parameter_marker), None)
                    if found is None:
                        raise EmulationError('could not recover parameter register position: %s' % m['name'])
                    nregs = found + ins_words
                if not (0 < size < 0x100000 and r.BASES[0] <= insns < r.BASES[1]):
                    raise EmulationError('invalid captured vmCode for %s' % m['name'])
                va = insns - r.BASES[0]
                off = self.nm.vaddr_to_off(va)
                if off + 2*size > len(self.nm.data):
                    raise EmulationError('captured instructions exceed ELF image')
                # The decrypt stub writes the real body into emulator memory;
                # the ELF image still holds the ciphertext, so the live buffer is
                # the only place the plaintext exists. Snapshot it per call.
                live = bytes(r.uc.mem_read(insns, 2 * size))
                m['units'] = list(struct.unpack('<%dH' % size, live))
                m['resolver'] = resolver
                self.blobs[m['thunk']] = {'units': m['units'],
                                         'insns': va, 'size': size,
                                         'tries': tries - r.BASES[0] if tries else None,
                                         'nregs': nregs, 'resolver': resolver}
                m['resolver'] = resolver
                self.sessions.setdefault(resolver, Pools())
                if (i+1) % 2000 == 0:
                    self.log('[*] captured blobs: %d/%d' % (i+1, len(self.methods)))
            except EmulationError as exc:
                if os.environ.get('UNMMP_CAPTURE_TOLERANT') != '1':
                    raise
                self.failures.append({'class': m['class'], 'name': m['name'],
                                      'sig': m['sig'], 'error': str(exc)})
                continue
        r.heap_next = temporary
        r.capture_vm = False
        self.log('[*] blobs captured: %d/%d (%d resolvers, %d skipped)' %
                 (len(self.blobs), len(self.methods), len(self.sessions),
                  len(self.failures)))
        return self

    def instructions(self, method):
        if method.get('units'):
            return method['units']
        th = self.blobs[method['thunk']]
        return struct.unpack_from('<%dH' % th['size'], self.nm.data,
                                  self.nm.vaddr_to_off(th['insns']))

    def resolve(self, resolver, kind, idx, static=False):
        pool = self.sessions[resolver]
        attr = {0:'fields', 1:'methods', 2:'types', 5:'const_strings'}[kind]
        values = getattr(pool, attr)
        if idx < len(values) and values[idx] is not None:
            return values[idx]
        r = self.runtime
        fn = r.read_ptr(resolver + kind * r.ptr)
        try:
            result = r.call(fn, [r.env, idx, int(static)])
        except EmulationError as exc:
            raise EmulationError('resolver %#x kind=%d index=%d static=%s: %s' %
                                 (resolver,kind,idx,static,exc)) from exc
        if kind in (0, 1):
            label = 'field' if kind == 0 else 'method'
            events = [e for e in r.events if e[0] == label]
            if events:
                _, cls, name, sig, _ = events[-1]
            else:
                # A previous probe may have populated the native resolver cache.
                offset = (8 if r.ptr == 8 else 4) if kind == 0 else 2*r.ptr
                handle = r.read_ptr(result + offset)
                cls, name, sig = r.classes[handle]
            cref = cls if cls.startswith('[') else 'L'+cls+';'
            value = {'cls': cref, 'name': name, 'type' if kind == 0 else 'proto': sig}
        elif kind == 2:
            value = r.cstring(result)
        else:
            value = r.classes[result]
        values.extend([None] * (idx + 1 - len(values)))
        values[idx] = value
        return value

    def resolve_references(self, mapping):
        self.methods = [m for m in self.methods if m['thunk'] in self.blobs]
        failures = []
        for m in self.methods:
            th = self.blobs[m['thunk']]
            ins = self.instructions(m)
            ok, error, ops = decode(ins, th['size'], shorty_of(m['sig']), mapping)
            if not ok:
                failures.append((m['class']+'.'+m['name'], error))
                continue
            res = m.get('resolver')
            if res is None:
                # Statically bound methods have no captured resolver session, so
                # their references stay symbolic instead of crashing the pass.
                continue
            for pc, op, name, size in ops:
                # A single unresolvable index must not abandon the whole corpus:
                # the reference simply stays symbolic in the lifted output.
                try:
                    if name.startswith(('iget', 'iput', 'sget', 'sput')):
                        self.resolve(res, 0, ins[pc+1], name[0] == 's')
                    elif name.startswith('invoke-'):
                        self.resolve(res, 1, ins[pc+1], name.startswith('invoke-static'))
                    elif name in ('const-string', 'const-string/jumbo'):
                        idx = ins[pc+1] | (ins[pc+2]<<16 if size == 3 else 0)
                        self.resolve(res, 5, idx)
                    elif name in ('const-class', 'new-instance', 'new-array', 'check-cast',
                                  'instance-of', 'filled-new-array', 'filled-new-array/range'):
                        self.resolve(res, 2, ins[pc+1])
                except EmulationError as exc:
                    if os.environ.get('UNMMP_CAPTURE_TOLERANT'):
                        continue
                    raise
            for start, end, handlers in parse_tries(self.nm.data, self.nm.vaddr_to_off, th['tries']):
                for idx, pc in handlers:
                    if idx is None:
                        continue
                    try:
                        self.resolve(res, 2, idx)
                    except EmulationError:
                        if not os.environ.get('UNMMP_CAPTURE_TOLERANT'):
                            raise
        return failures

    def refine_invokes(self, mapping):
        self.methods = [m for m in self.methods if m['thunk'] in self.blobs]
        """Use dex class metadata to distinguish equivalent JNI call bodies."""
        kinds = {k:v for d in self.dexes for k,v in d.referenced_interfaces().items()}
        votes = {}
        for m in self.methods:
            ins = self.instructions(m)
            ok,err,ops = decode(ins,len(ins),shorty_of(m['sig']),mapping)
            for pc,op,name,size in ops:
                if not name.startswith('invoke-virtual'):
                    continue
                ref = self.sessions[m['resolver']].methods[ins[pc+1]]
                kind = kinds.get(ref['cls'])
                if kind is not None:
                    score = votes.setdefault(op,[0,0])
                    score[int(kind)]+=1
        for op,(classes,interfaces) in votes.items():
            if interfaces and not classes:
                mapping[op] = mapping[op].replace('virtual','interface')
        return kinds

    def refine_returns(self, mapping):
        self.methods = [m for m in self.methods if m['thunk'] in self.blobs]
        kinds = {}
        for m in self.methods:
            ins = self.instructions(m)
            ok,err,ops = decode(ins,len(ins),shorty_of(m['sig']),mapping)
            ret = m['sig'].split(')')[1][0]
            name = ('return-void' if ret=='V' else 'return-wide' if ret in 'JD' else
                    'return-object' if ret in '[L' else 'return')
            for pc,op,current,size in ops:
                if current.startswith('return'):
                    kinds.setdefault(op,set()).add(name)
        for op,names in kinds.items():
            if len(names)==1:
                mapping[op] = next(iter(names))
