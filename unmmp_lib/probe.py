# -*- coding: utf-8 -*-
"""Measure one VM instruction at its next dispatch boundary."""
import struct

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from .emulate import EmulationError
from .handlers import find_handler_table


class InstructionProbe:
    """Measure one VM instruction at its next dispatch boundary.

    ``dex`` is optional.  When given, the method slot of the resolver returns a
    ``vmMethod`` carrying the *real* shorty of the referenced method instead of
    the synthetic ``II`` placeholder.  That matters because this VM derives the
    JNI call variant from that string: with a placeholder every ``invoke-*``
    handler takes the same path, with the real shorty they take the one the
    sample would take.  See ``docs`` in MY_BRANCH.md.
    """

    def __init__(self, runtime, dex=None):
        self.r = runtime
        self.uc = runtime.uc
        self.dex = dex
        self.shorty_cache = {}
        self.resolved_methods = []
        elf, base = runtime.images[1]
        self.table_va, table = find_handler_table(elf)
        self.heads = {base + elf.code_addr(a) for a in table}
        self.pending_dispatch = False
        self.code = runtime.alloc(5 * runtime.ptr)
        self.insns = runtime.alloc(0x40000)
        self.regs = runtime.alloc(65536 * 8)
        self.flags = runtime.alloc(65536)
        self.result = runtime.alloc(8)
        self.resolver = runtime.alloc(6 * runtime.ptr)
        self.type_name = runtime.alloc(32, b'[Lprobe/Object;\0')
        self.field = runtime.alloc(24)
        self.method = runtime.alloc(32)
        self.shorty = runtime.alloc(16, b'II\0')
        self.handle = runtime.handle('class', 'probe/Object')
        self.field_handle = runtime.handle('field', ('probe/Object', 'field', 'I'))
        self.method_handle = runtime.handle('method', ('probe/Object', 'method', '(I)I'))
        self.uc.mem_write(self.field, b'\0\0I\0')
        runtime.write_ptr(self.field + (8 if runtime.ptr == 8 else 4), self.field_handle)
        runtime.write_ptr(self.method + runtime.ptr, self.shorty)
        runtime.write_ptr(self.method + 2 * runtime.ptr, self.method_handle)
        runtime.array_data = runtime.alloc(0x10000,
                                           bytes.fromhex('81ff341278563412') * 8192)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.on_array,
                         begin=runtime.array_data, end=runtime.array_data + 0xffff)
        for i in range(6):
            runtime.write_ptr(self.resolver + runtime.ptr * i,
                              runtime.stub(lambda index=i: self.resolve(index)))
        self.uc.hook_add(UC_HOOK_MEM_READ, self.on_read,
                         begin=self.insns, end=self.insns + 0x3ffff)
        self.uc.hook_add(UC_HOOK_MEM_READ, self.on_dispatch,
                         begin=base + self.table_va,
                         end=base + self.table_va + 256 * runtime.ptr - 1)
        self.uc.hook_add(UC_HOOK_MEM_READ, self.on_vreg,
                         begin=self.regs, end=self.regs + 65536*8 - 1)
        # VM entry blocks may already have been translated while capturing
        # thunks. Install memory hooks on freshly translated code as well.
        text = elf.section('.text')
        self.uc.ctl_remove_cache(base + text['addr'], base + text['addr'] + text['size'])
        self.entries = 0
        self.last_fetch = None

    @staticmethod
    def shorty_of(proto):
        """Dalvik shorty of a prototype string: one char for the return type
        followed by one char per parameter.  Reference types (including arrays)
        collapse to ``L``; wide types keep ``J``/``D`` and count once."""
        if not proto.startswith('(') or ')' not in proto:
            return None
        head, tail = proto.split(')', 1)
        params, i = head[1:], 0
        out = []
        while i < len(params):
            if params[i] == '[':
                while params[i] == '[':
                    i += 1
                if params[i] == 'L':
                    i = params.index(';', i) + 1
                else:
                    i += 1
                out.append('L')
            elif params[i] == 'L':
                i = params.index(';', i) + 1
                out.append('L')
            else:
                out.append(params[i])
                i += 1
        if not tail:
            return None
        ret = 'L' if tail[0] in '[L' else tail[0]
        return ret + ''.join(out)

    def _shorty_at(self, idx):
        if idx in self.shorty_cache:
            return self.shorty_cache[idx]
        ptr = self.shorty  # fall back to the placeholder
        if self.dex is not None and 0 <= idx < len(self.dex.methods):
            cls, name, proto = self.dex.methods[idx]
            text = self.shorty_of(proto)
            if text:
                ptr = self.r.alloc(len(text) + 1, text.encode('ascii') + b'\0')
                self.resolved_methods.append((idx, cls, name, proto, text))
        self.shorty_cache[idx] = ptr
        return ptr

    def resolve(self, index):
        args = self.r.args(3)
        self.r.events.append(('resolve', index, args[1], args[2] if index < 2 else 0))
        if index == 1 and self.dex is not None:
            # vmMethod is {u2 classIdx; const char *shorty; jmethodID methodId}
            self.r.write_ptr(self.method + self.r.ptr, self._shorty_at(args[1]))
        return [self.field, self.method, self.type_name, self.handle, self.handle,
                self.r.handle('string', 'probe')][index]

    def on_read(self, uc, access, address, size, value, user):
        self.last_fetch = address

    def on_dispatch(self, uc, access, address, size, value, user):
        self.pending_dispatch = True

    def on_array(self, uc, access, address, size, value, user):
        self.array_access.append((access, address - self.r.array_data, size))

    def on_vreg(self, uc, access, address, size, value, user):
        self.vreg_reads.append((address-self.regs,size))

    def boundary(self, addr):
        if self.pending_dispatch and addr in self.heads:
            self.pending_dispatch = False
            self.entries += 1
            return self.entries > self.skip_entries + 1
        return False

    def run(self, op, high=0x21, words=(0x0302, 0, 0, 0), values=None,
            payload=0x100, prefix=(), flags=()):
        r = self.r
        self.entries = 0
        self.pending_dispatch = False
        self.skip_entries = int(bool(prefix))
        self.array_access = []
        self.vreg_reads = []
        self.last_fetch = None
        self.uc.mem_write(self.insns, bytes(0x40000))
        ins = list(prefix) + [op | (high << 8)] + list(words)
        self.uc.mem_write(self.insns, struct.pack('<%dH' % len(ins), *ins))
        # A valid payload for each trial. Both normal and exceptional branches
        # are observed; unsupported payload types do not get guessed as nops.
        target = self.insns + 2 * (words[0] | (words[1] << 16))
        if self.insns <= target < self.insns + 0x3ffe0:
            raw = {0x100: struct.pack('<HHiii', 0x100, 2, 5, 7, 9),
                   0x200: struct.pack('<HHiiii', 0x200, 2, 5, 13, 7, 9),
                   0x300: struct.pack('<HHI8B', 0x300, 1, 8, *range(8))}[payload]
            self.uc.mem_write(target, raw)
        if values is None:
            values = [((i * 17 + 5) & 0xffffffff) for i in range(65536)]
        initial = struct.pack('<65536Q', *values)
        self.uc.mem_write(self.regs, initial)
        flag_bytes = bytearray(65536)
        for index in flags:
            flag_bytes[index] = 1
        self.uc.mem_write(self.flags, bytes(flag_bytes))
        self.uc.mem_write(self.result, bytes(8))
        # move-result reads interpreter-local retval. Seed inactive stack bytes
        # so integer/wide loads can be distinguished reproducibly.
        self.uc.mem_write(r.STACK + 0x1c0000,
                          struct.pack('<Q', 0x3ff123456789abcd) * (0x30000 // 8))
        for i, value in enumerate((self.insns, 0x20000, self.regs, self.flags, 0)):
            r.write_ptr(self.code + i * r.ptr, value)
        r.probing = True
        r.capture_vm = False
        r.exception = 0
        r.boundary = self.boundary
        args = [r.env, self.code, self.resolver]
        if r.ptr == 4:
            args.insert(0, self.result)
        error = None
        try:
            result = r.call(r.vm_entry, args, count=15000)
        except EmulationError as exc:
            error, result = str(exc), 0
        finally:
            r.boundary = None
            r.probing = False
        final = bytes(self.uc.mem_read(self.regs, len(initial)))
        delta = {}
        # Most trials touch one vreg. Comparing byte buffers first keeps the
        # many-opcode probe inexpensive even with from16 operands.
        if final != initial:
            for i in range(65536):
                if final[8*i:8*i+8] != initial[8*i:8*i+8]:
                    delta[i] = struct.unpack_from('<Q', final, 8*i)[0]
        flags = bytes(self.uc.mem_read(self.flags, 65536))
        return {'pc': (self.last_fetch - self.insns) // 2 if self.last_fetch is not None else None,
                'delta': delta, 'flags': [i for i, v in enumerate(flags) if v],
                'events': list(r.events), 'return': r.stop_reason == 'return',
                'array': list(self.array_access),
                'vreg_reads': list(self.vreg_reads),
                'result': int.from_bytes(self.uc.mem_read(self.result, 8), 'little') if r.ptr == 4 else result,
                'error': error}
