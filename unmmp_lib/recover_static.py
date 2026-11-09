# -*- coding: utf-8 -*-
"""Registration discovery for VMs that self-register from ``<clinit>``.

``Recovery.bind`` replays ``JNI_OnLoad`` and re-invokes every registrar found in
the dex. A shell that instead spreads registration across each class' static
initialiser (``mPdUI2cA5Z(id)``) never populates ``runtime.registrations``, so
bind() cannot work and the whole pipeline stops before lifting.

The registration table is nevertheless fully static:

    dword_346DF8[id]  -> { u32 first_index; u32 name_index; u32 method_count; }
    method_table[i]   -> { u32 name_index; u32 sig_index; u64 fn_ptr; }   (16 B)

fn_ptr lives in ``.data.rel.ro`` and is materialised by an ``R_AARCH64_RELATIVE``
relocation, so it must be read through the relocation table.

Method order inside a row matches the order the methods are declared in the dex
class, which is what lets a row be matched to its dex class without decrypting
the (encrypted) name table.  When the decrypted name table *is* available
(``dump_strpool.py`` + ``resolve_names.py``) the row is matched by
``(name, signature)`` instead, which is exact: a class may mix VM-protected
methods with ordinary JNI methods, so its native count need not equal the row's
``method_count``.
"""
import struct

from .emulate import EmulationError
from .recover import Recovery


class StaticRecovery(Recovery):
    def __init__(self, nm, vm, dexes, regids, log=print,
                 row_table=0x346DF8, method_table=0x35DEF0, names=None):
        Recovery.__init__(self, nm, vm, dexes, log)
        self.regids = dict(regids)
        self.row_table = row_table
        self.method_table = method_table
        self.names = names or {}
        self._relocs = None

    def _reloc(self, va):
        if self._relocs is None:
            relocs = getattr(self.nm, 'relocs', None)
            if relocs is None:
                relocs = self.nm._parse_relocs()
            relative = self.nm.relative_reloc_type()
            self._relocs = {off: addend for off, typ, sym, addend in relocs
                            if typ == relative and addend is not None}
        return self._relocs.get(va)

    def _fn_ptr(self, va):
        addend = self._reloc(va)
        if addend is not None:
            return addend
        return struct.unpack_from('<Q', self.nm.data, self.nm.vaddr_to_off(va))[0]

    def _row(self, index):
        off = self.nm.vaddr_to_off(self.row_table + index * 12)
        return struct.unpack_from('<III', self.nm.data, off)

    def _entry(self, index):
        va = self.method_table + index * 16
        name_idx, sig_idx = struct.unpack_from('<II', self.nm.data, self.nm.vaddr_to_off(va))
        return name_idx, sig_idx, self._fn_ptr(va + 8)

    def natives(self, cls):
        """Native methods of one dex class, in dex declaration order."""
        out = []
        for (klass, name, sig), (flags, code) in self.definitions.items():
            if klass == cls and flags & 0x100:
                out.append((name, sig))
        return out

    def bind(self):
        missing = []
        unmatched = []
        for cls, regid in sorted(self.regids.items()):
            first, name_idx, count = self._row(regid)
            declared = self.natives(cls)
            resolved = self.names.get(cls)
            if resolved:
                # Exact path: the row carries real names, so match on identity.
                index = {}
                for name, sig in declared:
                    index.setdefault((name, sig), []).append((name, sig))
                bound = 0
                for offset, item in enumerate(resolved['methods']):
                    key = (item['name'], item['sig'])
                    if key not in index or not index[key]:
                        unmatched.append((cls, item['name'], item['sig']))
                        continue
                    index[key].pop()
                    _, _, fn_ptr = self._entry(first + offset)
                    if not fn_ptr:
                        raise EmulationError('null fn_ptr: %s.%s%s' % (cls, key[0], key[1]))
                    self.methods.append({'class': cls, 'name': key[0], 'sig': key[1],
                                         'entry': self.runtime.BASES[0] + fn_ptr,
                                         'thunk': fn_ptr, 'regid': regid})
                    bound += 1
                if not bound:
                    missing.append((cls, regid, count, len(declared)))
                continue
            if len(declared) != count:
                missing.append((cls, regid, count, len(declared)))
                continue
            for offset, (name, sig) in enumerate(declared):
                _, _, fn_ptr = self._entry(first + offset)
                if not fn_ptr:
                    raise EmulationError('null fn_ptr: %s.%s%s' % (cls, name, sig))
                self.methods.append({'class': cls, 'name': name, 'sig': sig,
                                     'entry': self.runtime.BASES[0] + fn_ptr,
                                     'thunk': fn_ptr, 'regid': regid})
        if missing:
            self.log('[!] %d classes skipped (native count mismatch):' % len(missing))
            for cls, regid, want, got in missing[:10]:
                self.log('    %s id=%d table=%d dex=%d' % (cls, regid, want, got))
        if unmatched:
            self.log('[!] %d row entries matched no dex native' % len(unmatched))
            for cls, name, sig in unmatched[:10]:
                self.log('    %s.%s%s' % (cls, name, sig))
        if not self.methods:
            raise EmulationError('static registration table produced no methods')
        self.log('[*] static bindings: %d methods over %d classes'
                 % (len(self.methods), len({m['class'] for m in self.methods})))
