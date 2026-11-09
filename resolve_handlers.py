"""Resolve dispatch-table entries through their lazy-decrypt thunk.

Every slot of the VM dispatch table points at a small thunk:

    adrp x10, <table> ; add x10, x10, #<off>   -> jump pair
    adrp x8,  <flag>  ; ... ldar w9,[x8] ; cset w9,eq ; ldr x10,[x10,w9,lsl#3] ; br x10

`[table+0]` is the real handler body (flag != 0), `[table+8]` the one-shot XOR
decrypt stub that falls through into it.  Two opcodes that share a body really
do share semantics, so this collapses the permutation.
"""
import argparse
import json
import os
import re
import struct
import sys

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unmmp_lib.elf import Elf

SLOTS = 256


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nm', required=True)
    ap.add_argument('--mapping', default=None)
    ap.add_argument('--table', default='0x364540')
    ap.add_argument('-o', '--out')
    args = ap.parse_args()

    elf = Elf(open(args.nm, 'rb').read())
    table = int(args.table, 0)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    def read_ptr(va):
        """Read a pointer from .data.rel.ro: the value lives in the RELA addend.

        ``elf._rel_ptr`` is keyed by the relocation's r_offset, which is a
        virtual address -- not a file offset.  Keying it by file offset silently
        returns the zeroed bytes from the file image instead.
        """
        if va in elf._rel_ptr:
            return elf._rel_ptr[va]
        return struct.unpack_from('<Q', elf.data, elf.vaddr_to_off(va))[0]

    def entry(i):
        return read_ptr(table + 8 * i)

    def thunk_targets(va):
        off = elf.vaddr_to_off(va)
        code = elf.data[off:off + 4 * 40]
        base = None
        for ins in md.disasm(code, va):
            if ins.mnemonic == 'adrp' and ins.op_str.startswith('x10,'):
                base = int(ins.op_str.split('#', 1)[1], 0)
            elif base is not None and ins.mnemonic == 'add' and ins.op_str.startswith('x10, x10, #'):
                base += int(ins.op_str.rsplit('#', 1)[1], 0)
            elif base is not None and ins.mnemonic == 'ldr' and '[x10' in ins.op_str:
                return read_ptr(base), read_ptr(base + 8)
        return None

    mapping = ({int(k): v for k, v in json.load(open(args.mapping, encoding='utf-8')).items()}
               if args.mapping else {})

    bodies = {}
    rows = []
    for i in range(SLOTS):
        a = entry(i)
        t = thunk_targets(a) if a else None
        body = t[0] if t else a
        bodies[i] = body
        rows.append({'op': i, 'slot': a, 'body': body, 'name': mapping.get(i)})

    groups = {}
    for r in rows:
        groups.setdefault(r['body'], []).append(r['op'])

    print('slots=%d  distinct bodies=%d' % (len(rows), len(groups)))
    for body, ops in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        names = sorted({mapping[o] for o in ops if o in mapping})
        unk = [o for o in ops if o not in mapping]
        if len(ops) > 1:
            print('body %#x  n=%d  known=%s  unknown=%s'
                  % (body, len(ops), ','.join(names[:3]) or '-',
                     ','.join('%#04x' % o for o in unk[:12]) or '-'))
    if args.out:
        json.dump(rows, open(args.out, 'w', encoding='utf-8'), indent=1)


if __name__ == '__main__':
    main()
