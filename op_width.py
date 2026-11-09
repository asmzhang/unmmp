"""Recover an opcode's instruction width from its handler code.

nmmp handlers advance the instruction pointer (`x22`) by 2 * <code units> right
after fetching, so the first `add x22, x22, #imm` in a handler gives the size of
the instruction it decodes.  That is enough to tell a 1-unit op from a 3-unit
invoke without knowing its name.
"""
import argparse
import json
import os
import struct
import sys

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unmmp_lib.elf import Elf

SLOTS = 256


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nm', required=True)
    ap.add_argument('--mapping', required=True)
    ap.add_argument('--table', default='0x364540')
    ap.add_argument('--scan', type=int, default=64)
    args = ap.parse_args()

    elf = Elf(open(args.nm, 'rb').read())
    relocs = {off: addend for off, typ, sym, addend in elf._parse_relocs()
              if typ == elf.relative_reloc_type()}
    table = int(args.table, 0)
    addrs = []
    for i in range(SLOTS):
        off = elf.vaddr_to_off(table + 8 * i)
        addrs.append(relocs.get(off, struct.unpack_from('<Q', elf.data, off)[0]))
    mapping = {int(k): v for k, v in json.load(open(args.mapping, encoding='utf-8')).items()}

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False

    def steps(va):
        off = elf.vaddr_to_off(va)
        code = elf.data[off:off + 4 * args.scan]
        out = []
        for ins in md.disasm(code, va):
            out.append((ins.mnemonic, ins.op_str))
        return out

    def width(va):
        # nmmp fetches the next code unit with a pre-indexed load on the
        # instruction pointer: `ldrh w27, [x22, #4]!` both reads the following
        # unit and advances x22, so the immediate is 2 * <units of this insn>.
        for mn, ops in steps(va):
            if mn in ('ldrh', 'ldr', 'ldurh', 'ldur') and '[x22, #' in ops and ']!' in ops:
                try:
                    return int(ops.split('[x22, #', 1)[1].split(']', 1)[0], 0) // 2
                except ValueError:
                    pass
        return None

    known = {op: width(a) for op, a in enumerate(addrs) if op in mapping and addrs[op]}
    print('width histogram over resolved ops:',
          {w: list(known.values()).count(w) for w in sorted(set(known.values()), key=str)})
    print()
    for op in range(SLOTS):
        if op in mapping or not addrs[op]:
            continue
        w = width(addrs[op])
        print('op %#04x handler=%#x width=%s' % (op, addrs[op], w))


if __name__ == '__main__':
    main()
