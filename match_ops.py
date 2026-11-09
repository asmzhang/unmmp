"""Match unresolved opcodes to resolved ones by handler code similarity.

The dispatch table is a permutation, but the *handlers* are ordinary compiled
code: opcodes of the same family (all `if-*`, all `iget*`, ...) differ only in a
few immediate fields, so a byte-level distance over the handler prologue puts
them next to each other.  For each unresolved opcode this prints the closest
resolved handlers with their differing offsets.
"""
import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unmmp_lib.elf import Elf

TABLE = 0x364540
SLOTS = 256


def handler_bytes(elf, va, length):
    off = elf.vaddr_to_off(va)
    return elf.data[off:off + length]


def distance(a, b):
    n = min(len(a), len(b))
    diff = sum(1 for i in range(n) if a[i] != b[i])
    return diff, [i for i in range(n) if a[i] != b[i]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nm', required=True)
    ap.add_argument('--mapping', required=True)
    ap.add_argument('--table', default=hex(TABLE))
    ap.add_argument('--length', type=int, default=96)
    ap.add_argument('--top', type=int, default=4)
    args = ap.parse_args()

    elf = Elf(open(args.nm, 'rb').read())
    table = int(args.table, 0)
    # the dispatch table lives in .data.rel.ro: file bytes are zero and the real
    # target only exists as an R_AARCH64_RELATIVE addend.
    relocs = {off: addend for off, typ, sym, addend in elf._parse_relocs()
              if typ == elf.relative_reloc_type()}
    addrs = []
    for i in range(SLOTS):
        off = elf.vaddr_to_off(table + 8 * i)
        addrs.append(relocs.get(off,
                                struct.unpack_from('<Q', elf.data, off)[0]))
    mapping = {int(k): v for k, v in json.load(open(args.mapping, encoding='utf-8')).items()}

    known = {op: a for op, a in enumerate(addrs) if op in mapping}
    unknown = [op for op in range(SLOTS) if op not in mapping]
    blobs = {op: handler_bytes(elf, a, args.length) for op, a in known.items()}

    for op in unknown:
        target = handler_bytes(elf, addrs[op], args.length)
        scored = sorted(((distance(target, b)[0], kop, b) for kop, b in blobs.items()))
        top = []
        for d, kop, _ in scored[:args.top]:
            top.append('%s(%d)' % (mapping[kop], d))
        shared = sum(1 for kop in known if addrs[kop] == addrs[op])
        print('op %#04x handler=%#x  dup_of=%d  nearest: %s'
              % (op, addrs[op], shared, ', '.join(top)))


if __name__ == '__main__':
    main()
