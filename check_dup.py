#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-check a derived opcode->name map against the handler jump table.

A randomised nmmp build maps many Dalvik opcodes onto ONE native handler: the
generic array-get/get-wide family, the switch payload decoders and the fatal
"unimplemented" stub are all shared.  Two opcodes resolving to the same Dalvik
name is therefore only a real mapping error when they sit on DIFFERENT
handlers; when they share a handler the name is the family name and the exact
variant has to come from the instruction's type context.

Usage:
    python check_dup.py <so> <map.json> [--table 0x364540]
"""
import argparse
import collections
import json
import struct
import sys
from pathlib import Path


def load_relocations(data):
    """VA -> resolved value for every R_AARCH64_RELATIVE in .rela.dyn."""
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    shs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, sh_off, size, link, info, align, entsize = \
            struct.unpack_from('<IIQQQQIIQQ', data, off)
        shs.append(dict(name=name, typ=typ, addr=addr, off=sh_off, size=size))
    strtab = shs[e_shstrndx]
    base = strtab['off']

    def sec_name(idx):
        return data[base + idx:data.index(b'\0', base + idx)].decode()

    rela = next(s for s in shs if sec_name(s['name']) == '.rela.dyn')
    out = {}
    for i in range(rela['size'] // 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, rela['off'] + i * 24)
        if (r_info & 0xffffffff) == 1027:
            out[r_offset] = r_addend
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('map')
    ap.add_argument('--table', default='0x364540')
    args = ap.parse_args(argv)

    data = Path(args.so).read_bytes()
    relocs = load_relocations(data)
    table = int(args.table, 0)
    mapping = {int(k): v for k, v in json.loads(Path(args.map).read_text(encoding='utf-8')).items()}

    handler = {op: relocs.get(table + op * 8, 0) for op in range(256)}

    by_name = collections.defaultdict(list)
    for op, name in mapping.items():
        by_name[name].append(op)

    dup = {n: ops for n, ops in by_name.items() if len(ops) > 1}
    if not dup:
        print('[*] no duplicate names')
        return 0

    for name, ops in sorted(dup.items(), key=lambda kv: -len(kv[1])):
        groups = collections.defaultdict(list)
        for op in ops:
            groups[handler[op]].append(op)
        shared = {h: o for h, o in groups.items() if len(o) > 1}
        split = [op for h, o in groups.items() if len(o) == 1 for op in o]
        verdict = 'SHARED HANDLER' if shared and not split else \
                  'DISTINCT HANDLERS' if split and not shared else 'MIXED'
        print('%-16s n=%d  %s' % (name, len(ops), verdict))
        for h, o in sorted(groups.items()):
            print('    handler 0x%08x  ops %s' % (h, ' '.join('0x%02x' % x for x in sorted(o))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
