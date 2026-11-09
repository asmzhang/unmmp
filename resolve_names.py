#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resolve registration-table entries to real class/method/signature names.

The table stores two indices per method (name, signature) that go through two
levels of indirection into an encrypted string pool.  Once the pool has been
dumped in decrypted form (see ``dump_strpool.py``), the names can be recovered
offline:

    name_idx --T1--> pool_index --T2--> byte offset --pool--> cstring

Usage:
    python resolve_names.py <libnmmp.so> --pool strpool.bin --base 0x3693A8
                             [--table 0x35DEF0] [--rows 0x346DF8]
                             [--regid regid_map.tsv] [--json out.json]
"""
import argparse
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from unmmp_lib.elf import Elf   # noqa: E402

DEFAULT_POOL = '0x3693A8'
DEFAULT_T1 = '0x348190'
DEFAULT_T2 = '0x347BCC'
DEFAULT_ROWS = '0x346DF8'
DEFAULT_TABLE = '0x35DEF0'


def cstring(pool, off):
    if off < 0 or off >= len(pool):
        return None
    end = pool.find(b'\0', off)
    if end < 0:
        return None
    try:
        return pool[off:end].decode('utf-8')
    except UnicodeDecodeError:
        return pool[off:end].decode('latin-1')


def read_u32(elf, va):
    return struct.unpack_from('<I', elf.data, elf.vaddr_to_off(va))[0]


class Names:
    """``name_idx`` indexes the offset table directly; each entry is a byte
    offset into the decrypted pool (the extra level described in the shell's
    registration loop is folded into that table by the builder)."""

    def __init__(self, elf, pool, base, t1, t2):
        self.pool = pool
        self.base = base
        self.t1 = [read_u32(elf, t1 + 4 * i) for i in range(4096)]
        self.t2 = [read_u32(elf, t2 + 4 * i) for i in range(8192)]

    def resolve(self, idx):
        if idx >= len(self.t2):
            return None
        return cstring(self.pool, self.t2[idx])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lib')
    parser.add_argument('--pool', required=True)
    parser.add_argument('--base', default=DEFAULT_POOL)
    parser.add_argument('--t1', default=DEFAULT_T1)
    parser.add_argument('--t2', default=DEFAULT_T2)
    parser.add_argument('--rows', default=DEFAULT_ROWS)
    parser.add_argument('--table', default=DEFAULT_TABLE)
    parser.add_argument('--regid')
    parser.add_argument('--json')
    args = parser.parse_args(argv)

    elf = Elf(open(args.lib, 'rb').read())
    pool = open(args.pool, 'rb').read()
    names = Names(elf, pool, int(args.base, 0), int(args.t1, 0), int(args.t2, 0))

    rows_base, table_base = int(args.rows, 0), int(args.table, 0)
    wanted = {}
    if args.regid:
        with open(args.regid, encoding='utf-8') as handle:
            next(handle, None)
            for line in handle:
                parts = line.rstrip('\n').split('\t')
                if len(parts) >= 3:
                    wanted[parts[0]] = int(parts[2])

    out = {}
    for cls, regid in sorted(wanted.items(), key=lambda kv: kv[1]):
        first, name_idx, count = (read_u32(elf, rows_base + 12 * regid + 4 * i)
                                  for i in range(3))
        methods = []
        for i in range(count):
            va = table_base + 16 * (first + i)
            n_idx, s_idx = read_u32(elf, va), read_u32(elf, va + 4)
            methods.append({'name': names.resolve(n_idx), 'sig': names.resolve(s_idx),
                            'name_idx': n_idx, 'sig_idx': s_idx,
                            'fn': elf.pointer(va + 8)})
        out[cls] = {'regid': regid, 'first': first, 'count': count, 'methods': methods}

    total = sum(len(v['methods']) for v in out.values())
    unnamed = sum(1 for v in out.values() for m in v['methods'] if not m['name'])
    print('[*] classes = %d, methods = %d, unresolved names = %d'
          % (len(out), total, unnamed))
    for cls, info in list(out.items())[:6]:
        print('== %s id=%d count=%d' % (cls, info['regid'], info['count']))
        for m in info['methods'][:6]:
            print('    %-28s %s' % (m['name'], m['sig']))
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump(out, handle, ensure_ascii=False, indent=1)
        print('[*] wrote %s' % args.json)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
