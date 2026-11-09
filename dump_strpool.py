#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dump the decrypted class/method name pool of a self-registering nmmp fork.

The registration table stores *indices* into an encrypted string pool; the pool
only becomes readable after the shell's own initialiser has run.  This script
loads the library, runs the initialiser inside Unicorn and prints every string
found at the pool base, so ``name_idx`` / ``sig_idx`` can be resolved offline.

Usage:
    python dump_strpool.py <libnmmp.so> [--base 0x3693A8] [--size 0xEB0D]
                            [--table 0x347BCC] [--t1 0x348190]
                            [--json out.json]
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from unmmp_lib.elf import Elf                 # noqa: E402
from unmmp_lib.emulate import NativeRuntime   # noqa: E402

DEFAULT_BASE = '0x3693A8'
DEFAULT_SIZE = '0xEB0D'
DEFAULT_T2 = '0x347BCC'
DEFAULT_T1 = '0x348190'


def init_array(nm, runtime):
    """Return the .init_array entry points, relocated to the loaded base."""
    sec = nm.section('.init_array')
    if not sec:
        return []
    load = runtime.images[0][1]
    out = []
    for off in range(0, sec['size'], nm.ptr):
        value = nm.pointer(sec['addr'] + off)
        if value:
            out.append(load + value)
    return out


def run_init(runtime, nm, budget):
    """Best-effort: run every .init_array entry, then JNI_OnLoad."""
    ran = []
    for addr in init_array(nm, runtime):
        try:
            runtime.call(addr, [], count=budget)
            ran.append(('init_array', hex(addr)))
        except Exception as exc:                      # noqa: BLE001
            ran.append(('init_array', hex(addr), repr(exc)))
    entry = runtime.symbols.get('JNI_OnLoad')
    if entry:
        try:
            runtime.call(entry, [runtime.jvm, 0], count=budget)
            ran.append(('JNI_OnLoad', hex(entry)))
        except Exception as exc:                      # noqa: BLE001
            ran.append(('JNI_OnLoad', hex(entry), repr(exc)))
    return ran


def split_strings(blob):
    out, cur = [], bytearray()
    for byte in blob:
        if byte == 0:
            if cur:
                out.append(bytes(cur).decode('latin-1'))
                cur = bytearray()
            continue
        if 0x20 <= byte < 0x7F:
            cur.append(byte)
        else:
            cur = bytearray()
    if cur:
        out.append(bytes(cur).decode('latin-1'))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lib')
    parser.add_argument('--base', default=DEFAULT_BASE)
    parser.add_argument('--size', default=DEFAULT_SIZE)
    parser.add_argument('--t2', default=DEFAULT_T2)
    parser.add_argument('--t1', default=DEFAULT_T1)
    parser.add_argument('--json')
    parser.add_argument('--raw', help='write the decrypted pool bytes here')
    parser.add_argument('--budget', type=int, default=200000000)
    args = parser.parse_args(argv)

    data = open(args.lib, 'rb').read()
    nm, vm = Elf(data), Elf(data)
    runtime = NativeRuntime(nm, vm)
    print('[*] symbols = %s' % sorted(runtime.symbols))

    for step in run_init(runtime, nm, args.budget):
        print('[*] ran %s' % (step,))

    load = runtime.images[0][1]
    base, size = load + int(args.base, 0), int(args.size, 0)
    try:
        blob = bytes(runtime.uc.mem_read(base, size))
    except Exception as exc:                          # noqa: BLE001
        raise SystemExit('cannot read pool at %#x: %s' % (base, exc))

    strings = split_strings(blob)
    print('[*] pool %#x..%#x  printable strings = %d' % (base, base + size, len(strings)))
    for idx, text in enumerate(strings[:40]):
        print('    [%4d] %s' % (idx, text))

    result = {'base': base, 'size': size, 'strings': strings}
    if args.raw:
        with open(args.raw, 'wb') as handle:
            handle.write(blob)
        print('[*] wrote %s' % args.raw)
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump(result, handle, ensure_ascii=False, indent=1)
        print('[*] wrote %s' % args.json)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
