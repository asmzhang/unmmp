#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe each opcode in its own process.

``probe_ops.py`` reuses one Unicorn instance for the whole sweep, so whatever a
handler leaves in the register file, the flag words or the heap is still there
when the next opcode runs. On a well-behaved VM that mostly does not matter; on
this one a single bad handler poisons every probe after it, and the sweep
degrades to 256 identical results that look like a working run.

Isolating the process per opcode costs about a second each and removes the
coupling entirely. Merge the per-opcode JSON into one file with the same shape
as ``probe_ops.py`` output.

Usage:
    python probe_isolated.py <so> --vm-entry <va> -o out.json [--ops 0-255]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def parse_ops(text):
    ops = []
    for part in text.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            lo, hi = part.split('-', 1)
            ops.extend(range(int(lo, 0), int(hi, 0) + 1))
        else:
            ops.append(int(part, 0))
    return ops


def main(argv=None):
    parser = argparse.ArgumentParser(prog='probe_isolated', description=__doc__.splitlines()[0])
    parser.add_argument('so')
    parser.add_argument('--vm-entry', required=True)
    parser.add_argument('--table')
    parser.add_argument('-o', '--out', required=True)
    parser.add_argument('--ops', default='0-255')
    args = parser.parse_args(argv)

    env = dict(os.environ)
    env['UNMMP_VM_ENTRY'] = args.vm_entry
    if args.table:
        env['UNMMP_HANDLER_TABLE'] = args.table

    merged = {}
    tmpdir = tempfile.mkdtemp(prefix='probe1_')
    for op in parse_ops(args.ops):
        tmp = os.path.join(tmpdir, '%d.json' % op)
        cmd = [sys.executable, str(HERE / 'probe_ops.py'), args.so,
               '--ops', str(op), '-o', tmp]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True,
                              encoding='utf-8', errors='replace')
        if proc.returncode != 0 or not os.path.exists(tmp):
            merged[str(op)] = {'error': 'process rc=%d' % proc.returncode}
            print('[%3d] FAILED rc=%d' % (op, proc.returncode), flush=True)
            continue
        with open(tmp, encoding='utf-8') as fh:
            data = json.load(fh)
        entry = data.get(str(op)) or data.get(op)
        merged[str(op)] = entry
        if entry:
            print('[%3d] pc=%s delta=%s ret=%s err=%s' % (
                op, entry.get('advance', entry.get('pc')), entry.get('delta'),
                entry.get('return'), entry.get('error')), flush=True)
        os.unlink(tmp)

    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump(merged, fh, ensure_ascii=False, indent=1)
    print('[*] wrote %s (%d opcodes)' % (args.out, len(merged)), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
