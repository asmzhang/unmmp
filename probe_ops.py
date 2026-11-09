#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe the opcode semantics of an nmmp-family VM without running extract().

unmmp's normal pipeline has two stages:

1. ``recover.extract``: run JNI_OnLoad, collect RegisterNatives entries, then
   re-invoke each registration site found in the dex.
2. ``probe.InstructionProbe``: feed controlled bytecode to the interpreter and
   observe register deltas to infer what each opcode does.

Samples that dpt-shell/normal-nmmp did NOT produce (forked VMs, per-class
``<clinit>`` self-registration, stripped exports) cannot pass stage 1, but stage
2 only needs two things: a ``vmCode`` and the interpreter entry. Both are known
statically. This script drives stage 2 directly.

Usage:
    python probe_ops.py <so> [-o out.json] [--ops 0,1,5,13] [--high 0x21]

    UNMMP_VM_ENTRY=<va> is read by NativeRuntime; pass --vm-entry to set it here.
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from unmmp_lib.elf import Elf                    # noqa: E402
from unmmp_lib.emulate import NativeRuntime, EmulationError  # noqa: E402
from unmmp_lib.probe import InstructionProbe     # noqa: E402


def parse_ops(text):
    if not text:
        return list(range(256))
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
    parser = argparse.ArgumentParser(prog='probe_ops', description=__doc__.splitlines()[0])
    parser.add_argument('so', help='path to the shared object holding the VM')
    parser.add_argument('-o', '--out', help='write results as JSON')
    parser.add_argument('--ops', help="opcode list, e.g. '0,1,5,13' or '0-255' (default all)")
    parser.add_argument('--high', default='0x21', help='second byte of the instruction word (default 0x21)')
    parser.add_argument('--vm-entry', help='link-time VA of the interpreter (sets UNMMP_VM_ENTRY)')
    args = parser.parse_args(argv)

    if args.vm_entry:
        os.environ['UNMMP_VM_ENTRY'] = args.vm_entry

    data = open(args.so, 'rb').read()
    nm = Elf(data)
    vm = Elf(data)
    print('[*] machine=%d ptr=%d' % (nm.machine, nm.ptr), flush=True)

    runtime = NativeRuntime(nm, vm)
    print('[*] vm_entry = 0x%x' % (runtime.vm_entry - runtime.images[1][1]), flush=True)

    probe = InstructionProbe(runtime)
    print('[*] handler table = 0x%x (%d distinct heads)'
          % (probe.table_va, len(probe.heads)), flush=True)

    high = int(args.high, 0)
    results = {}
    for op in parse_ops(args.ops):
        try:
            res = probe.run(op, high=high)
        except EmulationError as exc:
            results[op] = {'error': str(exc)}
            continue
        except Exception as exc:                     # noqa: BLE001 - report, do not abort
            results[op] = {'error': '%s: %s' % (type(exc).__name__, exc)}
            continue
        results[op] = {
            'pc': res['pc'],
            'delta': {str(k): v for k, v in sorted(res['delta'].items())},
            'flags': res['flags'],
            'return': res['return'],
            'array': [(a, o, s) for a, o, s in res['array']],
            'vreg_reads': [(o, s) for o, s in res['vreg_reads']],
            'result': res['result'],
            'error': res['error'],
        }
        print('[%3d] pc=%s delta=%s ret=%s err=%s'
              % (op, res['pc'], sorted(res['delta'].items())[:4], res['return'], res['error']),
              flush=True)

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding='utf-8')
        print('[*] wrote %s' % args.out, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
