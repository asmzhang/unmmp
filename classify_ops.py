"""Classify opcodes that the semantic deriver left unresolved.

For every requested opcode the handler is executed on a synthetic instruction
and the observable effects are reported: how far the instruction pointer moved,
which resolver kinds were touched (field/method/type/class/string), whether the
resolved member was static, and which virtual registers changed.  Together with
the Dalvik format widths that is usually enough to pin the opcode down.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from unmmp_lib.elf import Elf
from unmmp_lib.emulate import NativeRuntime, EmulationError
from unmmp_lib.probe import InstructionProbe

RESOLVE_KIND = {0: 'field', 1: 'method', 2: 'type', 3: 'class', 5: 'string'}


def describe(probe, opv):
    trace = probe.run(opv)
    kinds = []
    static = None
    for ev in trace.get('events', []):
        if ev[0] == 'resolve':
            kinds.append(RESOLVE_KIND.get(ev[1], str(ev[1])))
            if ev[1] == 1:
                static = bool(ev[3])
    return {
        'op': opv,
        'advance': trace.get('pc'),
        'resolve': sorted(set(kinds)),
        'static': static,
        'delta': sorted(trace.get('delta', {})),
        'vreg_reads': len(trace.get('vreg_reads', [])),
        'return': bool(trace.get('return')),
        'error': trace.get('error'),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nm', required=True)
    ap.add_argument('--vm', required=True)
    ap.add_argument('--vm-entry', default='0x3150c8')
    ap.add_argument('--table', default='0x364540')
    ap.add_argument('--ops', default='')
    ap.add_argument('-o', '--out')
    args = ap.parse_args()

    os.environ.setdefault('UNMMP_VM_ENTRY', args.vm_entry)
    os.environ.setdefault('UNMMP_HANDLER_TABLE', args.table)

    nm = Elf(open(args.nm, 'rb').read())
    vm = Elf(open(args.vm, 'rb').read())
    runtime = NativeRuntime(nm, vm)
    probe = InstructionProbe(runtime)

    ops = ([int(x, 0) for x in args.ops.split(',') if x.strip()] if args.ops
           else list(range(256)))
    rows = []
    for opv in ops:
        try:
            rows.append(describe(probe, opv))
        except EmulationError as exc:
            rows.append({'op': opv, 'error': str(exc)})
        r = rows[-1]
        print('op %#04x  adv=%s  resolve=%s  static=%s  delta=%s  reads=%s%s'
              % (r['op'], r.get('advance'), ','.join(r.get('resolve') or []) or '-',
                 r.get('static'), len(r.get('delta') or []), r.get('vreg_reads'),
                 ('  ERR=%s' % r['error']) if r.get('error') else ''))
    if args.out:
        json.dump(rows, open(args.out, 'w', encoding='utf-8'), indent=1)


if __name__ == '__main__':
    main()
