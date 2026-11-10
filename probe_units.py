"""Decide whether an unnamed opcode is 2 or 3 code units, by perturbation.

The interpreter keeps the Dalvik program counter in a register, so a handler
that reads its *second* operand unit touches `[pc+4]` (unit2).  Feeding the
same instruction word twice with two different unit2 values and comparing the
set of vregs that get read tells us whether unit2 belongs to this instruction:

  * reads unchanged              -> unit2 is not an operand -> 2 units
  * reads changed (or a new
    register appears / the index
    jumps)                       -> unit2 is an operand     -> 3 units

This is cheap and needs no ground truth.  Ops that read no register at all
cannot be decided this way and are reported as `unknown`.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unmmp_lib.elf import Elf
from unmmp_lib.emulate import NativeRuntime, EmulationError
from unmmp_lib.probe import InstructionProbe

DEFAULT_SO = (r'D:\work\Apps\com.hylztn.helper\unpack\decrypted_so'
              r'\06759a4000eaa96f47a5bfd561cc1794.so')
UNNAMED = [0x01, 0x06, 0x0d, 0x0f, 0x12, 0x15, 0x16, 0x18, 0x23, 0x2d, 0x32,
           0x33, 0x34, 0x36, 0x4a, 0x53, 0x5a, 0x5b, 0x5d, 0x60, 0x62, 0x67,
           0x6d, 0x82, 0x88, 0x89, 0x8c, 0x91, 0x94, 0x9c, 0xa0, 0xa2, 0xa7,
           0xbd, 0xc9, 0xcb, 0xd4, 0xd5, 0xd8, 0xdb, 0xdc, 0xdd, 0xe1, 0xe2,
           0xe7, 0xeb, 0xec, 0xed, 0xef, 0xf1, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
           0xf8, 0xf9, 0xfa]

# A nibble probe: 0x3210 exercises every 4-bit slot, so a 35c handler reacts to
# it while a 3rc handler would index 0x3210 and blow past the register file.
A = 0x0002
B = 0x3210


def reads(probe, op, unit2, high=0x01):
    try:
        r = probe.run(op, high=high, words=(1, unit2, 0))
    except EmulationError as exc:
        return None, str(exc)
    return [off for off, _ in (r.get('vreg_reads') or [])], None


def classify(probe, op):
    a, ea = reads(probe, op, A)
    b, eb = reads(probe, op, B)
    if ea or eb:
        return 'error', {'a': a, 'b': b, 'err': ea or eb}
    if not a and not b:
        return 'unknown', {'a': a, 'b': b}
    if a == b:
        return 2, {'a': a, 'b': b}
    return 3, {'a': a, 'b': b}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--so', default=DEFAULT_SO)
    ap.add_argument('--ops', default=None, help='comma separated, hex ok')
    ap.add_argument('-o', '--output', default=None)
    args = ap.parse_args()

    ops = UNNAMED
    if args.ops:
        ops = [int(x, 0) for x in args.ops.split(',')]

    os.environ.setdefault('UNMMP_VM_ENTRY', '0x3150c8')
    os.environ.setdefault('UNMMP_HANDLER_TABLE', '0x364540')

    raw = open(args.so, 'rb').read()
    runtime = NativeRuntime(Elf(raw), Elf(raw))
    probe = InstructionProbe(runtime)

    out = {}
    print('op     units  reads@0x0002            reads@0x3210')
    for op in ops:
        units, detail = classify(probe, op)
        out['%#04x' % op] = {'units': units, 'detail': detail}
        print('%#04x  %-6s %-24s %s' % (op, units, detail.get('a'), detail.get('b')))

    if args.output:
        Path(args.output).write_text(json.dumps(out, indent=1), encoding='utf-8')
        print('[*] wrote', args.output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
