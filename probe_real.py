"""Re-probe family members with real instruction words taken from real bodies.

The synthetic probe feeds index 1 and a made-up register, so every member of a
family lands on the same error path and looks identical.  Feeding the exact
units a real method uses lets the resolver resolve a real reference and lets
the handler touch a real register, which is what separates
`instance-of` from `check-cast`, `iget` from `iput`, and so on.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unmmp_lib.decoder import decode
from unmmp_lib.elf import Elf
from unmmp_lib.emulate import NativeRuntime, EmulationError
from unmmp_lib.probe import InstructionProbe

HOME = Path(r'D:\work\Apps\com.hylztn.helper')
BODIES = HOME / r'unpack\unmmp_out5\raw_bodies.json'
MAPPING = HOME / r'unpack\reports\opcode_semantic.json'
WIDTHS = HOME / r'unpack\reports\widths_probe2.json'
SO = HOME / r'unpack\decrypted_so\06759a4000eaa96f47a5bfd561cc1794.so'


def load_widths(path):
    raw = json.load(open(path, encoding='utf-8'))
    out = {}
    for k, v in raw.items():
        op = int(k, 16)
        out[op] = v if isinstance(v, int) else int(max(v.items(), key=lambda kv: kv[1])[0])
    return out


def collect(target, limit):
    """Return real (units) windows for `target`, one per distinct body."""
    bodies = json.load(open(BODIES, encoding='utf-8'))
    mapping = {int(k): v for k, v in json.load(open(MAPPING, encoding='utf-8')).items()}
    widths = load_widths(WIDTHS)
    found = []
    for cls, methods in bodies.items():
        for m in methods:
            units = [int(u, 16) for u in m.get('units') or []]
            ok, _, ops = decode(units, len(units), m.get('shorty') or '', mapping, widths=widths)
            if not ok:
                continue
            for pc, op, name, size in ops:
                if op == target:
                    found.append({'class': cls, 'method': m.get('name'), 'pc': pc,
                                  'size': size, 'head': units[pc:pc + max(size, 3)]})
                    break
    return found[:limit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ops', required=True, help='comma separated, hex ok')
    ap.add_argument('--per-op', type=int, default=3)
    args = ap.parse_args()

    os.environ.setdefault('UNMMP_VM_ENTRY', '0x3150c8')
    os.environ.setdefault('UNMMP_HANDLER_TABLE', '0x364540')

    raw = SO.read_bytes()
    runtime = NativeRuntime(Elf(raw), Elf(raw))
    probe = InstructionProbe(runtime)

    for tok in args.ops.split(','):
        op = int(tok, 0)
        inst = collect(op, args.per_op)
        print('== %#04x  %d instance(s)' % (op, len(inst)))
        for one in inst:
            head = one['head']
            unit0 = head[0]
            high = (unit0 >> 8) & 0xff
            words = tuple(head[1:3]) + (head[3] if len(head) > 3 else 0,)
            try:
                r = probe.run(op, high=high, words=words)
            except EmulationError as exc:
                print('   %-44s ERR %s' % (one['method'], str(exc)[:40]))
                continue
            ev = ','.join('%s:%s' % (e[0], e[1]) for e in (r.get('events') or []))
            print('   %-44s u=%s delta=%s reads=%s arr=%s ev=%s' % (
                str(one['method'])[:44], ['%04x' % x for x in head[:3]],
                r.get('delta'), r.get('vreg_reads'), (r.get('array_access') or [])[:2], ev[:60]))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
