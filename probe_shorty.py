"""Feed a *real* method reference so ``invoke-*`` handlers pick their real path.

Before this, the method slot of the resolver returned one synthetic ``vmMethod``
whose shorty was the literal ``II``.  This VM derives the JNI call variant from
that shorty, so every invoke handler took the same branch and the traces were
indistinguishable.  Here the shorty comes from the dex prototype of the index
being probed, which is what the sample itself would supply at runtime.

Three controls must pass before the output is trusted:

  A  a known opcode keeps its old behaviour      (0x5f = const/4)
  B  the shorty matches the dex prototype        (compared character by character)
  C  the JNI call id now varies with return type (the actual payoff)

Usage::

    python probe_shorty.py [--dex DEX] [--ops 0x5b,0x62] [-o out.json]
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[0]))

from unmmp_lib.dex import Dex
from unmmp_lib.elf import Elf
from unmmp_lib.emulate import EmulationError, NativeRuntime
from unmmp_lib.probe import InstructionProbe

SO = r'D:\work\Apps\com.hylztn.helper\unpack\decrypted_so\06759a4000eaa96f47a5bfd561cc1794.so'
DEFAULT_DEX = r'D:\work\Apps\com.hylztn.helper\unpack\oppo_cc\dex\classes4.dex'

os.environ['UNMMP_VM_ENTRY'] = '0x3150c8'
os.environ['UNMMP_HANDLER_TABLE'] = '0x364540'


def pick_methods(dex, limit_per_shape=1):
    """Index of one method per (return type) shape, widest variety first."""
    want = ['V', 'Z', 'I', 'J', 'F', 'D', 'L']
    chosen = {}
    for idx, (cls, name, proto) in enumerate(dex.methods):
        ret = proto.split(')', 1)[1]
        shape = 'L' if ret[0] in '[L' else ret[0]
        if shape in want and shape not in chosen:
            chosen[shape] = (idx, cls, name, proto)
            if len(chosen) == len(want):
                break
    return chosen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dex', default=DEFAULT_DEX)
    ap.add_argument('--ops', default='0x5b,0x62')
    ap.add_argument('-o', '--out',
                    default=r'D:\work\Apps\com.hylztn.helper\unpack\reports\probe_shorty.json')
    args = ap.parse_args()

    dex = Dex(Path(args.dex).read_bytes())
    data = open(SO, 'rb').read()
    runtime = NativeRuntime(Elf(data), Elf(data))
    probe = InstructionProbe(runtime, dex=dex)
    print('[*] dex methods=%d  table=0x%x heads=%d'
          % (len(dex.methods), probe.table_va, len(probe.heads)), flush=True)

    report = {'dex': args.dex, 'controls': {}, 'rows': []}

    # control A: a known opcode must not move
    res = probe.run(0x5f, high=0x35, words=(0x0025, 0, 0, 0))
    delta = {k: v for k, v in res['delta'].items()}
    report['controls']['A_const4'] = {'delta': delta, 'expect': {5: 3},
                                      'ok': delta == {5: 3}}
    print('[A] const/4  0x355f -> delta=%s  %s'
          % (delta, 'OK' if delta == {5: 3} else 'FAIL'), flush=True)

    chosen = pick_methods(dex)
    for shape, (idx, cls, name, proto) in sorted(chosen.items()):
        expect = InstructionProbe.shorty_of(proto)
        for op in [int(x, 0) for x in args.ops.split(',')]:
            try:
                res = probe.run(op, high=0x21, words=(idx, 2, 3, 0))
            except (EmulationError, Exception) as exc:      # noqa: BLE001
                report['rows'].append({'op': op, 'idx': idx, 'ret': shape,
                                       'error': '%s: %s' % (type(exc).__name__, exc)})
                continue
            jni = [e[1] for e in res['events'] if e[0] == 'jni' and e[1] != 23]
            meth = [e for e in res['events'] if e[0] == 'method']
            got = probe.resolved_methods[-1][4] if probe.resolved_methods else None
            report['rows'].append({
                'op': op, 'idx': idx, 'ret': shape, 'cls': cls, 'name': name,
                'proto': proto, 'expect': expect, 'shorty': got,
                'shorty_ok': got == expect, 'jni': jni,
                'method_event': [list(e) for e in meth],
                'delta': {str(k): v for k, v in res['delta'].items()},
            })
            print('   op %#04x  idx %-6d %-6s proto %-28s shorty %-6s %s  jni %s'
                  % (op, idx, shape, proto, got,
                     'OK' if got == expect else 'FAIL', jni), flush=True)

    rows = [r for r in report['rows'] if 'jni' in r]
    # control B: every shorty matched
    report['controls']['B_shorty'] = {
        'checked': len(rows),
        'ok': bool(rows) and all(r['shorty_ok'] for r in rows),
    }
    # control C: the call id must vary across return types for at least one op
    per_op = {}
    for r in rows:
        per_op.setdefault(r['op'], set()).update(r['jni'])
    report['controls']['C_varies'] = {('%#04x' % k): sorted(v) for k, v in per_op.items()}
    report['controls']['C_varies_ok'] = any(len(v) > 1 for v in per_op.values())\n    # id 23 is NewStringUTF from the string slot, not the op's own lookup

    print('[B] shorty matched: %s' % report['controls']['B_shorty'], flush=True)
    print('[C] jni ids per op: %s' % report['controls']['C_varies'], flush=True)
    print('[C] varies with return type: %s' % report['controls']['C_varies_ok'], flush=True)

    out = Path(args.out)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print('[*] wrote %s' % out)


if __name__ == '__main__':
    main()
