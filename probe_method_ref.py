"""Run one real method index through the twelve unresolved opcodes.

The synthetic probe feeds index 0x0025 (invalid), so every trace ends in the
resolve-error path and looks the same. Feed index 1 instead and see whether the
interpreter *calls* the method (a 'call' event) or merely stores the resolved
reference into a register (a register delta). That decides invoke-* versus
const-method-*.
"""

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[0]
sys.path.insert(0, str(Path(r'D:\work\vmp\arsenal\attack\tools\unmmp')))

from unmmp_lib.elf import Elf
from unmmp_lib.emulate import NativeRuntime, EmulationError
from unmmp_lib.probe import InstructionProbe

SO = r'D:\work\Apps\com.hylztn.helper\unpack\decrypted_so\06759a4000eaa96f47a5bfd561cc1794.so'
OPS = [0x01, 0x15, 0x5b, 0x62, 0x8c, 0x94, 0xa0, 0xa7, 0xc9, 0xd4, 0xe2, 0xec]

os.environ['UNMMP_VM_ENTRY'] = '0x3150c8'
os.environ['UNMMP_HANDLER_TABLE'] = '0x364540'

data = open(SO, 'rb').read()
runtime = NativeRuntime(Elf(data), Elf(data))
probe = InstructionProbe(runtime)
print('[*] table 0x%x, %d heads' % (probe.table_va, len(probe.heads)), flush=True)

rows = {}
for op in OPS:
    for aa in (0, 2):
        try:
            res = probe.run(op, high=aa, words=(1, 2, 3))
        except EmulationError as exc:
            rows['%#04x/aa%d' % (op, aa)] = {'error': str(exc)}
            continue
        except Exception as exc:                      # noqa: BLE001
            rows['%#04x/aa%d' % (op, aa)] = {'error': '%s: %s' % (type(exc).__name__, exc)}
            continue
        ev = [e[0] for e in res['events']]
        rows['%#04x/aa%d' % (op, aa)] = {
            'pc': res['pc'],
            'delta': {str(k): v for k, v in sorted(res['delta'].items())[:4]},
            'events': [list(e) for e in res['events']][:8],
            'return': res['return'],
            'error': res['error'],
        }
        print('%#04x aa=%d  pc=%s  delta=%s  ev=%s  err=%s'
              % (op, aa, res['pc'], sorted(res['delta'].items())[:3], ev[:6], res['error']), flush=True)

out = Path(r'D:\work\vmp\arsenal\attack\tools\unmmp\probe_a7.json')
out.write_text(json.dumps(rows, indent=2), encoding='utf-8')
print('[*] wrote %s' % out)
