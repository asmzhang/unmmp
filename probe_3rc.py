"""Probe the eight 3-unit handlers with a real index.

They read unit1 (16-bit) and unit2 (16-bit) and call a resolver slot at +0x20,
so they are 3-unit formats (3rc-ish). The synthetic probe fed an invalid index,
which made every trace end in the resolve-error path. Feed index 1 instead and
compare: which resolver kind fires (method / field / type / class / string),
and whether anything is written back to the register file.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, r'D:\work\vmp\arsenal\attack\tools\unmmp')

from unmmp_lib.elf import Elf
from unmmp_lib.emulate import NativeRuntime, EmulationError
from unmmp_lib.probe import InstructionProbe

SO = r'D:\work\Apps\com.hylztn.helper\unpack\decrypted_so\06759a4000eaa96f47a5bfd561cc1794.so'
OPS = [0x12, 0x18, 0x33, 0x34, 0x36, 0xcb, 0xdb, 0xed]

os.environ['UNMMP_VM_ENTRY'] = '0x3150c8'
os.environ['UNMMP_HANDLER_TABLE'] = '0x364540'

data = open(SO, 'rb').read()
runtime = NativeRuntime(Elf(data), Elf(data))
probe = InstructionProbe(runtime)

rows = {}
for op in OPS:
    for high, words in ((0x00, (1, 2, 3)), (0x21, (1, 2, 3)), (0x35, (1, 2, 3))):
        key = '%#04x/aa%02x' % (op, high)
        try:
            res = probe.run(op, high=high, words=words)
        except EmulationError as exc:
            rows[key] = {'error': str(exc)}
            continue
        rows[key] = {
            'pc': res.get('pc'),
            'delta': res.get('delta'),
            'events': res.get('events'),
            'reads': res.get('vreg_reads'),
            'error': res.get('error'),
        }

print(json.dumps(rows, indent=1, ensure_ascii=False))
out = Path(r'D:\work\Apps\com.hylztn.helper\unpack\reports\probe_3rc.json')
out.write_text(json.dumps(rows, indent=1, ensure_ascii=False), encoding='utf-8')
print('[*] wrote', out)
