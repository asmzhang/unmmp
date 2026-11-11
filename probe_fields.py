"""Confirm which JNI field accessor each candidate opcode reaches.

Run after the JNI index table in `emulate.py` was corrected against jni.h.
A field getter/setter shows up as a `field-get`/`field-put` event carrying the
value width, which is what separates `sget-object` from `sput-short` without
having to read the handler by hand.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unmmp_lib.elf import Elf                                  # noqa: E402
from unmmp_lib.emulate import NativeRuntime                    # noqa: E402
from unmmp_lib.probe import InstructionProbe                   # noqa: E402

DEFAULT_SO = (r'D:\work\Apps\com.hylztn.helper\unpack\decrypted_so'
              r'\06759a4000eaa96f47a5bfd561cc1794.so')


def main(argv=None):
    p = argparse.ArgumentParser(prog='probe_fields', description=__doc__.splitlines()[0])
    p.add_argument('--so', default=DEFAULT_SO)
    p.add_argument('--ops', default='0x01,0x15,0x5b,0x62,0x8c,0x94,0xa0,0xa7,0xc9,0xd4,0xe2,0xec')
    p.add_argument('--high', default='0x00')
    p.add_argument('--words', default='0,1,2,0')
    p.add_argument('--vm-entry', default='0x3150c8')
    p.add_argument('--table', default='0x364540')
    p.add_argument('-o', '--out')
    a = p.parse_args(argv)

    os.environ['UNMMP_VM_ENTRY'] = a.vm_entry
    os.environ['UNMMP_HANDLER_TABLE'] = a.table
    os.environ.setdefault('UNMMP_JNI_FAKE', '1')

    data = open(a.so, 'rb').read()
    runtime = NativeRuntime(Elf(data), Elf(data))
    probe = InstructionProbe(runtime)

    ops = [int(x, 0) for x in a.ops.split(',') if x.strip()]
    high = int(a.high, 0)
    words = tuple(int(x, 0) for x in a.words.split(','))
    rows = []
    for op in ops:
        try:
            tr = probe.run(op, high=high, words=words)
        except Exception as exc:                                # noqa: BLE001
            rows.append({'op': '%#04x' % op, 'error': str(exc)[:120]})
            print('%#04x  ERROR %s' % (op, str(exc)[:90]))
            continue
        ev = [e for e in tr['events'] if e[0] in ('field-get', 'field-put', 'field', 'method',
                                                  'resolve', 'jni', 'string', 'class')]
        rows.append({'op': '%#04x' % op, 'pc': tr['pc'], 'delta': tr['delta'], 'events': ev,
                     'error': tr['error']})
        print('%#04x  pc=%-3d delta=%-22s %s'
              % (op, tr['pc'], json.dumps(tr['delta']),
                 ' '.join(str(e) for e in ev[:5])))

    if a.out:
        json.dump(rows, open(a.out, 'w', encoding='utf-8'), indent=1)
        print('[*] wrote', a.out)


if __name__ == '__main__':
    main()
