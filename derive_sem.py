#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run unmmp's own semantic derivation without the extract() stage.

``pipeline.restore`` does:

    runtime = NativeRuntime(nm, vm)
    probe = InstructionProbe(runtime)
    mapping = derive_semantic(probe, log)      # <- this script only does this

Stage 1 (``recover.extract``) is what forked samples cannot pass: it expects a
centralised RegisterNatives during JNI_OnLoad, while dpt-shell forks register
each class from its own ``<clinit>``. ``derive_semantic`` never looks at extract
output, so it can be driven directly once the interpreter entry is known.

Usage:
    python derive_sem.py <so> [-o mapping.json] [--vm-entry 0x3150c8]
    python derive_sem.py <so> --nm libnmmp.so --vm libnmmvm.so
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from unmmp_lib.elf import Elf                          # noqa: E402
from unmmp_lib.emulate import NativeRuntime, EmulationError  # noqa: E402
from unmmp_lib.probe import InstructionProbe           # noqa: E402
from unmmp_lib.semantic import derive_semantic         # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(prog='derive_sem', description=__doc__.splitlines()[0])
    parser.add_argument('so', nargs='?', help='single library holding both the method table and the VM')
    parser.add_argument('--nm', help='library that owns the method/bytecode tables')
    parser.add_argument('--vm', help='library that owns the interpreter')
    parser.add_argument('-o', '--out', help='write the opcode -> Dalvik name mapping as JSON')
    parser.add_argument('--vm-entry', help='link-time VA of the interpreter (sets UNMMP_VM_ENTRY)')
    args = parser.parse_args(argv)

    if not args.nm:
        if not args.so:
            parser.error('give either a single <so> or --nm/--vm')
        args.nm = args.vm = args.so
    elif not args.vm:
        args.vm = args.nm

    if args.vm_entry:
        os.environ['UNMMP_VM_ENTRY'] = args.vm_entry

    nm = Elf(open(args.nm, 'rb').read())
    vm = Elf(open(args.vm, 'rb').read())
    print('[*] machine=%d ptr=%d' % (nm.machine, nm.ptr), flush=True)

    runtime = NativeRuntime(nm, vm)
    print('[*] vm_entry = 0x%x' % (runtime.vm_entry - runtime.images[1][1]), flush=True)
    probe = InstructionProbe(runtime)
    print('[*] handler table = 0x%x (%d heads)' % (probe.table_va, len(probe.heads)), flush=True)

    try:
        mapping = derive_semantic(probe)
    except EmulationError as exc:
        print('[!] %s' % exc, flush=True)
        return 1

    named = {k: v for k, v in sorted(mapping.items())}
    print('[*] resolved %d/%d opcodes' % (len(named), 256), flush=True)
    for op, name in named.items():
        print('  0x%02x  %s' % (op, name))

    if args.out:
        Path(args.out).write_text(json.dumps({str(k): v for k, v in named.items()}, indent=2),
                                  encoding='utf-8')
        print('[*] wrote %s' % args.out, flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
