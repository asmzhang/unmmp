#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run the unmmp pipeline against a self-registering nmmp fork.

unmmp's ``Recovery.bind`` needs ``JNI_OnLoad`` to register natives. Shells that
register per class from ``<clinit>`` never populate that list, so the stock
pipeline stops at ``exported vmInterpret entry not found`` or at ``brk #1``
inside a lazy-init thunk. ``recover_static.StaticRecovery`` reads the static
registration table instead; everything downstream (semantic derivation, reference
resolution, lifting) is the upstream code, unchanged.

Usage:
    python restore_static.py <dir-with-libnmmp+dex> -o <out> --regid regid_map.tsv
                             [--vm-entry 0x3150c8] [--table 0x364540] [--bind-only]
"""
import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from unmmp_lib.elf import Elf                       # noqa: E402
from unmmp_lib.probe import InstructionProbe        # noqa: E402
from unmmp_lib.semantic import derive_semantic      # noqa: E402
from unmmp_lib.lifter import Lifter                 # noqa: E402
from unmmp_lib.recover_static import StaticRecovery  # noqa: E402
from unmmp_lib.pipeline import method_info, write_json  # noqa: E402
from unmmp_lib.rebuild import rebuild                # noqa: E402

DEFAULT_VM = '0x3150c8'
DEFAULT_TABLE = '0x364540'


def load_regids(path):
    regids = {}
    with open(path, encoding='utf-8') as handle:
        next(handle, None)
        for line in handle:
            parts = line.rstrip('\n').split('\t')
            if len(parts) < 3:
                continue
            regids[parts[0]] = int(parts[2])
    return regids


def collect(root):
    root = Path(root)
    libs = sorted(root.rglob('libnmmp.so'))
    if not libs:
        libs = sorted(root.rglob('*.so'))
    if not libs:
        raise SystemExit('no shared object under %s' % root)
    dexes = sorted(root.rglob('classes*.dex'), key=lambda p: (len(p.name), p.name))
    if not dexes:
        raise SystemExit('no dex under %s' % root)
    return libs[0], dexes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='directory holding the VM library and dex files')
    parser.add_argument('-o', '--out', required=True)
    parser.add_argument('--regid', required=True, help='TSV: class<TAB>method<TAB>id')
    parser.add_argument('--vm-entry', default=DEFAULT_VM)
    parser.add_argument('--table', default=DEFAULT_TABLE)
    parser.add_argument('--bind-only', action='store_true')
    parser.add_argument('--widths', default=None,
                        help='opcode_width.json harvested by harvest_widths.py')
    parser.add_argument('--mapping', help='reuse a previously derived opcode map (json)')
    parser.add_argument('--names', help='regid_names.json from resolve_names.py')
    parser.add_argument('--no-dex', action='store_true',
                        help='stop after lifting; do not assemble restored dex files')
    parser.add_argument('--tools', default=str(HERE / 'tools'),
                        help='directory holding baksmali-*.jar and smali-*.jar')
    args = parser.parse_args(argv)

    os.environ['UNMMP_VM_ENTRY'] = args.vm_entry
    os.environ['UNMMP_HANDLER_TABLE'] = args.table
    os.environ.setdefault('UNMMP_ALLOW_PARTIAL', '1')

    lib, dexes = collect(args.input)
    print('[*] lib  = %s' % lib)
    print('[*] dex  = %s' % ', '.join(d.name for d in dexes))
    data = open(str(lib), 'rb').read()
    nm, vm = Elf(data), Elf(data)
    regids = load_regids(args.regid)
    print('[*] regids = %d' % len(regids))

    dex_raw = [(d.name, open(str(d), 'rb').read()) for d in dexes]
    recovery = StaticRecovery(nm, vm, [raw for _, raw in dex_raw], regids,
                              names=json.load(open(args.names, encoding='utf-8'))
                              if args.names else None)
    recovery.bind()
    print('[*] methods = %d' % len(recovery.methods))
    if args.bind_only:
        return 0

    # PATCH(mmpfit): derive the opcode map on a clean runtime *before* capture;
    # capture leaves capture_vm state and per-method flags behind, which makes
    # the probe fall back to 33/256 instead of 180/256.
    probe = InstructionProbe(recovery.runtime)
    if args.mapping:
        # PATCH(mmpfit): reuse a map derived in a pristine run. Deriving here is
        # polluted by the JNI leniency the capture stage needs, which drops the
        # yield from 180/256 to 33/256.
        mapping = {int(k): v for k, v in json.load(open(args.mapping, encoding='utf-8')).items()}
        print('[*] opcode map (loaded) = %d' % len(mapping))
    else:
        mapping = derive_semantic(probe)
        print('[*] opcode map = %d' % len(mapping))

    if args.widths:
        # Widths come from watching the interpreter advance x22 on real bodies
        # (harvest_widths.py); without them a single unrecognised opcode would
        # discard the whole method.
        from unmmp_lib import decoder
        table = json.load(open(args.widths, encoding='utf-8'))
        decoder.DEFAULT_WIDTHS.update(
            {int(k, 16): int(max(v.items(), key=lambda kv: kv[1])[0])
             for k, v in table.items()})
        print('[*] widths (loaded) = %d' % len(decoder.DEFAULT_WIDTHS))

    recovery.capture()
    print('[*] blobs = %d, resolvers = %d, skipped = %d'
          % (len(recovery.blobs), len(recovery.sessions), len(recovery.failures)))
    os.makedirs(args.out, exist_ok=True)
    write_json(os.path.join(args.out, 'opcode_mapping.json'),
               {str(k): v for k, v in sorted(mapping.items())})
    write_json(os.path.join(args.out, 'opcode_aliases.json'),
               getattr(probe, 'aliases', {}))

    # Always emit the raw code units: even when the opcode map cannot decode a
    # body yet, the captured instruction stream is the real payload and is worth
    # keeping (it is what a later pass will lift once the map is complete).
    raw = {}
    for m in recovery.methods:
        th = recovery.blobs.get(m['thunk'])
        if not th:
            continue
        units = recovery.instructions(m)
        raw.setdefault(m['class'], []).append(
            {'name': m['name'], 'sig': m['sig'], 'size': th['size'],
             'units': ['%04x' % u for u in units]})
    write_json(os.path.join(args.out, 'raw_bodies.json'), raw)
    print('[*] raw bodies: %d methods in %d classes'
          % (sum(len(v) for v in raw.values()), len(raw)))

    failures = recovery.resolve_references(mapping)
    if failures:
        write_json(os.path.join(args.out, 'decode_failures.json'), failures)
        print('[!] decode failed for %d/%d methods' % (len(failures), len(recovery.methods)))
        # A partial map is expected on a custom VM: keep the methods that did
        # decode rather than discarding the whole corpus.
        if not os.environ.get('UNMMP_ALLOW_PARTIAL'):
            return 1
    kinds = recovery.refine_invokes(mapping)
    recovery.refine_returns(mapping)
    write_json(os.path.join(args.out, 'opcode_mapping.json'),
               {str(k): v for k, v in sorted(mapping.items())})

    info = method_info(recovery.definitions, kinds)
    lifted = {}
    bad = []
    for m in recovery.methods:
        if m['thunk'] not in recovery.blobs:
            bad.append((m['class'] + '.' + m['name'], 'not captured'))
            continue
        m['static'] = bool(recovery.definitions[(m['class'], m['name'], m['sig'])][0] & 8)
        if m.get('resolver') not in recovery.sessions:
            bad.append((m['class'] + '.' + m['name'], 'no resolver session'))
            continue
        pool = recovery.sessions[m['resolver']]
        pool.semantic_aliases = getattr(probe, 'aliases', {})
        th = recovery.blobs[m['thunk']]
        try:
            body, maxreg, _ = Lifter(pool, mapping, nm.data, nm.vaddr_to_off, info).lift(m, th)
        except Exception as exc:                       # noqa: BLE001 - report, do not abort
            bad.append((m['class'] + '.' + m['name'], '%s: %s' % (type(exc).__name__, exc)))
            continue
        if body is None:
            bad.append((m['class'] + '.' + m['name'], 'lift returned None'))
            continue
        regs = th['nregs']
        if regs is None:
            regs = max(maxreg + 2, 1)
        lifted.setdefault(m['class'], []).append(
            {'name': m['name'], 'sig': m['sig'], 'static': m['static'],
             'regs': regs, 'body': body})
    write_json(os.path.join(args.out, 'lifted_bodies.json'), lifted)
    write_json(os.path.join(args.out, 'native_methods.json'), recovery.methods)
    if bad:
        write_json(os.path.join(args.out, 'lift_failures.json'), bad)
    print('[*] lifted %d methods in %d classes (%d failed)'
          % (sum(len(v) for v in lifted.values()), len(lifted), len(bad)))

    summary = {'backend': 'static', 'machine': nm.machine,
               'methods': len(recovery.methods), 'blobs': len(recovery.blobs),
               'resolvers': len(recovery.sessions), 'capture_failures': len(recovery.failures),
               'lifted': sum(len(v) for v in lifted.values()), 'lift_failed': len(bad),
               'opcodes_mapped': len(mapping), 'dex_files': [], 'patched': 0}
    if not args.no_dex:
        # The dex is the actual deliverable; everything above is evidence. Methods
        # whose body still holds UNKNOWN operands stay native and are listed in
        # recovery_summary.json rather than aborting the run.
        dex_summary = rebuild(dex_raw, lifted, args.out, args.tools)
        summary.update(dex_summary)
        print('[*] restored dex files: %d, patched methods: %d'
              % (len(dex_summary['dex_files']), dex_summary['patched']))
    write_json(os.path.join(args.out, 'recovery_summary.json'), summary)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
