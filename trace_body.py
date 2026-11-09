"""Trace the VM dispatch loop while it runs a real method body.

The interpreter keeps its Dalvik instruction pointer in x22 and re-enters the
main-loop handler (the slot-0 body) once per decoded instruction:

    ldrh w27, [x22, #2]!        ; fetch next code unit, advance the pointer
    ...
    br   x8                     ; -> handler

Hooking that single address therefore yields the exact code-unit offset of every
instruction the VM executes.  Successive differences are the instruction widths,
which is the one fact the static handler analysis could not pin down (the table
entries are lazy-decrypt thunks, so their prologues say nothing about width).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X22

from unmmp_lib.emulate import NativeRuntime
from unmmp_lib.elf import Elf
from unmmp_lib.recover_static import StaticRecovery

MAIN_LOOP = 0x31be0c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nm', required=True)
    ap.add_argument('--vm', required=True)
    ap.add_argument('--regid', required=True)
    ap.add_argument('--dex', nargs='+', required=True)
    ap.add_argument('--cls', required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--vm-entry', default='0x3150c8')
    ap.add_argument('--max-dispatch', type=int, default=64)
    args = ap.parse_args()

    dexes = [open(p, 'rb').read() for p in args.dex]
    from restore_static import load_regids
    regids = load_regids(args.regid)

    os.environ['UNMMP_VM_ENTRY'] = args.vm_entry
    nm = Elf(open(args.nm, 'rb').read())
    vm = Elf(open(args.vm, 'rb').read())
    rec = StaticRecovery(nm, vm, dexes, regids)
    rec.bind()
    target = next(m for m in rec.methods
                  if m['class'] == args.cls and m['name'] == args.name)
    print('[*] %s.%s sig=%s entry=%#x size_hint=%s'
          % (args.cls, args.name, target['sig'], target['entry'], target.get('size')))

    nm = rec.runtime
    base = nm.BASES[0]
    trace = []
    seen = {'n': 0}

    def on_code(uc, address, size, _):
        if seen['n'] >= args.max_dispatch:
            raise SystemExit
        ip = uc.reg_read(UC_ARM64_REG_X22) - base
        if trace and trace[-1] == ip:
            return
        trace.append(ip)
        seen['n'] += 1

    # Handlers tail-jump straight into the next handler (`br x8`), so the slot-0
    # body only runs once. Instead watch the whole image and record the Dalvik
    # instruction pointer (x22) whenever it moves: that is one entry per decoded
    # instruction, whatever handler ran.
    nm.uc.hook_add(UC_HOOK_CODE, on_code, begin=base, end=base + 0x500000)

    this_handle = nm.handle('object', 'this')
    try:
        nm.call(target['entry'], [nm.env, this_handle] + [0x5b] * 40)
    except Exception as exc:
        print('[!] stopped: %s' % exc)

    if not trace:
        print('[!] dispatch loop never reached')
        return
    print('[*] dispatches=%d' % len(trace))
    body = rec.instructions(target) if target.get('units') else []
    prev = None
    for i, ip in enumerate(trace):
        delta = '' if prev is None else '(+%d)' % ((ip - prev) // 2)
        unit = '%04x' % body[ip // 2] if body and ip // 2 < len(body) else '----'
        print('  %2d  off=%#06x  unit=%s  %s' % (i, ip, unit, delta))
        prev = ip
    json.dump(trace, open(os.path.join(os.path.dirname(args.regid) or '.',
                                       'dispatch_trace.json'), 'w'), indent=1)


if __name__ == '__main__':
    main()
