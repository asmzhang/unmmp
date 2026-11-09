"""Harvest opcode widths by watching the interpreter run real method bodies.

`trace_body.py` proved that the Dalvik instruction pointer lives in x22 and that
watching it yields the landing offset of every decoded instruction.  This tool
does that at scale: for each captured method it replays the body, records the
offsets the VM actually lands on, and votes on how many code units each opcode
consumes.

Widths are the one piece of the encoding that cannot be read off the handler
bodies (the dispatch table holds lazy-decrypt thunks, so the entry prologue says
nothing about operand layout), and without them no decoder can skip an opcode it
does not yet understand.
"""
import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X22

from unmmp_lib.elf import Elf
from unmmp_lib.recover_static import StaticRecovery
from restore_static import load_regids, collect

SKIP = {'error', 'budget'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--regid', required=True)
    ap.add_argument('--vm-entry', default='0x3150c8')
    ap.add_argument('--limit', type=int, default=40)
    ap.add_argument('--contains', default='',
                    help='only trace methods whose body uses these opcodes (hex, comma)')
    ap.add_argument('--max-dispatch', type=int, default=40)
    ap.add_argument('-o', '--out', required=True)
    args = ap.parse_args()

    os.environ['UNMMP_VM_ENTRY'] = args.vm_entry
    os.environ.setdefault('UNMMP_HANDLER_TABLE', '0x364540')
    os.environ.setdefault('UNMMP_JNI_LENIENT', '1')
    os.environ.setdefault('UNMMP_CAPTURE_TOLERANT', '1')

    lib, dex_paths = collect(args.input)
    nm = Elf(open(str(lib), 'rb').read())
    vm = Elf(open(str(lib), 'rb').read())
    dexes = [open(str(p), 'rb').read() for p in dex_paths]
    regids = load_regids(args.regid)

    rec = StaticRecovery(nm, vm, dexes, regids, log=lambda *_: None)
    rec.bind()
    rec.capture()

    rt = rec.runtime
    base = rt.BASES[0]
    votes = defaultdict(lambda: defaultdict(int))
    done = 0

    state = {'ip': [], 'lo': 0, 'hi': 0, 'n': 0, 'on': False}

    def on_code(uc, address, size, _):
        if not state['on']:
            return
        if state['n'] >= args.max_dispatch:
            raise SystemExit
        ip = uc.reg_read(UC_ARM64_REG_X22) - base
        if not (state['lo'] <= ip <= state['hi']):
            return
        if state['ip'] and state['ip'][-1] == ip:
            return
        state['ip'].append(ip)
        state['n'] += 1

    rt.uc.hook_add(UC_HOOK_CODE, on_code, begin=base, end=base + 0x500000)

    wanted = {int(x, 16) for x in args.contains.split(',') if x.strip()}
    order = list(rec.methods)
    if wanted:
        # Trace the methods that actually contain the opcodes still blocking the
        # decoder: a width only shows up where the instruction executes.
        order.sort(key=lambda m: -sum(1 for u in (m.get('units') or [])
                                      if (u & 0xFF) in wanted))
        order = [m for m in order
                 if any((u & 0xFF) in wanted for u in (m.get('units') or []))]

    for m in order:
        units = m.get('units')
        if not units or done >= args.limit:
            continue
        va = m.get('insns') or rec.blobs[m['thunk']]['insns']
        state.update(ip=[], lo=va, hi=va + 2 * len(units), n=0, on=True)
        rec._reset_flag(m['entry'])
        rt.heap_next = rt.heap_next
        try:
            rt.call(m['entry'], [rt.env, rt.handle('object', 'this')] + [0x5b] * 40)
        except SystemExit:
            pass
        except Exception:
            state['on'] = False
            continue
        state['on'] = False
        seq = [ip - va for ip in state['ip']]
        for a, b in zip(seq, seq[1:]):
            if b <= a:
                continue
            ia, ib = a // 2, b // 2
            if ia >= len(units) or ib > len(units):
                continue
            op = units[ia] & 0xFF
            votes[op][ib - ia] += 1
        done += 1
        if done % 10 == 0:
            print('[*] %d methods traced' % done)

    result = {('%#04x' % op): dict(sorted(v.items(), key=lambda kv: -kv[1])[:3])
              for op, v in votes.items()}
    json.dump(result, open(args.out, 'w', encoding='utf-8'), indent=1)
    print('[*] traced %d methods, %d opcodes observed' % (done, len(result)))
    for op in sorted(votes):
        top = max(votes[op].items(), key=lambda kv: kv[1])
        print('  %#04x  width=%d  (%d votes)' % (op, top[0], top[1]))


if __name__ == '__main__':
    main()
