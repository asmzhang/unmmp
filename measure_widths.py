"""Measure how much of the corpus becomes structurally parseable.

Unknown opcodes are the only reason a whole method is thrown away today. Feeding
the trace-harvested widths into the decoder lets it step over those instructions
instead of aborting, so this reports the payoff before the lifter is taught to
emit them.
"""
import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unmmp_lib.decoder import decode

RAW = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bodies', required=True)
    ap.add_argument('--mapping', required=True)
    ap.add_argument('--widths', required=True)
    args = ap.parse_args()

    bodies = json.load(open(args.bodies, encoding='utf-8'))
    mapping = {int(k): v for k, v in json.load(open(args.mapping, encoding='utf-8')).items()}
    widths = {int(k, 16): int(max(v.items(), key=lambda kv: kv[1])[0])
              for k, v in json.load(open(args.widths, encoding='utf-8')).items()}

    total = ok_plain = ok_wide = 0
    blocked = Counter()
    for cls, methods in bodies.items():
        for m in methods:
            total += 1
            units = [int(u, 16) for u in m['units']]
            ok1, err1, _ = decode(units, len(units), None, mapping)
            ok2, err2, ops2 = decode(units, len(units), None, mapping, widths)
            ok_plain += bool(ok1)
            ok_wide += bool(ok2)
            if not ok2:
                blocked[err2.split(' at ')[0]] += 1

    print('methods           : %d' % total)
    print('parsed (map only) : %d' % ok_plain)
    print('parsed (+widths)  : %d' % ok_wide)
    print('still blocked     : %s' % blocked.most_common(6))


if __name__ == '__main__':
    main()
