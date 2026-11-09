#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recover the self-registration table of a dpt-shell-fork smali tree.

Those shells strip every protected method down to a native declaration and
have each class register itself from its own ``<clinit>``::

    const/16 v0, 0xa1
    invoke-static {v0}, LUnPUtFOFz/.../exh6QERbMc2cqeSl;->mPdUI2cA5Z(I)V

so there is no central registration table to read. The ``id`` is the row index
into the on-disk method table (see ``unmmp_lib/recover_static.py``), which makes
this scan the entry point for static binding.

The helper class and method names are obfuscated per build, so pass them in.

Usage:
    python scan_regids.py <smali_root> -o regids.tsv [--register-method mPdUI2cA5Z]
    python scan_regids.py <smali_root> --stats
"""
import argparse
import os
import re
import sys
import collections

CLS_RE = re.compile(
    r'^\.class\s+(?:public\s+|private\s+|protected\s+|final\s+|abstract\s+|'
    r'synthetic\s+|interface\s+|enum\s+|annotation\s+)*L([^;]+);')
METHOD_RE = re.compile(r'^\.method\s+(.*?)([A-Za-z0-9_$<>]+)\((.*?)\)(\S+)\s*$')
CONST_RE = re.compile(
    r'^\s*const(?:/4|/16|/high16)?\s+(v\d+|p\d+)\s*,\s*(0x[0-9a-fA-F]+|-?\d+)\s*$')
REG_CALL_RE = re.compile(r'invoke-(?:static|virtual|direct)(?:/range)?\s+\{([^}]*)\},\s*'
                         r'L([^;]+);->([A-Za-z0-9_$]+)\((.*?)\)(\S+)')


def scan(root, register_method):
    rows = []
    files = 0
    unresolved = 0
    for dirpath, _dirs, filenames in os.walk(root):
        for fn in filenames:
            if not fn.endswith('.smali'):
                continue
            files += 1
            path = os.path.join(dirpath, fn)
            try:
                lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
            except OSError:
                continue

            cls = None
            for line in lines:
                m = CLS_RE.match(line)
                if m:
                    cls = m.group(1)
                    break
            if cls is None:
                continue

            # Forward pass: keep the last constant written to each register, so
            # the value at the call site is whatever fed it, however far back.
            cur_method = '?'
            consts = {}
            for line in lines:
                m = METHOD_RE.match(line)
                if m:
                    cur_method = m.group(2)
                    consts = {}
                    continue
                if line.startswith('.end method'):
                    consts = {}
                    continue
                c = CONST_RE.match(line)
                if c:
                    try:
                        consts[c.group(1)] = int(c.group(2), 0)
                    except ValueError:
                        pass
                    continue
                r = REG_CALL_RE.search(line)
                if not r or r.group(3) != register_method or r.group(5) != 'V':
                    continue
                if r.group(4).strip() != 'I':
                    continue
                operands = r.group(1)
                first = operands.split('..')[0].split(',')[0].strip()
                idval = consts.get(first)
                if idval is None:
                    unresolved += 1
                rows.append((cls, cur_method, idval,
                             os.path.relpath(path, root)))
    return rows, files, unresolved


def main(argv=None):
    p = argparse.ArgumentParser(prog='scan_regids',
                                description=__doc__.splitlines()[0])
    p.add_argument('root', help='smali tree (searched recursively)')
    p.add_argument('-o', '--out', help='write TSV here (class, method, id, id_hex, relpath)')
    p.add_argument('--register-method', default='mPdUI2cA5Z',
                   help='name of the helper method the classes call (default: %(default)s)')
    p.add_argument('--stats', action='store_true', help='print a per-id summary')
    args = p.parse_args(argv)

    rows, files, unresolved = scan(args.root, args.register_method)
    if not rows:
        print('no self-registration calls found under %s' % args.root, file=sys.stderr)
        print('try --register-method <name>; the helper is renamed per build',
              file=sys.stderr)
        return 1

    seen = {}
    for cls, method, idval, rel in rows:
        seen.setdefault((cls, idval), (cls, method, idval, rel))

    ordered = sorted(seen.values(),
                     key=lambda r: (r[2] if r[2] is not None else -1, r[0]))

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write('class\tmethod\tid\tid_hex\trelpath\n')
            for cls, method, idval, rel in ordered:
                fh.write('%s\t%s\t%s\t%s\t%s\n' % (
                    cls, method,
                    idval if idval is not None else '',
                    ('0x%x' % idval) if idval is not None else '',
                    rel))
        print('written -> %s' % args.out, file=sys.stderr)

    by_id = collections.defaultdict(list)
    for cls, _m, idval, _r in seen.values():
        by_id[idval].append(cls)

    print('scanned %d smali files' % files)
    print('calls found %d, unique (class,id) %d, unresolved id %d'
          % (len(rows), len(seen), unresolved))
    print('distinct ids %d (of which unresolved: %s)'
          % (len(by_id), 'yes' if None in by_id else 'no'))

    dupes = {k: v for k, v in by_id.items() if k is not None and len(v) > 1}
    if dupes:
        print('WARNING: %d id(s) claimed by more than one class' % len(dupes))
        for k in sorted(dupes)[:10]:
            print('  id=%d x%d  %s' % (k, len(dupes[k]), ', '.join(dupes[k][:3])))

    if args.stats:
        print('\nid\tclasses\tfirst class')
        for idval in sorted(by_id, key=lambda x: (x is None, x)):
            label = str(idval) if idval is not None else '?'
            print('%s\t%d\t%s' % (label, len(by_id[idval]), by_id[idval][0]))
    return 0


if __name__ == '__main__':
    sys.exit(main())
