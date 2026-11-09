# -*- coding: utf-8 -*-
"""Rebuild restored dex files from lifted method bodies.

``pipeline._restore`` patches and assembles in one pass but aborts on the first
mismatch.  A custom VM always leaves part of the opcode map unresolved, so a
shell that cannot be fully decoded should still produce a *usable* dex: the
methods that were lifted get real bodies, everything else keeps its ``native``
declaration and is reported in the summary.

Two failure modes are tolerated here (both are recorded, never fatal):

* a body that still carries ``UNKNOWN`` operands cannot be assembled by smali,
  so it is left as a native declaration;
* a native declaration that does not match exactly once in the class is skipped.
"""
import hashlib
import os
import re
import shutil
import struct
import zlib

from . import build
from .assemble import assemble_tree

API_BY_VERSION = {'035': 15, '037': 24, '038': 26, '039': 28}


def _dex_api(raw):
    version = raw[4:7].decode('ascii', 'replace')
    if version not in API_BY_VERSION:
        raise RuntimeError('unsupported original dex version: %r' % version)
    return API_BY_VERSION[version]


def _method_pattern(name, sig):
    return re.compile(r'^(\.method[^\n]*?[ \t]' + re.escape(name + sig) +
                      r'[ \t]*)\r?\n(.*?)^\.end method\b', re.M | re.S)


def _patch_class(path, cls, methods, failures):
    """Replace native declarations with lifted bodies; return the patch count."""
    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    patched = 0
    for m in methods:
        label = m['name'] + m['sig']
        if 'UNKNOWN' in m['body']:
            failures.append([cls, label, 'unresolved opcodes in body'])
            continue
        matches = list(_method_pattern(m['name'], m['sig']).finditer(text))
        if len(matches) != 1:
            failures.append([cls, label, 'declaration matched %d times' % len(matches)])
            continue
        match = matches[0]
        head = match.group(1)
        if not re.search(r'\bnative\b', head):
            failures.append([cls, label, 'declaration is not native'])
            continue
        head = re.sub(r'\bnative[ \t]*', '', head).rstrip()
        body = (head + '\n    .registers %d\n' % m['regs'] +
                match.group(2) + '\n' + m['body'] + '\n.end method')
        text = text[:match.start()] + body + text[match.end():]
        patched += 1
    if patched:
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
    return patched


def rebuild(dexes, lifted, out, tools, log=print):
    """dexes: [(name, raw bytes)]; lifted: {class: [method dict, ...]}."""
    jars = build.require_jars(tools)
    build.find_java()
    work = os.path.join(out, 'work')
    os.makedirs(work, exist_ok=True)

    summary = {'dex_files': [], 'patched': 0, 'patch_failures': [],
               'dex_sources': {}, 'verified': []}
    next_dex = 1
    for name, raw in dexes:
        stem = os.path.splitext(os.path.basename(name))[0]
        suffix = '' if stem == 'classes' else '_' + stem
        work_dex = os.path.join(work, stem + '.dex')
        with open(work_dex, 'wb') as handle:
            handle.write(raw)
        bak = os.path.join(out, 'smali' + suffix)
        patched_dir = os.path.join(out, 'patched_smali' + suffix)
        for directory in (bak, patched_dir):
            if os.path.isdir(directory):
                shutil.rmtree(directory)
        # baksmali aborts on a code item whose last instruction runs past
        # insns_size. dpt-shell leaves such stubs behind, and there is no
        # --ignore-errors switch, so a non-zero exit is only fatal when nothing
        # was written: the offending classes are skipped and reported instead.
        rc, out = build.run_jar(jars['baksmali'], ['disassemble', '-o', bak, work_dex],
                                lambda *a, **k: None)
        dropped = sorted(set(re.findall(r'disassembling class (L[^;\s]+;)', out)))
        if rc or dropped:
            summary.setdefault('baksmali_errors', {})[name] = dropped
            log('[!] %s: baksmali rc=%d, %d class(es) skipped: %s'
                % (name, rc, len(dropped), ', '.join(dropped[:5]) or '-'))
        if not os.path.isdir(bak) or not any(
                f.endswith('.smali') for _, _, files in os.walk(bak) for f in files):
            raise RuntimeError('baksmali produced nothing for %s' % name)
        shutil.copytree(bak, patched_dir)

        count = 0
        for cls, methods in lifted.items():
            path = os.path.join(patched_dir, cls.replace('/', os.sep) + '.smali')
            if not os.path.isfile(path):
                continue                     # class belongs to another dex
            count += _patch_class(path, cls, methods, summary['patch_failures'])
        log('[*] %s patched methods: %d' % (name, count))
        summary['patched'] += count

        outputs = assemble_tree(patched_dir, out, stem, jars['smali'], next_dex,
                                log, api=_dex_api(raw))
        next_dex += len(outputs)
        summary['dex_files'].extend(outputs)
        summary['dex_sources'][name] = outputs

    for path in summary['dex_files']:
        with open(path, 'rb') as handle:
            data = handle.read()
        ok = (data[12:32] == hashlib.sha1(data[32:]).digest() and
              struct.unpack_from('<I', data, 8)[0] == (zlib.adler32(data[12:]) & 0xffffffff))
        summary['verified'].append([os.path.basename(path), bool(ok)])
        if not ok:
            raise RuntimeError('restored dex checksum invalid: %s' % path)
    return summary
