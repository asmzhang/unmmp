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


_VREG = re.compile(r'\bv(\d+)\b')


def _param_registers(sig, is_static):
    """Dalvik register slots taken by the parameters (plus `this`)."""
    body = sig[1:sig.index(')')] if '(' in sig else ''
    count = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '[':
            while body[i] == '[':
                i += 1
            if body[i] == 'L':
                i = body.index(';', i) + 1
            else:
                i += 1
            count += 1
        elif ch == 'L':
            i = body.index(';', i) + 1
            count += 1
        else:
            count += 2 if ch in 'JD' else 1
            i += 1
    return count + (0 if is_static else 1)


def _register_count(body, declared, sig='', is_static=False):
    """The lifter emits absolute VM register indices, which can exceed the
    method's declared registers_size; smali needs .registers to cover them."""
    used = [int(n) for n in _VREG.findall(body)]
    return max([declared, _param_registers(sig, is_static)] + [n + 1 for n in used])


_RETURN_OF = {'V': 'return-void', 'Z': 'return', 'B': 'return', 'S': 'return',
              'C': 'return', 'I': 'return', 'F': 'return',
              'J': 'return-wide', 'D': 'return-wide'}


def _expected_return(sig):
    tail = sig[sig.rindex(')') + 1:]
    if tail.startswith('[') or tail.startswith('L'):
        return 'return-object'
    return _RETURN_OF.get(tail[:1])


def _body_ops(body):
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith(':') or line.startswith('.'):
            continue
        out.append(line)
    return out


def verify_body(body, sig, is_static=False, declared=0):
    """Decide whether a lifted body may replace a native declaration.

    A body that merely assembles is not a restored method: the lifter emits
    operands using the *standard* Dalvik format of whatever name it guessed,
    so a wrong name yields a body that is syntactically valid but
    semantically nonsense (e.g. a method returning V replaced by
    ``return-void``, or a value-returning method replaced by ``return-void``).
    Anything that fails a check keeps its ``native`` declaration.

    Returns ``(ok, reason)``.
    """
    if 'UNKNOWN' in body:
        return False, 'unresolved opcodes in body'
    ops = _body_ops(body)
    if not ops:
        return False, 'empty body'
    last = ops[-1].split()[0]
    want = _expected_return(sig)
    if last != 'throw':
        if want is None:
            return False, 'unparsable return type'
        if last != want:
            return False, 'return mismatch: body ends with %s, signature wants %s' % (last, want)
    used = [int(n) for n in _VREG.findall(body)]
    if used:
        top = max(used)
        if top > 65535:
            return False, 'register index v%d out of range' % top
        if top >= 1000:
            return False, 'implausible register index v%d' % top
        if declared and top < declared and top >= 1000:
            return False, 'register index v%d exceeds declared %d' % (top, declared)
    return True, ''


def _patch_class(path, cls, methods, failures, stats=None):
    """Replace native declarations with lifted bodies; return the patch count.

    Only bodies that pass :func:`verify_body` are written. ``stats`` collects
    ``syntax_patched`` (bodies that were UNKNOWN-free and matched a native
    declaration) and ``semantic_verified`` (the subset actually written).
    """
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
        if stats is not None:
            stats['syntax_patched'] = stats.get('syntax_patched', 0) + 1
        ok, reason = verify_body(m['body'], m['sig'], m.get('static', False),
                                 m.get('regs', 0))
        if not ok:
            failures.append([cls, label, 'kept native: ' + reason])
            if stats is not None:
                stats['kept_native'] = stats.get('kept_native', 0) + 1
            continue
        head = re.sub(r'\bnative[ \t]*', '', head).rstrip()
        regs = _register_count(m['body'], m['regs'], m['sig'], m['static'])
        body = (head + '\n    .registers %d\n' % regs +
                match.group(2) + '\n' + m['body'] + '\n.end method')
        text = text[:match.start()] + body + text[match.end():]
        patched += 1
        if stats is not None:
            stats['semantic_verified'] = stats.get('semantic_verified', 0) + 1
    if patched:
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
    return patched


def _index_tree(root):
    """class descriptor -> smali path, for one tree."""
    index = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if not name.endswith('.smali'):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding='utf-8') as handle:
                    for line in handle:
                        if line.startswith('.class '):
                            index[line.rstrip().rsplit(' ', 1)[-1]] = path
                            break
            except OSError:
                continue
    return index


def rebuild_from_tree(roots, lifted, out, tools, log=print, api=28):
    """Rebuild from smali trees that already exist on disk.

    ``roots`` is ``[(stem, smali_dir)]``.  This exists because baksmali is not
    always usable as the first step: a shell can leave code items whose
    insns_size disagrees with the instruction stream, and baksmali drops the
    whole class rather than the one bad method.  When the trees were produced
    some other way (an earlier unpack, a manual dump), patching them in place
    avoids re-disassembling at all.
    """
    jars = build.require_jars(tools)
    build.find_java()
    work = os.path.join(out, 'work')
    os.makedirs(work, exist_ok=True)

    summary = {'dex_files': [], 'syntax_patched': 0, 'semantic_verified': 0,
               'kept_native': 0, 'patch_failures': [],
               'dex_sources': {}, 'verified': [], 'missing_classes': []}
    patched_dirs = []
    index = {}
    for stem, root in roots:
        patched_dir = os.path.join(out, 'patched_smali_' + stem)
        if os.path.isdir(patched_dir):
            shutil.rmtree(patched_dir)
        shutil.copytree(root, patched_dir)
        patched_dirs.append((stem, patched_dir))
        index.update(_index_tree(patched_dir))
    log('[*] indexed %d classes over %d tree(s)' % (len(index), len(roots)))

    missing = set()
    for cls, methods in lifted.items():
        path = index.get('L' + cls + ';')
        if not path:
            missing.add(cls)
            continue
        summary['semantic_verified'] += _patch_class(
            path, cls, methods, summary['patch_failures'], summary)
    summary['missing_classes'] = sorted(missing)
    log('[*] syntax-patched %d, semantically verified %d, kept native %d'
        ' (%d class(es) not found)'
        % (summary['syntax_patched'], summary['semantic_verified'],
           summary['kept_native'], len(missing)))

    next_dex = 1
    for stem, patched_dir in patched_dirs:
        outputs = assemble_tree(patched_dir, out, stem, jars['smali'], next_dex,
                                log, api=api)
        next_dex += len(outputs)
        summary['dex_files'].extend(outputs)
        summary['dex_sources'][stem] = outputs

    for path in summary['dex_files']:
        with open(path, 'rb') as handle:
            data = handle.read()
        ok = (data[12:32] == hashlib.sha1(data[32:]).digest() and
              struct.unpack_from('<I', data, 8)[0] == (zlib.adler32(data[12:]) & 0xffffffff))
        summary['verified'].append([os.path.basename(path), bool(ok)])
    return summary


def rebuild(dexes, lifted, out, tools, log=print):
    """dexes: [(name, raw bytes)]; lifted: {class: [method dict, ...]}."""
    jars = build.require_jars(tools)
    build.find_java()
    work = os.path.join(out, 'work')
    os.makedirs(work, exist_ok=True)

    summary = {'dex_files': [], 'syntax_patched': 0, 'semantic_verified': 0,
               'kept_native': 0, 'patch_failures': [],
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
            count += _patch_class(path, cls, methods, summary['patch_failures'],
                                  summary)
        log('[*] %s semantically verified: %d' % (name, count))
        summary['semantic_verified'] += count

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
