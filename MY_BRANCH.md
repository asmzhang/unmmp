# `my` branch — adaptations for lazily-registered, stripped VMs

Upstream `unmmp` assumes a very specific shape: `JNI_OnLoad` exports
`vmInterpret`, registers every native centrally, and the `.so` keeps its
symbols. Samples from the dpt-shell-fork families break all three:

| upstream assumption | what those samples do instead |
|---|---|
| `JNI_OnLoad` exports `vmInterpret` | symbols stripped; only `JNI_OnLoad` survives, 84 bytes |
| registration happens inside `JNI_OnLoad` | each class registers itself from its own `<clinit>` via `mPdUI2cA5Z(id)` |
| one `.so` per role | `libnmmp.so` and `libnmmvm.so` are the **same file** |

`Recovery.extract()` therefore dies at its first step and nothing downstream
ever runs. This branch adds a second binding path that reads the method table
straight out of the file, plus the tolerance needed to get through capture.

Nothing here is sample-specific: every address is a command-line argument.

## Library changes

### `unmmp_lib/emulate.py`

- **`UNMMP_VM_ENTRY`** — hex offset of the interpreter entry, resolved against
  whichever image actually contains it:

  ```python
  candidates = [img[1] + off for img in self.images]
  self.vm_entry = next((va for va in candidates if lo <= va < hi), ...)
  ```

  Upstream used `images[1]` unconditionally, which is right only when nmmp and
  nmmvm are separate libraries. When they are one file the interpreter lives in
  `images[0]` and the computed entry lands outside the mapped range, so capture
  returns `0/1513` blobs with no error.

- **libc stubs** — `dlopen`/`dlsym`/`__android_log_*`/`pthread_*`/`sysconf`/
  `getpid`/`clock_gettime`/`__system_property_get`/`getauxval`/`syscall`, etc.
  Without these the loader init aborts on the first external call.

- **JNI 95/96/97** (`GetStaticFieldID`, `GetMethodID`, `GetStaticMethodID`)
  routed into the existing ID path; previously they fell through to
  `unsupported JNI call`.

- **`cstring()` decodes with `'replace'`** — obfuscated name tables contain
  bytes that are not valid UTF-8 and `surrogatepass` raises.

- **`UNMMP_JNI_LENIENT=1`** — unknown JNI index returns 0 instead of raising.
  Required for capture; it degrades semantic derivation, so pass a mapping file
  computed in a clean run (`--mapping`) rather than recomputing it here.

### `unmmp_lib/handlers.py`

- **`UNMMP_HANDLER_TABLE`** — force the dispatch table address. The bare scan
  locates a plausible run of code pointers 56 bytes before the real table
  (221 heads instead of 219), which shifts **every** slot index. Always set it
  when you know the address from static analysis.

### `unmmp_lib/recover.py`

- `extract()` split into `bind()` + `capture()`; `extract()` still calls both.
- **`UNMMP_CAPTURE_TOLERANT=1`** — record `{'class','name','sig','error'}` and
  continue. Without it the first failing method aborts all 1500.
- **Thunk dedupe removed.** Two methods can share one wrapper; identity comes
  from the data pointer passed at call time, not from the entry point. Skipping
  "already seen" thunks silently drops half the bodies.

### `unmmp_lib/recover_static.py` (new)

`class StaticRecovery(Recovery)` — binds from the on-disk method table instead
of `JNI_OnLoad`:

```python
StaticRecovery(nm, vm, dexes, regids,
               row_table=0x346DF8,      # 12 B rows: {u32 first; u32 name_idx; u32 count}
               method_table=0x35DEF0)   # 16 B entries: {u32 name_idx; u32 sig_idx; u64 fn_ptr}
```

`fn_ptr` is read through `reloc_ptrs()` — the table lives in `.data.rel.ro` and
is all zeros on disk.

### `unmmp_lib/decoder.py`

`DEFAULT_WIDTHS` — a module-level `{opcode: code_units}` table. An opcode with
no known name but a known width is emitted as `UNKNOWN` and stepping continues,
instead of abandoning the whole method. On one sample this took the parse rate
from 116 to 569 methods.

### `unmmp_lib/lifter.py`

Reads `th['units']` (captured from emulator memory) in preference to the ELF
file image. Decrypt stubs write plaintext into the emulator's memory, so the
file still holds ciphertext and the lifter would otherwise decode noise.

### `unmmp_lib/semantic.py`

- `structural_name()` only reports `invoke-*` when a real JNI call event was
  observed — method *resolution* alone does not imply invocation.
- `effect_matches()` rejects traces containing `jni`/`call`/`throw` rather than
  any event at all.
- **`UNMMP_ALLOW_PARTIAL=1`** — log unresolved opcodes and continue instead of
  raising at the end of derivation.

### `unmmp_lib/dex.py`

Bounds guard in `referenced_interfaces()` — patched dex files carry interface
indices past the method table.

## Scripts

| script | what it does |
|---|---|
| `restore_static.py` | driver: static bind → capture → derive/lift → rebuild dex |
| `probe_ops.py` | run `InstructionProbe` without `extract()` |
| `derive_sem.py` | run `derive_semantic` without `extract()` |
| `trace_body.py` | replay a body, log the instruction-pointer register (`x22`) to recover per-opcode widths |
| `harvest_widths.py` | batch the above over captured bodies, vote per opcode |
| `measure_widths.py` | report how many methods parse with/without `DEFAULT_WIDTHS` |
| `classify_ops.py` | per-opcode: advance, resolver hits, register reads, delta |
| `match_ops.py` | nearest known opcode by handler code distance |
| `op_width.py` | extract a handler's own instruction-pointer advance from its body |
| `resolve_handlers.py` | follow handler thunks to the real bodies (`slots` / `distinct bodies`) |
| `check_dup.py` | group mapped opcodes by handler, separating family aliases from real mislabels |
| `resolve_names.py` | decode the method table's name/signature indices into a JSON map |
| `dump_strpool.py` | run `.init_array`, then dump the decrypted string pool |

## Running it

```bash
export UNMMP_VM_ENTRY=0x3150c8        # interpreter entry (from static analysis)
export UNMMP_HANDLER_TABLE=0x364540   # dispatch table (from static analysis)
export UNMMP_ALLOW_PARTIAL=1
export UNMMP_JNI_LENIENT=1
export UNMMP_CAPTURE_TOLERANT=1

python restore_static.py <in_dir> -o <out_dir> \
    --regid regid_map.tsv --mapping opcode_semantic.json
```

`<in_dir>` holds the `.so` copied to `lib/nmmp.so` and `lib/nmmvm.so` plus the
dex files. Outputs: `opcode_mapping.json`, `opcode_aliases.json`,
`native_methods.json`, `lifted_bodies.json`, `raw_bodies.json`,
`decode_failures.json`, `recovery_summary.json`, and `classes*_restored.dex`
when enough methods lift cleanly.

Derive the mapping **in a clean run first** (without `UNMMP_JNI_LENIENT`) and
pass it back with `--mapping`; deriving under the lenient flag drops the map
from 180 to 33 opcodes.

## Known limits

- **Opcode numbering is per-build.** `RandomInstructionRewriter` permutes it at
  build time with an unseeded `Random()`. A mapping recovered from one APK does
  not transfer to the next build of the same app.
- **An unknown opcode with unknown width ends the method.** Nothing here can
  guess a width; use `harvest_widths.py` to measure it from a real execution.
- **Semantic derivation only sees handlers that actually run.** Opcodes that
  never execute in the captured corpus stay unnamed. Check
  `decode_failures.json` — the distribution tells you which two or three
  opcodes to chase.
- **Shape matching against a reference build is not a substitute.** When the two
  builds use different compilers the top-1 rate drops to ~23%; use
  `attack/tools/elf-inspect/so_handler_diff.py` for ranking, not naming.
