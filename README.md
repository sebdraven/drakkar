# Drakkar

Static analysis of Android applications, built for stalkerware and mobile
malware research.

Drakkar reads an APK, or a raw DEX, and answers one question per mode: which
MITRE ATT&CK for Mobile behaviours it implements, whether they are reachable,
who signed it, when it was built, what its native code does at the JNI
boundary, how close it is to another sample. Every mode prints its own legend:
`drakkar --<mode> --legend` defines each label and each field it emits, and
states the limits of each metric.

Nothing is executed. Samples are parsed, never run, never emulated.

## Install

Each release ships one bare executable per target, with nothing to unpack:

| Target | Asset |
|---|---|
| macOS arm64 | `drakkar-vX.Y.Z-aarch64-apple-darwin` |
| macOS x86_64 | `drakkar-vX.Y.Z-x86_64-apple-darwin` |
| Linux x86_64 | `drakkar-vX.Y.Z-x86_64-unknown-linux-gnu` |
| Linux arm64 | `drakkar-vX.Y.Z-aarch64-unknown-linux-gnu` |
| Windows x86_64 | `drakkar-vX.Y.Z-x86_64-pc-windows-msvc.exe` |
| Windows arm64 | `drakkar-vX.Y.Z-aarch64-pc-windows-msvc.exe` |

Each binary comes with a `BUILD-INFO.txt`, and `SHA256SUMS` holds the full
SHA-256 of every asset:

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS   # macOS
sha256sum -c --ignore-missing SHA256SUMS       # Linux
```

From source:

```sh
cargo build --release
```

The optional `lief-backend` feature (`cargo build --features lief-backend`)
pulls LIEF, a C++ build. Release binaries are built without it.

## Inputs

- **APK or raw DEX, recognised by content, never by extension** (`PK\x03\x04`,
  `dex\n`). Most modes take either, which is how the DEX recovered from a
  packed sample is analysed.
- **Single or bulk.** One sample as the positional argument, or `--bulk DIR`
  (with `--recursive`) for the modes that support it; bulk output goes to
  `--out` (default `./reports`, `-` for stdout), one file per sample.
- **Tampered archives.** When the `zip` crate refuses an APK (patched
  general-purpose flags, non-standard compression methods, false sizes), a
  tolerant reader takes over (`src/parser/apkzip.rs`). It never activates on a
  well-formed archive. Each module that opens the APK on its own wires that
  fallback at open, entry lookup and read — `parser::dart_snapshot` included.

## Modes

### Detection

| Flag | What it answers |
|---|---|
| *(default)* | MITRE ATT&CK for Mobile detections, each with its evidence (declared permission, resolved API with its path from a manifest entry point, string, intimacy score). `--export-graph FILE` writes the call graph as NetworkX node-link JSON. |
| `--capabilities [PATTERN…]` | invoke, `const-string` and `sget` sites matching capability patterns (accessibility, SMS, overlay, execution, DEX loading…). A site found is not proof of reachability. |
| `--probe API` | is this API a node of the graph, and is it reachable from the roots — with the paths. |
| `--orphan-audit` | methods unreachable from the entry points, grouped in weakly connected components, over four root stages (manifest, dynamic, UI handlers, `<clinit>`). |
| `--dyn-entrypoints` | components reached other than by a manifest declaration: `registerReceiver`, `startActivity`, `new Intent(ctx, X.class)`, `Class.forName`… |
| `--reflection-inputs` | where the name of each reflection target comes from (constant, decryptable constant, runtime, parameter…). |

### Inventory

| Flag | What it answers |
|---|---|
| `--manifest` | permissions, components, intent filters, derived entry points. |
| `--cert` | signature schemes v1/v2/v3/v3.1 and the X.509 certificates, with full fingerprints. |
| `--dating` | raw dating indicators: signing dates, build-chain floors (DEX format, schemes, compileSdk, library versions), archive timestamps, date literals in code, API targets. No date is ever estimated. |
| `--strings [PATTERN…]` | the DEX string pool, whole or filtered (case-insensitive). |
| `--api-surface` | the protocol declared by annotations: Retrofit verbs and routes, `@Path` / `@Query` names, Gson `@SerializedName` keys. An empty output means "not Retrofit", not "no route". |
| `--resource NAME`, `--resource-id ID`, `--resources [TYPE…]` | resolve or dump `resources.arsc`. |
| `--resource-xref`, `--resource-orphans` | join DEX constants to real resource entries; list resources no code constant references ("orphan" means unreferenced from code, not unused). |
| `--list-entries` | every entry path of the archive; nothing extracted. |
| `--list-assets`, `--extract-assets DIR`, `--assets-fingerprint` | the `assets/` entries: sizes, declared method, full SHA-256 of the decompressed content, sniffed type, entropy; a set fingerprint emitted only when it covers every asset. Filters: `--assets-include`, `--assets-max-size`, `--assets-hash[-file]`, `--assets-hash-exclude[-file]`. |
| `--extract-entry PATTERN…` | extract matching entries only (exact path, glob or substring) — the archive is never unpacked whole. |
| `--extract-libs` | every native ELF, including the ones outside `lib/` (packer stubs under `assets/`). |

### Code

| Flag | What it answers |
|---|---|
| `--disasm [PATTERN…]` | selected classes disassembled, indexed operands resolved (strings, types, methods, fields). Not a decompiler. |
| `--decompile [PATTERN…]` | selected classes decompiled to Java by [dex-decompiler](https://github.com/sebdraven/dex-decompiler). |
| `--bundle OUT` | everything Drakkar extracts from one sample, every class disassembled and decompiled, under `OUT/<sha256>/`. See below. |

### Comparison

| Flag | What it answers |
|---|---|
| `--diff-dex A B` | same source tree? Per-method opcode fingerprints, robust to package renaming and ProGuard, blind to operands by design. |
| `--diff-explain A B` | what actually differs in the resolved operands of matched methods (string, method target, type, real or renamed field). |
| `--diff-strings A B` | what differs in the string pools — where `static final` values, C2 endpoints included, live. |
| `--diff-matrix DIR` | all-against-all similarity over a directory, each sample parsed once, plus single-linkage groups (`--matrix-metric opcodes\|strings`). |
| `--bench-diff A B` | did a new dex-decompiler revision make the Java better or worse? Compares the defect counters of two bundles of the same input; exit code 1 when one gets worse. See Bundle. |

The `--*-normalize FROM=TO` options rewrite descriptors before matching, so two
lots built under different namespaces (`com/duiyun=com/dy`) are compared on
their code rather than on their package names. The similarity thresholds
(`--diff-threshold`, `--matrix-threshold`) are parameters of this tool, not
published empirical values.

### Native code

| Flag | What it answers |
|---|---|
| `--native-arch` | ABI, word size and machine of each `.so`. |
| `--native` | every ELF of the APK, found by content (`lib/`, `assets/`, `res/raw/`, elsewhere): sections with entropy, segments, `DT_NEEDED`, classified imports and strings, demangled `Java_*` exports, `JNINativeMethod` tables rebuilt through relative relocations (RELA, REL, RELR), and the binding of each DEX `native` method to its implementation. A raw ELF can be passed directly, with `--native-dex` for the DEX to bind. |
| `--native --native-disasm` | static disassembly (AArch64, ARM, Thumb-2, x86, x86_64) of the functions at the Java↔native boundary — bound functions, `JNI_OnLoad` / `JNI_OnUnload`, `DT_INIT`, `DT_INIT_ARRAY`, `e_entry` — and of the internal functions they call, up to `--disasm-depth`: `JNIEnv` calls decoded with class, name and signature when the strings are local, PLT/GOT imports called, strings referenced, system calls. |
| `--native --native-symex <elf\|*>@<start>` | symbolic value propagation inside one AArch64 function, path by path, without a solver: for each `--native-symex-watch` instruction, the expression of the address and of the value it reads or writes (of the target and `x0..x3` for a call), with the instructions that produced it. Exploration is directed toward the watches (`--native-symex-undirected` turns this off); conditional selects merge into `ite(c, a, b)` instead of forking. Called functions are skipped by default (`--native-symex-depth 0`) and followed on demand: by hand (`--native-symex-follow`), or when a watch reads memory never written and a skipped call received a pointer into it (`--native-symex-refine`, up to 4 reruns). Constant-length `memcpy` / `memmove` copy bytes, jump tables are enumerated. Distinct memory bases are assumed not to overlap. |
| `--native --native-xrefs <elf\|*>@<addr>[,<addr>…]` | cross-references to up to 64 addresses of an AArch64 ELF, without executing anything: the enclosing function, the direct branches that land exactly on each address, the instructions that form or access it, and the data words that hold it. One pass over the code for all addresses. |
| `--native --native-words <elf\|*>@<addr>:<n>[,<addr>:<n>…]` | 8-byte words read at addresses of an AArch64 ELF, relative relocations applied, without executing anything: what each word designates (code with its enclosing function, data with its section and text, plain integer), and whether a range starts like a Rust vtable header. |
| `--native --native-vtables <elf\|*>` | the Rust method tables (vtables) of an AArch64 ELF, found by their shape in read-only and RELRO data, without executing anything: destructor, size, alignment and methods of each, filtered by function, slot offset, size or start address, and on request the instructions and data words that carry each table's address. |
| `--native-strings [PATTERN…]` | the strings of every ELF (APK, XAPK splits, raw ELF), each with how its bound was found: NUL byte, Rust `{ptr, len}` pair rebuilt through relative relocations, AArch64 immediate length next to the address, or an unsplit heuristic block. `--xrefs`: the instructions that form each address, over the whole code, with the enclosing function from symbols or `.eh_frame`. `--crates`: Rust crates named by source paths, banners of statically linked C libraries. Cryptographic constants recognised by content. JSON streamed to `--json-out`. |

`--native-disasm` follows paths, not bytes: a function stops at a return, a
jump, a tail call or a call to a no-return function, and an instruction the
decoder refuses ends only its own path (recorded in `invalid_paths`). The same
junk bytes hit by several functions are reported as `opaque_dead_code`, the
usual trace of OLLVM flattening. Extra roots: `--native-root`,
`--native-roots exports`; listings: `--native-listing`; heuristic string
index: `--native-string-index`.

`--native-symex-peek=<watch>:<reg>+<offset>:<len>[,…]` reads the symbolic
memory a register points to at a watch, without any instruction of the binary
reading it, e.g. `--native-symex-peek=36ffbd0:x0+0x110:3,36ffbd0:x0+0xf8:3`.
`<watch>` is hexadecimal without prefix and must be one of
`--native-symex-watch`; `<reg>` is `x0`..`x30` or `sp`; `<offset>` is decimal
or `0x` hexadecimal, a `-` sign is accepted; `<len>` is 1 to 64 bytes. On every
path that reaches the watch, before the watched instruction takes effect, each
byte is read as an `ldrb` at that point would read it; the state, the paths,
the budgets and the on-demand refinement are left untouched. Each
`watches[].results[]` entry then carries `peeks`, in option order: `reg`,
`offset` and `len` as requested, `address` (register value plus offset, as
`{text, expr}`), and `bytes` (`len` values `{text, expr}`, one per byte, by
increasing address). Two paths whose peeks differ give two results.

`--native-symex` reports in `fn_start` the start of the function found by
symbol or `.eh_frame`, even when the requested address falls inside it; the
exploration still starts at the requested address, carried by `entry`. With
`bound` = `none`, `fn_start` stays the requested address.

`--native-xrefs=<elf|*>@<addr>[,<addr>…]` answers, for each address, which
function contains it, which instructions branch to it and which instructions
or data words carry it, e.g.
`--native --native-xrefs='lib/arm64-v8a/libapp.so@36ffbd0,0x4a2f10'`.
Addresses are hexadecimal, `0x` optional, 1 to 64 per option (repeatable); a
malformed item is named in the error. `*` takes every AArch64 ELF one of whose
allocated sections contains the address; an ELF named explicitly that is not
AArch64 is an error. Each `xrefs[]` entry, one per (ELF, address), carries
`elf`, `target`, `section`, `function` (`fn_start`, `fn_end`, `bound` =
`symbol`, `eh_frame` or `none`, by the same code as `--native-symex`; absent
when the address is not in executable code), and three lists, each sorted by
address and cut at `--native-xrefs-max` (default 2000) with an exact `total`
and a `truncated` flag:
`code_refs` (`bl`, `b`, `b.cond`, `cbz`, `cbnz`, `tbz`, `tbnz` whose
destination is exactly the address: `insn_addr`, `mnemonic`, `kind` = `call`,
`jump` or `cond_jump`, enclosing `function`); `addr_refs` (`adr`, `adrp` then
`add`, `adrp` then `ldr`/`str`, literal `ldr`, paired as the
`--native-strings --xrefs` scan pairs them, within 8 instructions: `insn_addr`
of the instruction that completes the address, `adrp_addr`, `kind` =
`address`, `load` or `store`, `function`); `data_refs` (8-byte words aligned
on 8 in non-executable sections, RELRO included, equal to the address as
stored in the file or after relative relocation, `R_AARCH64_RELATIVE` and
RELR: `vaddr`, `section`, `relocated`). No reference is not proof of absence:
indirect branches (`br`, `blr`), computed addresses, an `adrp` far from its
`add`/`ldr`/`str`, jump tables, encrypted or generated code escape it;
`code_refs` only counts branches to the exact address, not into the function;
`data_refs` only sees words aligned on 8.
`data_refs` reads program data only: link-time metadata is skipped — sections
of type REL, RELA, RELR (and their Android variants), DYNSYM, STRTAB, HASH,
GNU_HASH, versym/verdef/verneed and DYNAMIC, sections named `.eh_frame` and
`.eh_frame_hdr`, and any word whose file offset lies in a relocation table
declared by `PT_DYNAMIC` (`DT_RELA`, `DT_REL`, `DT_RELR`, `DT_ANDROID_RELR`,
`DT_JMPREL`) — so a relocated reference is no longer listed a second time
through the addend of its own `.rela.dyn` entry.

`--native-words=<elf|*>@<addr>:<n>[,<addr>:<n>…]` reads `n` 8-byte words from
each address and says what each one designates, e.g. the header and the
methods of a Rust vtable in a stripped library:
`--native --native-words='lib/arm64-v8a/libapp.so@4a2f10:6,0x4a3c08:3'`.
Addresses are hexadecimal, `0x` optional, aligned on 8; `n` is decimal, 1 to
512; 1 to 64 ranges per option (repeatable); a malformed item is named in the
error. `*` and an explicit ELF behave as for `--native-xrefs` (the range start
selects the ELF). Each `words[]` entry, one per (ELF, range), carries `elf`,
`start`, `count`, `vtable_like`, `size` and `align` when it applies, and
`items[]`: `index`, `offset` (hex from `start`), `vaddr`, `section`, `raw`
(the word in the file), `value` (after relative relocation, otherwise `raw`),
`relocated`, and `kind`. In a shared library or position-independent
executable (`ET_DYN`), a word that is not relocated is always an integer:
`int`, whatever its value; only a relocated word can be `code` or `data`
there. Otherwise `kind` comes from `value`: `code` (in an executable section,
with `function` = `fn_start`, `fn_end`, `bound` as in `--native-xrefs`, and
`at_start` when `value` is exactly a function start), `data` (in an allocated
non-executable section other than the link-time metadata skipped by
`data_refs`: `target_section`, and `text`, at most 96 bytes cut at
the first NUL, with `text_truncated`, when it is printable), `int` (anything
else), or `none` (word in `.bss` or outside any section: no `raw`, no
`value`). `vtable_like` is true when word 0 is `code` at a function start or
null, word 1 is an `int` below `0x100000` and word 2 an `int` power of two up
to 4096; `size` and `align` are then words 1 and 2. It is a hint, not a proof.
Limits: only relative relocations are applied (`R_AARCH64_ABS64` against a
symbol and packed APS2 relocations are not); in an `ET_EXEC`, `kind` only
looks at the address, so an integer that happens to fall inside a code or data
section is classified `code` or `data`; no Rust string length or table type is
guessed. Addresses and values are `0x` hexadecimal strings in JSON.

`--native-vtables=<elf|*>` lists the Rust method tables of an AArch64 ELF,
stripped or not, to answer three questions: which tables hold a given function
and at which offset, which tables have a method at a given offset, and which
instructions build a given table — e.g. to list the candidate targets of a
`blr` on the word at `+0x38` of a table, or to climb from an async function
back to the one that creates its task. Read-only sections and sections fully
covered by `PT_GNU_RELRO` are scanned on 8-byte aligned words (link-time
metadata excluded, as for `data_refs`); without section headers, read-only
`PT_LOAD` and `PT_GNU_RELRO` segments. An address `T` starts a table when
`T+0x0` is relocated onto a function start or is zero without relocation (no
destructor), `T+0x8` is not relocated and at most `0x1000000` (size),
`T+0x10` is not relocated, a power of two up to 4096 (alignment), and
`T+0x18` is relocated onto a function start. Methods are the consecutive
words from `T+0x18` relocated onto a function start; the table ends at the
first other word or at the start of another detected table. Function starts
come from symbols or `.eh_frame`, and each word is classified by the
`--native-words` code. Filters, optional and combined with AND:
`--native-vtables-fn=<a1>[,<a2>…]` (1 to 64 hex addresses, destructor or
method), `--native-vtables-slot=<offset>` (a method at that offset, `0x` hex
or decimal, multiple of 8, at least `0x18`), `--native-vtables-size=<n>`,
`--native-vtables-at=<a1>[,<a2>…]` (table start); `--native-vtables-max`
caps the tables rendered per ELF (default 500, totals stay exact);
`--native-vtables-refs` adds, in one pass over the code, `addr_refs` and
`data_refs` for each rendered table, by the `--native-xrefs` code and cap.
Examples:
`--native --native-vtables='lib/arm64-v8a/libapp.so' --native-vtables-fn=0x36ffbd0`
(tables that hold this function, with the offsets in `matched`), and
`--native --native-vtables='*' --native-vtables-slot=0x38 --native-vtables-refs`
(tables with a method at `+0x38`, with the instructions and words that carry
them). Each `vtables[]` entry, one per ELF, carries `elf`, `tables_total`
(detected), `tables_matched` (after filters), `truncated`, and `tables[]`
sorted by address: `vaddr`, `section`, `drop` (address or null), `size`,
`align`, `methods_count`, `methods[]` (`offset` from the table start, `value`,
`function` = `fn_start`, `fn_end`, `bound`), `matched[]` with
`--native-vtables-fn` (offsets where a requested address was found, `0x0` for
the destructor), `addr_refs` and `data_refs` with `--native-vtables-refs`. An
AArch64-only mode: a non-AArch64 ELF named explicitly is an error, `*` skips
it. Limits: detection is structural, so a data block that happens to have this
shape is reported and a table without methods is missed; a table's end is not
marked in the binary, so two adjacent tables whose second has no valid
destructor can merge, and a foreign function pointer right after the last
method can be counted; a function in a table does not prove that a given
indirect call targets it — the mode returns candidates; no reference to a
table is no proof either (computed address, distant `adrp`/`add`); only
relative relocations are read.

It does not execute or emulate, and runs symbolically only under
`--native-symex`, without a solver; it does not follow `JNIEnv`
past the first argument of a callee; strings built or decrypted at run time,
and native code absent from the APK, are invisible.

### Flutter (Dart AOT snapshot)

| Flag | What it answers |
|---|---|
| `--dart-snapshot` | for each `lib/<abi>/libapp.so` (or a raw ELF): the four snapshot blobs (`_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`, `_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`) located through `.dynsym`, or by scanning for the snapshot magic when the symbols are gone; the header of each data blob (`version_hash`, `kind`, `features`, `compressed_pointers`), which splits it into a serialized part and a data image; and a **heuristic** enumeration of the `OneByteString` / `TwoByteString` objects of each data image, with a count of rejected candidates per reason. |

Every blob that carries the magic with a coherent header is a data blob
candidate, examined on its own; it is named after its symbol only when a
symbol exists (`heuristic` otherwise). Its header bounds it: the serialized
part is `[magic, magic + length + 4)`, and the data image starts at
`magic + RoundUp(length + 4, 64)` (`kObjectStartAlignment`, Dart SDK 3.5.0).
Only the data image is scanned.

The string enumeration needs the object layout of the snapshot's Dart version,
which changes between SDK releases. It runs only with a layout that has been
**calibrated** on the sample, or found in the known-versions table
(`KNOWN_VERSIONS`, empty for now); otherwise `strings` is null with the reason
(`unsupported_snapshot_version`). It also refuses a symbol-located blob whose
end is not known (`data_blob_size_unknown`), an empty data image
(`data_image_empty`) and any layout that fails validation
(`invalid_heap_layout`).

Calibration infers the layout from strings whose text you already know:

```sh
drakkar app.apk --dart-snapshot --format json \
  --dart-calibrate "<known string 1>" --dart-calibrate "<known string 2>" \
  --dart-calibrate "<known string 3>"
drakkar app.apk --dart-snapshot --dart-calibrate-file witnesses.txt
```

Each witness is first counted over the whole ELF section that carries the
blob, split by zone (`serialized`, `data_image`, `outside`), even when
calibration cannot run: `data_image_verdict` says whether the witnesses are
objects of the data image at all (`witnesses_outside_data_image` when none
is). Inside the data image, Drakkar then looks up to
64 bytes upstream for an object header whose length field matches the
witness, and keeps only the layouts that explain **every** witness. When
`features` says `compressed-pointers` (or `no-compressed-pointers`), the
width of the length field is taken from it instead of being guessed. It needs
three witnesses at least (`insufficient_witnesses`), and refuses to choose
between several surviving layouts (`ambiguous_layout`). A calibrated layout
wins over the table, and a disagreement between them is reported. On success
the report carries a ready-to-paste `KnownVersion { … }` literal; Drakkar
never writes to the table itself. The JSON report carries every accepted
string by default; `--dart-max-rows N` keeps only the first N, as a deliberate
preview (`truncated` then says so, `accepted` stays the real count).

### Enrichment

`--enrich vt,koodous` enriches a list of SHA-256 (a dating CSV, one hash per
line, a directory of `*.dating.json`, or stdin) from VirusTotal and Koodous.
Tokens are read from `VT_API_KEY` and `KOODOUS_TOKEN`, never from arguments.
Raw responses are cached under `--cache`, so a batch resumes where it stopped;
`--rate` sets the requests per minute per service (default 4, the public
VirusTotal quota). AV labels are a starting signal, never the measurement.

## Output

Inventory and native modes print text by default; `--format json` writes JSON
to stdout, or to `--json-out FILE`; `--format both` prints the text and requires
`--json-out`. Modes without JSON print TSV with a header. Coloured output
follows `--color auto|always|never` and `NO_COLOR`.

Failures are never silent: each sample that fails is reported on stderr
(`[FAIL]`, `[PANIC]`), and a part that cannot be read is recorded rather than
omitted.

## Bundle

```sh
drakkar sample.apk --bundle /cases/bundles --archive
```

writes `OUT/<sha256>/`: `bundle.json` (identity, provenance, statistics),
`manifest.json`, `cert.json`, `dating.json`, `rules.json`, `strings.json`
(string pool and static field values, where compile-time constants live),
`dyn_entrypoints.tsv`, `index.json` (one entry per class), `errors.json`, and
per class `classes/<id>.java`, `.class.java`, `.dasm` and `.json`. Files are
named by class id, never by descriptor, so obfuscated classes `La;` and `LA;`
do not overwrite each other on a case-insensitive file system.

`bundle.json` carries:

- `schema_version` — version of the bundle's structure, raised on any
  incompatible change; an added file or field does not raise it;
- `sha256` and `input_size` of the input;
- `drakkar_version` and the full commit of dex-decompiler;
- `rules_hash` — full SHA-256 of the rule set and MITRE catalogue behind
  `rules.json`, null when `rules.json` is null.

`--archive` also writes `OUT/<sha256>.bundle.zip`: the whole directory under
`<sha256>/`, entries sorted, fixed timestamps and permissions, no extra fields
— the same directory content always gives the same bytes. It is the file to
hand to an import service. Two bundles of the same input still differ, through
`generated_at`. `--overwrite` replaces an existing bundle; an existing archive
is replaced with `--archive` and deleted without, so it never outlives the
bundle it was made from.

Every method's Java is read back by tree-sitter-java: `classes/<id>.json`
records its syntax errors and its suspect constructs (`suspect`: literal
receiver, undefined variable, dead code after return, type mismatch, null
compared to a primitive, identifier starting with a digit, empty catch over a
non-empty handler, switch case lost), `index.json` counts the suspect methods
per class, and `fidelity.json` totals them. The detectors are syntactic: they
flag, they do not prove.

```sh
drakkar --bench-diff bundles-rev1/<sha256> bundles-rev2/<sha256> [--format json]
```

compares two bundles of the same input built with two dex-decompiler
revisions: a kind | A | B | delta table, then the methods that gain a defect
(regressions) and those that lose one (corrections). It exits 0 when no
counter gets worse, 1 when a defect counter rises or `methods_clean` drops, 2
on a usage error (different inputs, missing `fidelity.json`).

`drakkar --bundle --legend` defines every file and field, each defect kind
with its known false positives, and `--bench-diff`.

## Rules

The detection catalogue is generated from MITRE ATT&CK for Mobile (STIX) merged
with the detection logic compiled into Drakkar (`src/rules/catalog.rs`), then
cached as one YAML file per technique under the user cache directory
(`~/Library/Caches/drakkar/rules` on macOS, `~/.cache/drakkar/rules` on Linux).

- The first run downloads the STIX bundle from MITRE's repository; later runs
  read the cache. `--refresh` downloads it again.
- The cache is regenerated automatically when `catalog.rs` changes.
- `--rules DIR` uses a rule directory instead of the cache (`rules/mitre/`
  holds examples).

Rules are written in a composable DSL: `and`, `or`, `not`, `count`,
`sequence`, `api`, `string`, `permission`, `intent-action`, `native-symbol`,
`service`, `accessibility-service`, two coupling features over the call graph
— `co-reachable` (boolean) and `intimacy` (a score, for instance between
collection and exfiltration primitives, adapted from IntDroid) — and
`unsupported`, an explicit marker for a technique static analysis cannot
decide, always false, so the gap is documented rather than silent. A matched API carries its reachability: a capability
whose code is present but which no entry point reaches is reported as such.

The STIX bundle follows MITRE's latest release, so two caches downloaded at
different times may differ; `rules_hash` in a bundle records which one was
used.

## Documentation

In French, under [`docs/`](docs/README.md):

- [`architecture.md`](docs/architecture.md) — the pipeline, from APK to report;
- [`intimacy.md`](docs/intimacy.md) — the `intimacy` feature: formula,
  safeguards, effective diameter, empirical results;
- [`calibration.md`](docs/calibration.md) — calibrating `min-score`:
  corpus, Mann-Whitney test, per-label thresholds.

## Development

```sh
git config core.hooksPath .githooks
```

`pre-commit` and `pre-push` run the lint steps of CI: `cargo fmt --all
--check`, then `cargo clippy --locked --all-targets -- -D warnings`. They never
reformat: on a fmt failure, run `cargo fmt --all` and commit again.

CI runs fmt, clippy, tests and builds on Linux; the macOS test leg runs on manual
dispatch only, and tags go through the release workflow, which builds every target.
Releases are cut from a tag `vX.Y.Z`, refused when it disagrees with the
version in `Cargo.toml`; a version bump goes in its own `release/vX.Y.Z` pull
request.

## Related

- [mcp-drakkar](https://github.com/sebdraven/mcp-drakkar) — an MCP server
  exposing each Drakkar mode as a typed tool.

## Acknowledgements

This work is part of the DEFMAL project, funded by the French National
Research Agency (ANR) under France 2030, reference ANR-22-PECY-0007.

## Licence

AGPL-3.0-or-later. See [LICENSE.md](LICENSE.md).
