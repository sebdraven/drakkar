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
  well-formed archive.

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

`--native-disasm` follows paths, not bytes: a function stops at a return, a
jump, a tail call or a call to a no-return function, and an instruction the
decoder refuses ends only its own path (recorded in `invalid_paths`). The same
junk bytes hit by several functions are reported as `opaque_dead_code`, the
usual trace of OLLVM flattening. Extra roots: `--native-root`,
`--native-roots exports`; listings: `--native-listing`; heuristic string
index: `--native-string-index`.

It does not execute, emulate or run symbolically; it does not follow `JNIEnv`
past the first argument of a callee; strings built or decrypted at run time,
and native code absent from the APK, are invisible.

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

`drakkar --bundle --legend` defines every file and field.

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
