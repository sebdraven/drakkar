# Architecture

Overview of the Drakkar pipeline, from the APK file to the JSON output.

```
APK
 │
 ├─ parser::dex       → methods, call edges, strings
 ├─ parser::manifest  → package, permissions, services, intent actions, components
 └─ parser (native)   → symbols of the .so files
        │
        ▼
   model::ApkFeatures        +        cfg::CallGraph
   (flat features)                    (inter-procedural graph, petgraph)
        │                                   │
        └───────────────┬───────────────────┘
                        ▼
              rules::Engine::run
        (manifest entry points → rule evaluation → reachability enrichment)
                        │
                        ▼
                 Vec<rules::Match>  → JSON
```

This is the default pipeline, the one behind the ATT&CK detections. The other
modes (inventories, diffs, bundle, native analysis) reuse the same parsers but
stop before the rule engine, or never reach it; the top-level
[README](../README.md) lists them.

---

## Parsing (`src/parser/`)

- **`dex.rs`**: extracts every DEX of the APK (crates `dex-parser` and
  `dex-bytecode`), and produces the methods and the call edges of the call
  graph, as well as the strings. Unreadable classes (invalid string id,
  malformed CESU-8) are skipped with a `WARN` rather than aborting the
  analysis.
- **`manifest.rs`**: decodes the binary manifest (AXML) → package,
  permissions, services (including the `accessibility` marker), intent
  actions, declared components.
- **`axml.rs`**: AXML decoder. The nominal path is `axmldecoder`, with a
  tolerant fallback when it refuses the manifest or panics — chunk of unknown
  type skipped, bounded string pool, unclosed elements reattached. Same pattern
  as `apkzip` for the ZIP: the fallback never activates on a sound APK.
  `--manifest` reports produced by the fallback say so in `anomalies`.
- **`assets.rs`**: inventory (`--list-assets`) and export (`--extract-assets`)
  of the `assets/` entries — declared and real size, declared compression
  method, full SHA-256, type sniffed from the leading bytes, Shannon entropy.
  Same fallback as elsewhere: the `apkzip` reader when the `zip` crate refuses
  the archive, without which tampered APKs would come out with an empty
  `assets/`. Produces a set fingerprint (SHA-256 of the sorted list of
  `path\tsha256`) that serves as a grouping axis, absent — not empty — when the
  APK has no asset. No recursive unpacking: an asset that is itself a ZIP, an
  APK or a DEX is typed and written as is. The `sha256` covers the
  **decompressed** content — the only form that can be queried on
  VT/MalwareBazaar/Koodous, and the only stable form when the tolerant reader
  tries deflate then stored. Filtering by a set of known hashes
  (`--assets-hash*`), with no effect on the fingerprint.
- The symbols of native libraries (`.so`) are extracted for the
  `native-symbol` rules. The static analysis of native code (`--native`,
  `--native-disasm`) lives in `elf.rs` and `native_static/`, and is described
  by `drakkar --native --legend`.

## Model (`src/model`)

`ApkFeatures` gathers the "flat" features (methods, strings, permissions,
intent actions, native symbols, services, components). `MethodRef` carries two
views of a method:

- `signature()` — full signature (class → name + descriptor), for display and
  paths;
- `api()` — `class->name` key **without descriptor**, used as the node key of
  the call graph and for substring matching of rules.

> Choosing `api()` as the node key is deliberate: the descriptor differs
> between the caller's view (exact) and the callee's view (shorty), which would
> fragment the graph if `signature()` were used.

## Call graph (`src/cfg/mod.rs`)

`CallGraph` wraps a `petgraph::DiGraph`. Main primitives:

- **`entrypoints(components)`**: nodes matching the components declared in the
  manifest (activities, services, receivers…) — the root of any *validated*
  reachability.
- **`reachability(api, entrypoints)`**: is an API reachable from a manifest
  entry point, and through which paths.
- **`reaches(a, b)`** / **`reaches_both(a, b, …)`**: simple reachability /
  co-reachability from a common pivot.
- **`intimacy(first, second, …)`**: coupling score between two groups of
  primitives (see [`intimacy.md`](intimacy.md)).
- Support: `reverse_bfs_dist` (reverse multi-source BFS), `bfs_path`,
  `wcc_labels` (weakly connected components, union-find),
  `effective_diameter_directed` (directed effective diameter),
  `is_allowlisted_pkg` (allowlist `BENIGN_SDK_PREFIXES` of benign SDKs).

The analysis is **flow- and context-insensitive**: a deliberate trade-off for
scalability (IntDroid makes the same choice), at the cost of following neither
reflection nor dynamic loading.

## Rule engine (`src/rules/`)

### DSL (`schema.rs`)

A rule has a `meta` block (id, name, tactic, detectability, references…) and a
`features` block: a composable expression, deserialised by hand from YAML with
single-key maps. Variants of `Feature`:

- combinators: `and`, `or`, `not`, `count { feature, min }`, `sequence`;
- atoms: `api`, `string`, `permission`, `intent-action`, `native-symbol`,
  `service`, `accessibility-service`;
- coupling: `co-reachable` (boolean), `intimacy` (score);
- `unsupported`: explicit marker of a technique outside the scope of static
  analysis (always false) — it documents what is out of scope instead of
  leaving a gap.

### Catalogue (`catalog.rs`)

`detection_for(id)` returns the embedded YAML `features` block for a given
ATT&CK technique, or `None` (→ the technique is marked `out-of-scope`). This is
the core of the domain logic: Drakkar's own detection logic.

### Cache (`fetch.rs`)

On first run, `ensure_cache` downloads the STIX 2.1 bundle of MITRE ATT&CK
Mobile, extracts the active Android techniques, merges them with the catalogue
(`detection_for`), and writes one YAML per technique into the user cache
directory (`~/Library/Caches/drakkar/rules/` on macOS,
`~/.cache/drakkar/rules/` on Linux).

**Hash-based invalidation.** The source of `catalog.rs` is hashed at compile
time (`include_str!` + FNV-1a) and stored in `.catalog_hash`. On every run, if
the embedded hash differs from the stored one, the cache is **regenerated
automatically** — no manual purge is needed after a rule change. The raw STIX
bundle is cached separately (`mobile-attack.json`): a catalogue change
regenerates the YAML without downloading again, and works offline once the
STIX has been fetched.

The STIX bundle is downloaded from MITRE's repository without a version pin,
so it follows their latest release: two caches downloaded at different times
may differ. In a bundle, `rules_hash` records the exact rule set and catalogue
used (`drakkar --bundle --legend`).

### Evaluation (`mod.rs`)

`Engine::run(features, cg)`:

1. computes once the entry points validated by the manifest;
2. for each rule, `eval`s the `features` expression and collects the evidence
   of the true branches only;
3. deduplicates the evidence, then **enriches** the evidence of kind `api`
   with its reachability and its paths from an entry point;
4. emits one `Match` (id, name, tactic, evidence) per satisfied rule.

Each `Evidence` carries its `kind`, the observed `value`, and depending on the
case `reachable`, `score` (intimacy) and `paths`.

## Execution modes

- **Single** (`main.rs`): one APK → one JSON on standard output.
- **Bulk** (`bulk.rs`): a directory of APKs, processed in parallel (`rayon`),
  one JSON per APK. The `Engine` (hence the rule cache) is loaded once; each
  APK is isolated (`catch_unwind`) so that a parsing failure does not stop the
  batch. Useful for building the score distributions needed for calibration
  (see [`intimacy.md`](intimacy.md) § 9).

## Design choices, in short

- **Traceability first**: every detection comes with its evidence and, for
  APIs, the reachability path — no black-box verdict.
- **Reachability validated by the manifest**: only entry points actually
  declared are used as roots, which rules out dead code and the false
  positives of mere presence.
- **Substring matching on `api()`**: simple and robust to parameter order, but
  sensitive to the obfuscation of bundled libraries — hence the choice, for
  network sinks, of targeting system APIs that cannot be obfuscated (see
  [`intimacy.md`](intimacy.md) § 6).
- **Catalogue versioned by hash**: iterating on the rules requires no cache
  maintenance.
