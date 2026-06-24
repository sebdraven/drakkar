# Drakkar

Static MITRE ATT&CK for Mobile detection on Android APKs.

Pipeline : **LIEF** (DEX / ELF / manifest) → **CFG inter-procédural** →
**matching MITRE** (DSL composable style capa) → export **NetworkX**
(pour APKolgomorov) + confirmation dynamique optionnelle via **Kharon**.

## Build

```sh
cargo build                          # backend stub (instantané, sans LIEF)
cargo build --features lief-backend  # backend LIEF (C++/CMake, build lourd)
```

## Run

```sh
drakkar app.apk --rules rules/mitre \
  --export-graph cfg.json \
  --kharon kharon_summary.json
```

## Architecture

| Module        | Rôle                                             |
|---------------|--------------------------------------------------|
| `parser/dex`  | DEX → methods + call edges (LIEF Android)         |
| `parser/elf`  | `.so` → symboles natifs (LIEF ELF)                |
| `parser/manifest` | permissions / intent / services (LIEF axml)   |
| `cfg`         | call graph inter-proc (petgraph) + reachability   |
| `rules`       | DSL `and/or/not/count/sequence/api/...` + moteur  |
| `export`      | node-link JSON compatible `networkx`              |
| `kharon`      | confirmation DSE des candidats statiques          |

## Statut

Scaffold : pipeline end-to-end compile et tourne en mode stub.
Reste à câbler : extraction réelle LIEF (`TODO(lief)` dans `parser/*`).

Licence : AGPL-3.0-or-later.
