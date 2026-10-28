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

## Analyse native statique (`--native`)

```sh
drakkar app.apk --native                         # texte
drakkar app.apk --native --format json           # JSON sur stdout
drakkar app.apk --native --format both --json-out reports/app.native.json
drakkar --native --legend                        # définition de chaque champ
```

Inventorie **tous** les ELF de l'APK, reconnus à leurs octets (`\x7FELF`) et
non à leur chemin : `lib/`, mais aussi `assets/`, `res/raw/` ou la racine. Pour
chacun : SHA-256 du contenu décompressé, architecture, sections (avec
entropie), segments, `DT_NEEDED`, imports classés par catégorie, chaînes
classées, exports `Java_*` démanglés, et tables `JNINativeMethod` reconstruites
à travers les relocations relatives (RELA, REL, RELR). Relie ensuite chaque
méthode `native` du DEX à son export ou à son entrée de table, et signale les
fonctions natives sans méthode Java. Mode single, comme `--native-arch`.

Ce qu'il ne fait pas :

- aucun désassemblage, aucune exécution, aucune émulation ;
- une table `JNINativeMethod` dont les noms ou signatures sont chiffrés, ou
  construits à l'exécution, n'est pas retrouvée : le statut est alors
  `unresolved`, rien n'est inventé ;
- les relocations packées Android (APS2) ne sont pas décodées, elles sont
  signalées en anomalie ;
- seuls les ELF de `lib/` sont liés au DEX ; les autres sont inventoriés.

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
