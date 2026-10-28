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

## Hooks git

```sh
git config core.hooksPath .githooks
```

Les deux hooks lancent les mêmes commandes que la CI (`.github/workflows/ci.yml`) :
`cargo fmt --all --check`, puis `cargo clippy --locked --all-targets -- -D warnings`.

- `pre-commit` bloque un commit mal formaté ou qui déclenche un avertissement clippy.
- `pre-push` refait les mêmes vérifications avant de pousser. Il couvre les commits
  créés par un rebase ou par un outil, qui ne passent pas par `pre-commit`.

Aucun hook ne reformate. En cas d'échec de fmt, lancer `cargo fmt --all`, puis
recommiter.

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

### Désassemblage de la frontière JNI (`--native-disasm`)

```sh
drakkar app.apk --native --native-disasm                       # texte, sans les instructions
drakkar app.apk --native --native-disasm --disasm-full         # texte, avec les instructions
drakkar app.apk --native --native-disasm --disasm-depth 0 \
  --disasm-max-insns 2000 --format json --json-out reports/app.native.json
```

Désassemble statiquement, dans chaque ELF (AArch64, ARM, Thumb-2, x86,
x86_64), les fonctions qui portent la frontière Java↔natif : celles des lignes
de liaison et les exports `Java_*`, les entrées de tables `JNINativeMethod`,
`JNI_OnLoad` / `JNI_OnUnload`, `DT_INIT`, `DT_INIT_ARRAY`, `e_entry` d'un
exécutable, puis les fonctions internes qu'elles appellent jusqu'à
`--disasm-depth` (défaut 1). Pour chaque fonction : instructions, appels
(internes, imports par PLT ou GOT, indirects), chaînes référencées, appels par
la table de `JNIEnv` (`FindClass`, `GetMethodID`, `RegisterNatives`…, avec
classe, nom et signature quand les chaînes sont dans la fonction) et appels
système. Par ELF : les upcalls vers Java, les méthodes enregistrées par
`RegisterNatives` (qui lèvent, quand c'est possible, l'ambiguïté d'une ligne
`registered_ambiguous`) et les imports appelés par catégorie.
`drakkar --native --legend` définit chaque champ.

Une fonction s'arrête où ses chemins s'arrêtent : retour, saut, tail-call, ou
appel direct à une fonction sans retour (`__stack_chk_fail`, `abort`,
`__cxa_throw`… liste dans la légende) ; le code qui suit n'est jamais lu en
séquence. Les stubs PLT AArch64, ARM et x86 sont reconnus, l'import nommé par
la relocation `JUMP_SLOT`. Une instruction que le décodeur refuse, ou sur
laquelle il panique, n'abandonne que son chemin : elle va dans `invalid_paths`
(adresse, octets, raison, branchement qui y mène) et les autres chemins sont
parcourus ; la fonction reste `ok`. C'est la trace typique d'un code aplati
(OLLVM) : prédicats opaques menant à des octets poubelle. Quand au moins trois
fonctions d'un ELF butent sur les mêmes octets, l'anomalie `opaque_dead_code`
le signale. `truncated` ne marque plus qu'un plafond atteint
(`--disasm-max-insns`), `truncated_at` donnant alors la première instruction
non lue. Les instructions VFP et Advanced SIMD (ARM, Thumb-2), que yaxpeax-arm
ne décode pas, sont sautées à leur longueur sous le mnémonique `coproc`.

Ce qu'il ne fait pas :

- aucune exécution, aucune émulation, aucune exécution symbolique ;
- l'env n'est pas suivi d'une fonction à l'autre au-delà du premier argument
  d'un callee, ni au-delà de `--disasm-depth` ;
- un appel par la table de `JNIEnv` dont le registre n'est pas suivi sort avec
  `resolved = false` : la même forme est celle d'un appel virtuel C++ ;
- les chaînes construites ou déchiffrées à l'exécution sont invisibles ;
- le code natif absent de l'APK (téléchargé, déchiffré au chargement) est
  invisible.

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
