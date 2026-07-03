# Architecture

Vue d'ensemble du pipeline Drakkar, du fichier APK à la sortie JSON.

```
APK
 │
 ├─ parser::dex       → méthodes, arêtes d'appel, strings
 ├─ parser::manifest  → package, permissions, services, intent-actions, composants
 └─ parser (natif)    → symboles des .so
        │
        ▼
   model::ApkFeatures        +        cfg::CallGraph
   (features plates)                  (graphe inter-procédural, petgraph)
        │                                   │
        └───────────────┬───────────────────┘
                        ▼
              rules::Engine::run
        (entrypoints manifest → eval des règles → enrichissement reachability)
                        │
                        ▼
                 Vec<rules::Match>  → JSON
```

---

## Parsing (`src/parser/`)

- **`dex.rs`** : extrait chaque DEX de l'APK (crates `dex` + `dex-bytecode`),
  produit les méthodes et les arêtes d'appel du call graph, ainsi que les
  strings. Les classes illisibles (id de string invalide, CESU-8 malformé) sont
  ignorées avec un `WARN` plutôt que d'interrompre l'analyse.
- **`manifest.rs`** : décode le manifest binaire (AXML) → package, permissions,
  services (dont le marqueur `accessibility`), intent-actions, composants
  déclarés.
- Les symboles des bibliothèques natives (`.so`) sont extraits pour les règles
  `native-symbol`.

## Modèle (`src/model`)

`ApkFeatures` agrège les features « plates » (méthodes, strings, permissions,
intent-actions, symboles natifs, services, composants). `MethodRef` porte deux
vues d'une méthode :

- `signature()` — signature complète (classe → nom + descripteur), pour
  l'affichage et les chemins ;
- `api()` — clé `classe->nom` **sans descripteur**, utilisée comme clé de nœud
  du call graph et pour le matching des règles par sous-chaîne.

> Le choix de `api()` comme clé de nœud est délibéré : le descripteur diverge
> entre la vue appelant (exacte) et la vue appelé (shorty), ce qui fragmenterait
> le graphe si l'on utilisait `signature()`.

## Call graph (`src/cfg/mod.rs`)

`CallGraph` enveloppe un `petgraph::DiGraph`. Primitives principales :

- **`entrypoints(components)`** : nœuds correspondant aux composants déclarés au
  manifest (activities, services, receivers…) — la racine de toute reachability
  *validée*.
- **`reachability(api, entrypoints)`** : une API est-elle atteignable depuis un
  entrypoint manifest, et par quels chemins.
- **`reaches(a, b)`** / **`reaches_both(a, b, …)`** : atteignabilité simple /
  co-atteignabilité depuis un pivot commun.
- **`intimacy(first, second, …)`** : score de couplage entre deux groupes de
  primitives (voir [`intimacy.md`](intimacy.md)).
- Support : `reverse_bfs_dist` (BFS multi-source inversé), `bfs_path`,
  `wcc_labels` (composantes faiblement connexes, union-find),
  `effective_diameter_directed` (diamètre effectif dirigé), `is_allowlisted_pkg`
  (allowlist `BENIGN_SDK_PREFIXES` des SDK bénins).

L'analyse est **flow- et context-insensitive** : un compromis assumé pour la
scalabilité (cf. IntDroid, même choix), au prix de ne pas suivre la réflexion ni
le chargement dynamique.

## Moteur de règles (`src/rules/`)

### DSL (`schema.rs`)

Une règle a un bloc `meta` (id, name, tactic, detectability, references…) et un
bloc `features` : une expression composable, désérialisée à la main depuis un
YAML à maps à clé unique. Variantes de `Feature` :

- combinateurs : `and`, `or`, `not`, `count { feature, min }`, `sequence` ;
- atomes : `api`, `string`, `permission`, `intent-action`, `native-symbol`,
  `service`, `accessibility-service` ;
- couplage : `co-reachable` (booléen), `intimacy` (score) ;
- `unsupported` : marqueur explicite d'une technique hors périmètre de l'analyse
  statique (toujours faux) — documente l'out-of-scope au lieu de laisser un trou.

### Catalogue (`catalog.rs`)

`detection_for(id)` renvoie le bloc `features` YAML embarqué pour une technique
ATT&CK donnée, ou `None` (→ la technique est marquée `out-of-scope`). C'est le
cœur métier : la logique de détection propre à Drakkar.

### Cache (`fetch.rs`)

Au premier lancement, `ensure_cache` télécharge le bundle STIX 2.1 de MITRE
ATT&CK Mobile, en extrait les techniques Android actives, les fusionne avec le
catalogue (`detection_for`), et écrit un YAML par technique dans
`~/…/Caches/drakkar/rules/`.

**Invalidation par hash.** Le source de `catalog.rs` est haché à la compilation
(`include_str!` + FNV-1a) et stocké dans `.catalog_hash`. À chaque lancement, si
le hash embarqué diffère du hash stocké, le cache est **régénéré
automatiquement** — plus besoin de purge manuelle après un changement de règles.
Le bundle STIX brut est mis en cache séparément (`mobile-attack.json`) : un
changement de catalogue régénère les YAML sans retélécharger, et fonctionne
hors-ligne une fois le STIX récupéré.

### Évaluation (`mod.rs`)

`Engine::run(features, cg)` :

1. calcule une fois les entrypoints validés par le manifest ;
2. pour chaque règle, `eval` l'expression `features` et collecte les preuves des
   seules branches vraies ;
3. dédoublonne les preuves, puis **enrichit** les preuves de type `api` avec leur
   atteignabilité et leurs chemins depuis un entrypoint ;
4. émet un `Match` (id, name, tactic, evidence) par règle satisfaite.

Chaque `Evidence` porte son `kind`, la `value` observée, et selon le cas
`reachable`, `score` (intimité) et `paths`.

## Modes d'exécution

- **Single** (`main.rs`) : un APK → un JSON sur la sortie standard.
- **Bulk** (`bulk.rs`) : un répertoire d'APK, parcouru en parallèle (`rayon`),
  un JSON par APK. L'`Engine` (donc le cache de règles) est chargé une seule
  fois ; chaque APK est isolé (`catch_unwind`) pour qu'un échec de parsing
  n'interrompe pas le lot. Utile pour constituer les distributions de scores
  nécessaires à la calibration (cf. [`intimacy.md`](intimacy.md) § 9).

## Choix de conception, en résumé

- **Traçabilité d'abord** : toute détection s'accompagne de ses preuves et, pour
  les API, du chemin d'atteignabilité — pas de verdict boîte noire.
- **Reachability validée par le manifest** : on ne part que d'entrypoints
  réellement déclarés, ce qui écarte le code mort et les faux positifs de simple
  présence.
- **Matching par sous-chaîne d'`api()`** : simple et robuste à l'ordre des
  paramètres, mais sensible à l'obfuscation des bibliothèques bundlées — d'où le
  choix, pour les sinks réseau, de cibler des API système non-obfuscables (voir
  [`intimacy.md`](intimacy.md) § 6).
- **Catalogue versionné par hash** : l'itération sur les règles ne demande aucun
  entretien de cache.
