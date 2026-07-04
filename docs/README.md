# Documentation Drakkar

Analyse statique d'APK Android pour la détection de comportements ATT&CK, avec
un accent sur le stalkerware.

## Index

- [`architecture.md`](architecture.md) — vue d'ensemble du pipeline : parsing
  APK → call graph → moteur de règles → sortie.
- [`intimacy.md`](intimacy.md) — la feature `intimacy` : détection de couplage
  (crypto↔réseau, collecte↔exfiltration) par intimité de call graph, adaptée
  d'IntDroid. Formule, garde-fous, diamètre effectif, résultats empiriques.
- [`calibration.md`](calibration.md) — protocole de calibration du seuil
  `min-score` : constitution du corpus, test de Mann-Whitney, choix et validation
  du seuil par label.

## En bref

Drakkar prend un APK, en extrait les features (DEX, manifest, symboles natifs),
construit un call graph inter-procédural, puis évalue un catalogue de règles
dérivé de MITRE ATT&CK Mobile. Chaque détection est justifiée par des **preuves**
(`evidence`) traçables — permission déclarée, API résolue avec son chemin
d'atteignabilité depuis un entrypoint manifest, string, score d'intimité, etc.

Le catalogue de règles est régénéré automatiquement quand le code du catalogue
change (invalidation par hash, cf. `architecture.md` § Cache).
