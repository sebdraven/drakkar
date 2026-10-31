# Drakkar documentation

Static analysis of Android APKs for detecting ATT&CK behaviours, with a focus
on stalkerware.

## Index

- [`architecture.md`](architecture.md) — overview of the pipeline: APK parsing
  → call graph → rule engine → output.
- [`intimacy.md`](intimacy.md) — the `intimacy` feature: coupling detection
  (crypto↔network, collection↔exfiltration) by call-graph intimacy, adapted
  from IntDroid. Formula, safeguards, effective diameter, empirical results.
- [`calibration.md`](calibration.md) — protocol for calibrating the
  `min-score` threshold: building the corpus, Mann-Whitney test, choosing and
  validating the threshold per label.

The command-line modes, their output and the bundle format are described in the
[top-level README](../README.md); each mode's own legend
(`drakkar --<mode> --legend`) defines every label and field it emits.

## In short

Drakkar takes an APK, extracts its features (DEX, manifest, native symbols),
builds an inter-procedural call graph, then evaluates a rule catalogue derived
from MITRE ATT&CK Mobile. Every detection is justified by traceable
**evidence** — declared permission, resolved API with its reachability path
from a manifest entry point, string, intimacy score, and so on.

The rule catalogue is regenerated automatically when the catalogue code
changes (hash-based invalidation, see `architecture.md` § Cache).
