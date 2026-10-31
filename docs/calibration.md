# Calibrating the intimacy threshold

> **Status.** This document describes the calibration **protocol**. It does not
> yet contain a calibrated threshold or corpus distributions: at this stage only
> two reference APKs are available (§ 8), which is a starting point, not a
> calibration. The figures will be added once bulk mode has been run on a full
> corpus.

The goal: turn the continuous intimacy score (see
[`intimacy.md`](intimacy.md)) into a decision, through a `min-score` threshold
that is **statistically justified** rather than fixed a priori.

---

## 1. Principle

On the two reference samples, the intimacy score separates benign application
coupling (low) from malicious coupling (high). Calibration consists in:

1. measuring the score **distributions** on a benign vs stalkerware corpus;
2. **testing** that the two distributions differ significantly;
3. **choosing** the threshold that optimises an explicit decision criterion;
4. **validating** that threshold on unseen data.

Each intimacy `label` (`crypto-network`, `collection-network`,
`digest-network`…) has its own scale and must be calibrated **separately** — a
score of 3 does not mean the same thing from one label to another.

---

## 2. Building the corpus

The quality of the calibration depends entirely on the corpus. Three
requirements:

- **Reliable labelling.** Confirmed benign apps and stalkerware (known source,
  ideally cross-checked against VirusTotal or a reference repository). Do not
  mix "legitimate parental monitoring" and stalkerware without an explicit
  decision — that is precisely the boundary the thesis discusses.
- **Deduplication.** Public Android datasets contain near-identical duplicates
  that artificially inflate performance; the impact is documented [2].
  Deduplicate by hash **and** by call-graph similarity before any measurement.
- **Family-aware split.** If the same stalkerware family or SDK appears in both
  calibration and test, the threshold overfits that family. Split train/test
  **by family**, not by sample, to estimate generalisation to unseen families.

Aim for a balanced corpus (or rebalance at analysis time) large enough for the
statistical test to have power (order of magnitude: at least a few dozen per
class, ideally more).

---

## 3. Extracting the scores

**Bulk mode** (`src/bulk.rs`) produces one JSON per APK. From it, extract for
each APK and each intimacy `label` the `score` field (normalised score) — and
optionally `score_raw`, `n`, `ad`, `eff` for sensitivity analysis.

An APK with no match on a given label counts as **score 0** for that label
(absence of qualified coupling), not as missing data — absence is information.

Recommended working output: a table
`apk_id, label, score, score_raw, n, ad, eff, class`
(class ∈ {benign, stalkerware}), processed offline (Python/pandas).

---

## 4. Analysing the distributions

Per label:

- **Descriptive**: median, IQR, min/max per class; means are not very
  informative on skewed distributions.
- **Visualisation**: box plots or violins, benign vs stalkerware; overlaid
  histograms on a log scale if the tails are long (the score can reach several
  dozen).
- **Overlap**: identify the range where the two classes overlap — that is
  where the choice of threshold is critical.

---

## 5. Separation test: Mann-Whitney U

We test whether the scores of the two classes come from different
distributions. The test chosen is the **Mann-Whitney U** [3]:

- **non-parametric**: no normality assumption (the scores are skewed,
  long-tailed);
- **robust to unequal sizes** and to ordinal scales;
- H₀: the two distributions are identical; a low p-value indicates a
  significant separation.

Report, in addition to the p-value, an **effect size**: the rank-biserial
correlation, or equivalently the AUC (probability that a randomly drawn
stalkerware has a higher score than a randomly drawn benign app). The AUC
summarises the discriminating power of the label independently of the
threshold.

> Significance (p-value) is not enough: on a large corpus, a tiny separation
> becomes "significant". It is the **effect size / AUC** that says whether the
> label is useful in practice.

---

## 6. Choosing the threshold

From the ROC curve (TPR vs FPR over the whole range of thresholds):

- **Operational constraint (recommended here).** In stalkerware detection, a
  false positive wrongly accuses a benign app: a high cost. First set an
  acceptable **target FPR** (e.g. ≤ 1–5 %), then take the threshold that
  maximises the TPR under that constraint.
- **Youden's J index.** The threshold maximising `TPR − FPR`: a symmetric
  balance, useful as a neutral reference point.
- **Maximising F₁.** If the precision/recall trade-off is preferred.

Document the criterion chosen and the resulting `min-score` threshold, **per
label**. Carry that threshold into the catalogue rules.

---

## 7. Validation

- **Family-aware hold-out or k-fold**: the threshold is set on the calibration
  part, then evaluated on the test part (unseen families).
- **Metrics on the test set**: TPR, FPR, precision, F₁, AUC — never on the data
  used to set the threshold.
- **Error analysis**: inspect the false positives (benign coupling with a high
  score: which SDK, which logic?) and the false negatives (stalkerware with a
  low score: obfuscated sink? coupling outside the defined groups?). These
  cases feed the sink groups (§ 6 of `intimacy.md`) and the allowlist.

---

## 8. Preliminary state (2 APKs — illustrative, not calibrated)

A starting point on the reference samples, for indication **only**:

| class | APK | label | score |
|---|---|---|---|
| benign | Flixoid | collection-network | 1.0 |
| benign | Flixoid | digest-network | 2.0 |
| stalkerware | iKeyMonitor | digest-network | 3.6 |
| stalkerware | iKeyMonitor | crypto-network | 28.2 |
| stalkerware | iKeyMonitor | collection-network | 35.5 |

Separation is clear on strong couplings (≥ 28) and narrow at the bottom (benign
2.0 vs stalkerware 3.6). Two data points allow **neither** setting a threshold
**nor** running a test — they only motivate moving to the corpus.

---

## 9. Reproducibility

- Freeze the binary version (the catalogue hash, see `architecture.md`
  § Cache) and the version of the STIX bundle used for extraction. A bundle
  records both in `rules_hash` (`drakkar --bundle --legend`).
- Freeze the list of corpus APKs (hashes) and the train/test split.
- The effective-diameter computation is deterministic (seeded RNG), so scores
  are reproducible for a given binary.

---

## 10. References

[1] IntDroid — see [`intimacy.md`](intimacy.md), ref. [1]. Reference
benign/malicious validation methodology.

[2] Y. Zhao, L. Li, H. Wang, H. Cai, T. F. Bissyandé, J. Klein, J. Grundy.
"On the Impact of Sample Duplication in Machine-Learning-Based Android Malware
Detection." *ACM Transactions on Software Engineering and Methodology (TOSEM)*,
vol. 30, no. 3, 2021, pp. 1–38.

[3] H. B. Mann, D. R. Whitney. "On a Test of Whether One of Two Random Variables
is Stochastically Larger than the Other." *Annals of Mathematical Statistics*,
vol. 18, no. 1, 1947, pp. 50–60.

> Youden's J index and ROC/AUC metrics are standard statistical tools; a
> bibliographic reference is to be added at the source if cited in the thesis.
