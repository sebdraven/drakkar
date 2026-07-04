# Calibration du seuil d'intimité

> **État.** Ce document décrit le **protocole** de calibration. Il ne contient
> pas encore de seuil calibré ni de distributions de corpus : à ce stade on ne
> dispose que de deux APK de référence (§ 6), ce qui est une amorce, pas une
> calibration. Les valeurs chiffrées seront ajoutées une fois le mode bulk passé
> sur un corpus complet.

L'objectif : transformer le score d'intimité continu (cf.
[`intimacy.md`](intimacy.md)) en une décision, via un seuil `min-score` **justifié
statistiquement** plutôt que fixé a priori.

---

## 1. Principe

Le score d'intimité sépare, sur les deux échantillons de référence, le couplage
applicatif bénin (bas) du couplage malveillant (haut). La calibration consiste à :

1. mesurer les **distributions** de scores sur un corpus bénin vs stalkerware ;
2. **tester** que les deux distributions diffèrent significativement ;
3. **choisir** le seuil qui optimise un critère de décision explicite ;
4. **valider** ce seuil sur des données non vues.

Chaque `label` d'intimité (`crypto-network`, `collection-network`,
`digest-network`…) a sa propre échelle et doit être calibré **séparément** — un
score de 3 ne signifie pas la même chose d'un label à l'autre.

---

## 2. Constitution du corpus

La qualité de la calibration dépend entièrement du corpus. Trois exigences :

- **Étiquetage fiable.** Bénins et stalkerware confirmés (source connue,
  idéalement recoupée VirusTotal / dépôt de référence). Ne pas mélanger
  « monitoring parental légitime » et stalkerware sans décision explicite —
  c'est précisément la frontière que la thèse discute.
- **Déduplication.** Les datasets Android publics contiennent des doublons quasi
  identiques qui gonflent artificiellement les performances ; l'impact est
  documenté [2]. Dédupliquer par hash **et** par similarité de call graph avant
  toute mesure.
- **Découpage famille-aware.** Si un même famille/SDK stalkerware apparaît à la
  fois en calibration et en test, le seuil sur-apprend cette famille. Séparer
  train/test **par famille**, pas par échantillon, pour estimer la
  généralisation à des familles non vues.

Viser un corpus équilibré (ou rééquilibré à l'analyse) et de taille suffisante
pour que le test statistique ait de la puissance (ordre de grandeur : ≥ quelques
dizaines par classe, idéalement plus).

---

## 3. Extraction des scores

Le **mode bulk** (`src/bulk.rs`) produit un JSON par APK. On en extrait, pour
chaque APK et chaque `label` d'intimité, le champ `score` (score normalisé) — et
optionnellement `score_raw`, `n`, `ad`, `eff` pour l'analyse de sensibilité.

Un APK sans match sur un label donné compte comme **score 0** pour ce label
(absence de couplage qualifié), et non comme donnée manquante — l'absence est une
information.

Sortie de travail conseillée : une table `apk_id, label, score, score_raw, n, ad, eff, class`
(class ∈ {benign, stalkerware}), traitée hors ligne (Python/pandas).

---

## 4. Analyse des distributions

Par label :

- **Descriptif** : médiane, IQR, min/max par classe ; les moyennes sont peu
  informatives sur des distributions asymétriques.
- **Visualisation** : box-plots ou violons bénin vs stalkerware ; histogrammes
  superposés en échelle log si les queues sont longues (le score peut atteindre
  plusieurs dizaines).
- **Chevauchement** : identifier la plage où les deux classes se recouvrent —
  c'est la zone où le choix du seuil est critique.

---

## 5. Test de séparation : Mann-Whitney U

On teste si les scores des deux classes proviennent de distributions
différentes. Le test retenu est le **U de Mann-Whitney** [3] :

- **non paramétrique** : aucune hypothèse de normalité (les scores sont
  asymétriques, à queue longue) ;
- **robuste aux tailles inégales** et aux échelles ordinales ;
- H₀ : les deux distributions sont identiques ; un p-value faible indique une
  séparation significative.

Rapporter, en plus du p-value, une **taille d'effet** : la corrélation
rang-bisériale, ou de façon équivalente l'AUC (probabilité qu'un stalkerware tiré
au hasard ait un score supérieur à un bénin tiré au hasard). L'AUC résume le
pouvoir discriminant du label indépendamment du seuil.

> La significativité (p-value) ne suffit pas : sur un grand corpus, une
> séparation minime devient « significative ». C'est la **taille d'effet / AUC**
> qui dit si le label est utile en pratique.

---

## 6. Choix du seuil

À partir de la courbe ROC (TPR vs FPR sur toute la plage de seuils) :

- **Contrainte opérationnelle (recommandé ici).** En détection de stalkerware,
  un faux positif accuse à tort une app bénigne : coût élevé. Fixer d'abord un
  **FPR cible** acceptable (p. ex. ≤ 1–5 %), puis prendre le seuil qui maximise
  le TPR sous cette contrainte.
- **Indice J de Youden.** Seuil maximisant `TPR − FPR` : équilibre
  symétrique, utile comme point de référence neutre.
- **Maximisation du F₁.** Si l'on privilégie le compromis précision/rappel.

Documenter le critère choisi et le seuil `min-score` qui en résulte, **par
label**. Reporter ce seuil dans les règles du catalogue.

---

## 7. Validation

- **Hold-out ou k-fold famille-aware** : le seuil est fixé sur la partie
  calibration, puis évalué sur la partie test (familles non vues).
- **Métriques sur le test** : TPR, FPR, précision, F₁, AUC — jamais sur les
  données ayant servi à fixer le seuil.
- **Analyse d'erreurs** : inspecter les faux positifs (couplage bénin à score
  élevé : quel SDK/quelle logique ?) et les faux négatifs (stalkerware à score
  bas : obfuscation du sink ? couplage hors des groupes définis ?). Ces cas
  nourrissent les groupes de sinks (§ 6 d'`intimacy.md`) et l'allowlist.

---

## 8. État préliminaire (2 APK — illustratif, non calibré)

Amorce sur les échantillons de référence, à titre indicatif **uniquement** :

| classe | APK | label | score |
|---|---|---|---|
| bénin | Flixoid | collection-network | 1.0 |
| bénin | Flixoid | digest-network | 2.0 |
| stalkerware | iKeyMonitor | digest-network | 3.6 |
| stalkerware | iKeyMonitor | crypto-network | 28.2 |
| stalkerware | iKeyMonitor | collection-network | 35.5 |

La séparation est nette sur les couplages forts (≥ 28) et étroite en bas
(bénin 2.0 vs stalkerware 3.6). Deux points ne permettent **ni** de poser un
seuil **ni** de lancer un test — ils motivent seulement le passage au corpus.

---

## 9. Reproductibilité

- Figer la version du binaire (le hash du catalogue, cf. `architecture.md`
  § Cache) et la version du bundle STIX utilisés pour l'extraction.
- Figer la liste des APK du corpus (hashes) et le découpage train/test.
- Le calcul du diamètre effectif est déterministe (RNG seedé), donc les scores
  sont reproductibles à binaire constant.

---

## 10. Références

[1] IntDroid — cf. [`intimacy.md`](intimacy.md), réf. [1]. Méthodologie de
validation bénin/malveillant de référence.

[2] Y. Zhao, L. Li, H. Wang, H. Cai, T. F. Bissyandé, J. Klein, J. Grundy.
« On the Impact of Sample Duplication in Machine-Learning-Based Android Malware
Detection. » *ACM Transactions on Software Engineering and Methodology (TOSEM)*,
vol. 30, n° 3, 2021, p. 1–38.

[3] H. B. Mann, D. R. Whitney. « On a Test of Whether One of Two Random Variables
is Stochastically Larger than the Other. » *Annals of Mathematical Statistics*,
vol. 18, n° 1, 1947, p. 50–60.

> L'indice J de Youden et les métriques ROC/AUC sont des outils statistiques
> standard ; référence bibliographique à compléter au source si citée en thèse.
