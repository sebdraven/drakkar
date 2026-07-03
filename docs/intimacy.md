# Intimité — détection de couplage par intimité de call graph

Ce document décrit la feature `intimacy` du moteur de règles Drakkar : sa
motivation, son fondement académique, l'adaptation qui la rend calculable sur
des call graphs à ~200 k nœuds, son implémentation, son DSL, et les résultats
empiriques observés.

---

## 1. Motivation

Certaines techniques ATT&CK ne s'observent pas dans la *présence* d'une API,
mais dans le **couplage** de deux primitives depuis une même région de code. Le
cas canonique est l'exfiltration : chiffrer des données (`Cipher.doFinal`) puis
les envoyer sur le réseau (`HttpURLConnection`, socket TLS…). La présence des
deux primitives ne dit rien — n'importe quelle app en HTTPS chiffre et envoie.
Ce qui distingue un stalkerware, c'est que **son propre code applicatif**
orchestre le couple crypto → réseau, alors qu'une app bénigne délègue ce couple
à un SDK tiers (publicité, lecteur vidéo, client HTTP).

Une première approche booléenne (« existe-t-il un pivot commun aux deux
primitives à ≤ N sauts ? ») bute sur deux écueils :

1. **Le seuil `N` est arbitraire.** Les call graphs sont *small-world* : la
   distance croît en `log(V)`, pas linéairement. Fixer `N = 15` n'a pas de
   justification transférable d'un APK à l'autre.
2. **Le résultat binaire perd l'information.** Un couplage serré (beaucoup de
   ponts courts) et un couplage lâche (un pont long) rendent tous deux « vrai ».

La feature `intimacy` remplace ce booléen par un **score continu**, calibrable
statistiquement et comparable entre APK.

---

## 2. Fondement : IntDroid

La mesure s'inspire d'IntDroid [1], qui traite le function call graph comme un
réseau social et calcule l'**intimité** entre API sensibles et nœuds centraux.
La définition d'IntDroid, entre deux fonctions `a` et `b`, est :

```
intimacy(a, b) = n / (ad(a, b) + 1)
```

où `n` est le nombre de chemins atteignables entre `a` et `b`, et `ad` la
distance moyenne de ces chemins. Plus il y a de chemins et plus ils sont courts,
plus l'intimité est élevée. Le `+1` au dénominateur gère le cas où `a` est
lui-même le nœud central (distance 0). IntDroid alimente ensuite un classifieur
ML avec ces intimités (F-measure 97,1 %, TPR 99,1 % sur ~8 k apps) [1].

Deux propriétés d'IntDroid conditionnent notre adaptation :

- Ses call graphs sont **petits** (~4,8 k nœuds, ~10 k arêtes en moyenne) et
  quasi-arborescents, ce qui rend le comptage de chemins tractable.
- L'intimité y est mesurée entre une API sensible et un nœud **central** en
  relation *ancêtre → descendant* (le hub atteint l'API).

Aucune de ces deux propriétés ne tient pour Drakkar (graphes ~200 k arêtes,
avec cycles ; couplage entre deux primitives *sœurs*, non ancêtre l'une de
l'autre). D'où la reformulation ci-dessous.

---

## 3. Reformulation pour Drakkar

### 3.1 `n` = pivots communs, pas chemins

Compter tous les chemins entre deux nœuds est **#P-complet** et non borné en
présence de cycles (récursion, callbacks mutuels). Sur un graphe à 200 k arêtes,
c'est intractable. On reformule `n` :

- **IntDroid** : `n` = nombre de chemins entre `a` et `b`.
- **Drakkar** : `n` = nombre de **pivots communs qualifiés**, c.-à-d. de
  fonctions qui atteignent *à la fois* le groupe crypto et le groupe réseau.

Ce `n` se calcule par intersection des ensembles d'ancêtres, soit **deux BFS
inversés en O(V + E)** — au lieu d'un comptage de chemins exponentiel. C'est
l'adaptation clé, et elle doit être **assumée explicitement** en publication :
notre `n` (multiplicité des fonctions couplantes) mesure une densité de couplage
différente du `n` d'IntDroid (multiplicité des chemins), même si les deux
capturent une intimité.

### 3.2 Structure : co-appelés, pas ancêtre-descendant

Chez IntDroid, `a` et `b` sont en relation ancêtre → descendant : il existe un
chemin dirigé du nœud central *vers* l'API. Chez Drakkar, `Cipher.doFinal` et
`getOutputStream` ne sont **pas** l'un ancêtre de l'autre — la crypto n'appelle
pas le réseau. Ce sont deux **descendants d'un pivot commun** (la fonction qui
chiffre puis envoie). La notion de « chemins entre `a` et `b` » n'a donc pas de
sens ici ; l'ancêtre commun est l'analogue correct.

Le « pont » crypto↔réseau via un pivot `p` a pour longueur
`dist(p → a) + dist(p → b)`.

---

## 4. Pipeline de calcul

Implémenté dans `src/cfg/mod.rs::intimacy`.

### 4.1 Cibles : appelants directs non-allowlistés des primitives

Point crucial, et corrigé après un premier faux positif (voir § 8). On ne cible
**pas** les primitives système elles-mêmes (`Cipher.doFinal`, `getOutputStream`),
qui sont des API partagées appelées aussi bien par un SDK bénin que par l'app.
On cible leurs **appelants directs non-allowlistés** (`nonallowlisted_callers`) :

- Pour chaque nœud matchant une primitive du groupe, on prend ses prédécesseurs
  directs (arêtes entrantes).
- On ne garde que ceux dont le package n'est **pas** dans l'allowlist des SDK
  bénins (`BENIGN_SDK_PREFIXES` : gms, exoplayer2, ironsource, unity3d, androidx,
  okhttp, retrofit, kotlin…).

Ainsi « findlink délègue à ironsource qui chiffre » (appelant = ironsource,
allowlisté → écarté) se distingue de « le malware chiffre depuis son propre
code » (appelant = classe obfusquée du malware, non-allowlisté → gardé). Le
filtre est appliqué au **point de couplage réel** (qui invoque la primitive),
pas au pivot le plus haut.

Si l'un des deux ensembles d'appelants qualifiés est vide → score nul.

### 4.2 Pivots communs

À partir des cibles, deux BFS multi-sources sur les arêtes **entrantes**
(`reverse_bfs_dist`) donnent, pour chaque ancêtre, sa distance à la cible la plus
proche de chaque groupe. L'intersection des deux tables de distances = les pivots
communs. Chaque pivot est **qualifié** par trois garde-fous optionnels :

- `exclude_entrypoints` : écarte les entrypoints manifest (évite le pivot racine
  trivial) ;
- `max_dist` : borne optionnelle sur `dist(p → a)` et `dist(p → b)` ;
- `exclude_allowlisted` : écarte les pivots dans un package SDK bénin.

### 4.3 Décomposition en composantes (WCC)

Le CFG n'est pas connexe (code app, chaque SDK, code mort forment des îlots).
Agréger les pivots sur tout le graphe mélangerait « à quel point ironsource
couple crypto et réseau » avec « à quel point l'app le fait ». On isole donc par
**composante faiblement connexe** (WCC), labellisée par union-find
(`wcc_labels`, `petgraph::unionfind`). Les pivots sont regroupés par WCC, un
score est calculé **par composante**, et l'on retient la composante au score
maximal.

> **Note.** La WCC ne sépare pas deux modules quand l'un *appelle* l'autre
> (findlink → ironsource = même WCC). La séparation par composante est donc
> opérante quand le module malveillant est réellement isolé (p. ex. un service
> déclenché par le framework), moins quand un composant applicatif tire tout le
> monde dans sa composante. Un grain plus fin (clustering par package) est une
> piste (§ 9).

### 4.4 Diamètre effectif dirigé

Pour rendre la distance `ad` comparable entre composantes de tailles
différentes, on la normalise par le **diamètre effectif dirigé** de la WCC —
le 90ᵉ percentile des distances dirigées finies (q-effective diameter, `q = 0.9`,
au sens de [2]). Estimation dans `effective_diameter_directed` :

- **Multi-sweep échantillonné** : on tire des sources dans la composante ;
  depuis chacune, un BFS *forward* (arêtes sortantes) fournit toutes les
  distances dirigées finies. Les paires non atteignables ne sont jamais comptées
  — ce qui gère nativement l'asymétrie du dirigé (distances infinies).
- Les distances alimentent un **histogramme**, d'où l'on lit le 90ᵉ percentile.
- **Budget `k` adaptatif** : arrêt quand le p90 est stable sur `PATIENCE = 3`
  sources consécutives, après un minimum de `MIN_SOURCES = 8`, plafonné à
  `MAX_SOURCES = 64`. Composantes ≤ 8 nœuds : échantillonnage exhaustif.
- **RNG xorshift64 déterministe** (seed dérivé de la taille) → reproductible
  entre runs.

> **Note de méthode.** Le double-sweep classique estime le diamètre *maximum* ;
> pour un *percentile*, on échantillonne des sources représentatives plutôt que
> de chaîner les sweeps vers la périphérie (ce qui biaiserait l'estimation vers
> le haut). Une variante « canonique » par sketches (ANF / HyperANF [3]) est
> possible en évolution, avec la même interface.

### 4.5 Score

Pour la composante retenue, de `n` pivots qualifiés et de distance de pont
moyenne `ad` :

```
score_raw  = n / (ad + 1)                 # non normalisé
eff        = diamètre effectif dirigé de la WCC
score      = n / (ad / eff + 1)           # normalisé, critère de match
```

`score` (normalisé) est comparable entre APK et sert de critère de seuil ;
`score_raw`, `n`, `ad` et `eff` sont tous exposés dans l'evidence pour le tri et
la calibration en post-traitement.

---

## 5. DSL de règle

La feature `intimacy` accepte deux **groupes** d'API (`first`, `second`), chacun
une chaîne unique ou une liste de primitives équivalentes ; un nœud appartient au
groupe s'il matche l'un de ses membres. Paramètres :

| clé | défaut | rôle |
|---|---|---|
| `first` | *(requis)* | groupe source (p. ex. primitives crypto) |
| `second` | *(requis)* | groupe cible (p. ex. sinks réseau) |
| `label` | `"coupling"` | nom du couplage, repris dans l'evidence |
| `exclude-entrypoints` | `true` | écarte les entrypoints comme pivots |
| `exclude-allowlisted` | `false` | écarte les pivots en package SDK bénin |
| `max-dist` | *(aucune)* | borne optionnelle sur les distances de pont |
| `min-score` | `0.0` | seuil de match sur le score **normalisé** |

Exemple (T1521, Encrypted Channel) :

```yaml
intimacy:
  label: crypto-network
  first:
    - Ljavax/crypto/Cipher;->doFinal
    - Ljavax/crypto/Mac;->doFinal
  second:
    - Ljava/net/HttpURLConnection;->getOutputStream
    - Ljavax/net/ssl/SSLContext;->init
    # … (voir § 6)
  exclude-entrypoints: true
  exclude-allowlisted: true
  min-score: 0.0
```

Avec `min-score: 0.0`, la règle matche dès qu'un pivot qualifié existe et
**expose le score** ; le tri/seuil se fait ensuite hors ligne, plutôt que de
figer un seuil à l'aveugle.

---

## 6. Groupes de sinks

Le groupe réseau vise des **API système non-obfuscables** : une bibliothèque
réseau bundlée et renommée par R8/ProGuard (p. ex. un okhttp obfusqué en
`q6.z`) échappe au matching littéral, mais finit toujours par appeler le JDK ou
le framework, qui ne s'obfusquent pas. Groupe réseau courant :

```
Ljava/net/HttpURLConnection;->getOutputStream
Ljava/net/HttpURLConnection;->connect
Ljava/net/URL;->openConnection
Ljava/net/URL;->openStream
Ljava/net/Socket;->getOutputStream
Ljava/net/Socket;->connect
Ljavax/net/ssl/SSLSocketFactory;->createSocket
Ljavax/net/ssl/SSLContext;->init
Lokhttp3/OkHttpClient;->newCall
Lokhttp3/Call;->execute
Ljava/net/DatagramSocket;->send
```

Effet de bord bénéfique : sur une app propre, le réseau passe par un okhttp
**reconnaissable** (allowlisté) → appelant écarté ; sur un malware, il passe par
une stack réseau **obfusquée et bundlée** (non-allowlistée) → appelant gardé.
**L'obfuscation de la lib réseau devient elle-même un discriminant.**

Règles utilisant ces groupes : T1521 (`crypto-network`), T1521.001
(`symmetric-crypto-network`), T1646 (`collection-network`), T1637.001
(`digest-network`).

---

## 7. Sortie (evidence)

Une preuve `intimacy` a la forme :

```json
{
  "kind": "intimacy",
  "value": "crypto-network @ Lx/u;->a(LLL)V (n=114, ad=12.1, eff=4.0, raw=8.670)",
  "reachable": true,
  "score": 28.24,
  "paths": [ [ "<pivot>", "…", "<appelant crypto>" ],
             [ "<pivot>", "…", "<appelant réseau>" ] ]
}
```

- `score` : score **normalisé** (champ numérique, pour tri/calibration) ;
- `value` : label + pivot + `n`, `ad`, `eff`, `raw` (lisible) ;
- `paths` : les deux legs du pont via le meilleur pivot (traçabilité).

---

## 8. Résultats empiriques

Deux échantillons de référence, mêmes règles.

| APK | règle | pivot | n | eff | raw | **score** |
|---|---|---|---|---|---|---|
| Flixoid (bénin + proxy Popa) | T1646 collection-network | `findlink/LinkActivity;->loadData` | 2 | 7.0 | 0.25 | **1.0** |
| Flixoid | T1637.001 digest-network | `findlink/LinkActivity;->loadData` | 5 | 7.0 | 0.45 | **2.0** |
| iKeyMonitor (stalkerware) | T1637.001 digest-network | `t4/c;->l` | 12 | 4.0 | 1.16 | **3.6** |
| iKeyMonitor | T1521 / .001 crypto-network | `x/u;->a` | 114 | 4.0 | 8.67 | **28.2** |
| iKeyMonitor | T1646 collection-network | `n7/a;->g` | 122 | 4.0 | 11.35 | **35.5** |

Lecture :

- **Séparation nette.** Les couplages malveillants (crypto→réseau, exfil) sont
  un ordre de grandeur au-dessus des couplages bénins.
- **Le driver principal est `n`** : 2 pivots chez Flixoid contre 122 chez
  iKeyMonitor — le malware a des dizaines de méthodes qui chiffrent-et-envoient.
- **Les pivots sont sémantiquement justes.** Chez iKeyMonitor, `n7/a.g` est le
  client HTTP custom (appelle `HttpURLConnection`/`HttpsURLConnection`), `x/u.a`
  couple crypto et TLS, `t4/c.l` couple digest et HTTP. Chez Flixoid, le pivot
  est du code applicatif légitime (recherche de films via l'API Trakt), d'où un
  score bas mais non nul — un couplage réel, mais bénin.
- **Faux positif corrigé (§ 4.1).** Une version antérieure ciblait les
  primitives elles-mêmes et remontait au premier ancêtre non-allowlisté ; sur
  Flixoid, `findlink.loadFullIronSource` (un simple launcher IronSource)
  ressortait comme pivot alors que tout le couplage était dans ironsource. Cibler
  les **appelants directs** des primitives élimine ce cas.

---

## 9. Limites et travaux futurs

- **Chevauchement en bas de distribution.** Flixoid monte à 2,0 ; le DGA
  d'iKeyMonitor descend à 3,6. Les signaux forts (≥ 28) sont nets, mais la zone
  basse demande une calibration soignée.
- **Normaliser `n` par `|WCC|`.** Le score est dominé par `n`, qui dépend de la
  taille/densité du code. Un gros APK bénin pourrait gonfler `n`. Normaliser par
  la taille de la composante rendrait le score pleinement invariant à l'échelle.
  À trancher **sur données**, pas a priori.
- **Calibration du seuil.** La vraie contribution : sur un corpus bénin vs
  stalkerware (mode bulk), poser `min-score` par un test de **Mann-Whitney** sur
  les deux distributions — la démarche de validation d'IntDroid [1].
- **Estimateur de diamètre.** Le multi-sweep échantillonné est une borne ; une
  version HyperANF [3] donnerait un q-effective diameter canonique et citable.
- **Réflexion / chargement dynamique.** Comme toute analyse statique flow- et
  context-insensitive, `intimacy` ne suit ni la réflexion ni le code chargé à
  l'exécution — limite partagée avec IntDroid [1].
- **Mémoïsation du diamètre.** Le diamètre effectif est recalculé par règle ; le
  mémoïser par WCC (OnceCell) est une optimisation si le profilage le justifie.

---

## 10. Références

[1] D. Zou, Y. Wu, S. Yang, A. Chauhan, W. Yang, J. Zhong, S. Dou, H. Jin.
« IntDroid: Android Malware Detection Based on API Intimacy Analysis. » *ACM
Transactions on Software Engineering and Methodology (TOSEM)*, vol. 30, n° 3,
article 39, mai 2021, p. 1–32. DOI : 10.1145/3442588.

[2] J. Leskovec, J. Kleinberg, C. Faloutsos. « Graphs over Time: Densification
Laws, Shrinking Diameters and Possible Explanations. » *Proc. 11th ACM SIGKDD
Int. Conf. on Knowledge Discovery in Data Mining (KDD '05)*, 2005, p. 177–187.
(q-effective diameter, q = 0.9.)

[3] C. R. Palmer, P. B. Gibbons, C. Faloutsos. « ANF: A Fast and Scalable Tool
for Data Mining in Massive Graphs. » *Proc. 8th ACM SIGKDD Int. Conf. on
Knowledge Discovery and Data Mining (KDD '02)*, 2002. (Estimation de la fonction
de voisinage ; base de HyperANF. Pagination à confirmer au source.)
