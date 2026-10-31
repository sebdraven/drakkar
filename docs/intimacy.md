# Intimacy — coupling detection by call-graph intimacy

This document describes the `intimacy` feature of the Drakkar rule engine: its
motivation, its academic grounding, the adaptation that makes it computable on
call graphs of ~200 k nodes, its implementation, its DSL, and the empirical
results observed.

---

## 1. Motivation

Some ATT&CK techniques cannot be observed in the *presence* of an API, but in
the **coupling** of two primitives from the same region of code. The canonical
case is exfiltration: encrypting data (`Cipher.doFinal`), then sending it over
the network (`HttpURLConnection`, TLS socket…). The presence of both primitives
says nothing — any app using HTTPS encrypts and sends. What sets stalkerware
apart is that **its own application code** orchestrates the crypto → network
pair, whereas a benign app delegates that pair to a third-party SDK
(advertising, video player, HTTP client).

A first, boolean approach ("is there a pivot common to both primitives within
≤ N hops?") runs into two problems:

1. **The threshold `N` is arbitrary.** Call graphs are *small-world*: distance
   grows as `log(V)`, not linearly. Setting `N = 15` has no justification that
   carries over from one APK to another.
2. **A binary result loses information.** A tight coupling (many short bridges)
   and a loose one (one long bridge) both return "true".

The `intimacy` feature replaces that boolean with a **continuous score**,
statistically calibratable and comparable across APKs.

---

## 2. Grounding: IntDroid

The measure is inspired by IntDroid [1], which treats the function call graph
as a social network and computes the **intimacy** between sensitive APIs and
central nodes. IntDroid's definition, between two functions `a` and `b`, is:

```
intimacy(a, b) = n / (ad(a, b) + 1)
```

where `n` is the number of reachable paths between `a` and `b`, and `ad` the
average distance of those paths. The more paths and the shorter they are, the
higher the intimacy. The `+1` in the denominator handles the case where `a` is
itself the central node (distance 0). IntDroid then feeds these intimacies to
an ML classifier (F-measure 97.1 %, TPR 99.1 % on ~8 k apps) [1].

Two properties of IntDroid shape our adaptation:

- Its call graphs are **small** (~4.8 k nodes, ~10 k edges on average) and
  almost tree-like, which keeps path counting tractable.
- Intimacy is measured there between a sensitive API and a **central** node in
  an *ancestor → descendant* relation (the hub reaches the API).

Neither property holds for Drakkar (graphs of ~200 k edges, with cycles;
coupling between two *sibling* primitives, neither an ancestor of the other).
Hence the reformulation below.

---

## 3. Reformulation for Drakkar

### 3.1 `n` = common pivots, not paths

Counting all paths between two nodes is **#P-complete** and unbounded in the
presence of cycles (recursion, mutual callbacks). On a graph of 200 k edges it
is intractable. We reformulate `n`:

- **IntDroid**: `n` = number of paths between `a` and `b`.
- **Drakkar**: `n` = number of **qualified common pivots**, i.e. functions that
  reach *both* the crypto group and the network group.

This `n` is computed by intersecting ancestor sets, i.e. **two reverse BFS in
O(V + E)** — instead of an exponential path count. This is the key adaptation,
and it must be **stated explicitly** in publication: our `n` (multiplicity of
coupling functions) measures a different coupling density from IntDroid's `n`
(multiplicity of paths), even though both capture an intimacy.

### 3.2 Structure: co-callees, not ancestor-descendant

In IntDroid, `a` and `b` are in an ancestor → descendant relation: there is a
directed path from the central node *to* the API. In Drakkar,
`Cipher.doFinal` and `getOutputStream` are **not** ancestors of one another —
crypto does not call the network. They are two **descendants of a common
pivot** (the function that encrypts, then sends). The notion of "paths between
`a` and `b`" therefore makes no sense here; the common ancestor is the correct
analogue.

The crypto↔network "bridge" through a pivot `p` has length
`dist(p → a) + dist(p → b)`.

---

## 4. Computation pipeline

Implemented in `src/cfg/mod.rs::intimacy`.

### 4.1 Targets: non-allowlisted direct callers of the primitives

A crucial point, corrected after a first false positive (see § 8). We do
**not** target the system primitives themselves (`Cipher.doFinal`,
`getOutputStream`), which are shared APIs called by a benign SDK as much as by
the app. We target their **non-allowlisted direct callers**
(`nonallowlisted_callers`):

- For each node matching a primitive of the group, take its direct
  predecessors (incoming edges).
- Keep only those whose package is **not** in the benign-SDK allowlist
  (`BENIGN_SDK_PREFIXES`: gms, exoplayer2, ironsource, unity3d, androidx,
  okhttp, retrofit, kotlin…).

This separates "findlink delegates to ironsource, which encrypts" (caller =
ironsource, allowlisted → dropped) from "the malware encrypts from its own
code" (caller = an obfuscated class of the malware, not allowlisted → kept).
The filter is applied at the **actual coupling point** (whoever invokes the
primitive), not at the topmost pivot.

If either set of qualified callers is empty → score zero.

### 4.2 Common pivots

From the targets, two multi-source BFS over **incoming** edges
(`reverse_bfs_dist`) give, for each ancestor, its distance to the nearest
target of each group. The intersection of the two distance tables = the common
pivots. Each pivot is **qualified** by three optional safeguards:

- `exclude_entrypoints`: drops manifest entry points (avoids the trivial root
  pivot);
- `max_dist`: optional bound on `dist(p → a)` and `dist(p → b)`;
- `exclude_allowlisted`: drops pivots in a benign-SDK package.

### 4.3 Decomposition into components (WCC)

The CFG is not connected (app code, each SDK and dead code form islands).
Aggregating pivots over the whole graph would mix "how tightly ironsource
couples crypto and network" with "how tightly the app does". We therefore
isolate by **weakly connected component** (WCC), labelled by union-find
(`wcc_labels`, `petgraph::unionfind`). Pivots are grouped by WCC, a score is
computed **per component**, and the component with the highest score is kept.

> **Note.** The WCC does not separate two modules when one *calls* the other
> (findlink → ironsource = same WCC). Separation by component is therefore
> effective when the malicious module is truly isolated (e.g. a service
> triggered by the framework), less so when an application component pulls
> everything into its component. A finer grain (clustering by package) is an
> avenue (§ 9).

### 4.4 Directed effective diameter

To make the distance `ad` comparable across components of different sizes, it
is normalised by the **directed effective diameter** of the WCC — the 90th
percentile of finite directed distances (q-effective diameter, `q = 0.9`, in
the sense of [2]). Estimated in `effective_diameter_directed`:

- **Sampled multi-sweep**: sources are drawn in the component; from each, a
  *forward* BFS (outgoing edges) yields all finite directed distances.
  Unreachable pairs are never counted — which natively handles the asymmetry
  of the directed case (infinite distances).
- Distances feed a **histogram**, from which the 90th percentile is read.
- **Adaptive budget `k`**: stop when the p90 is stable over `PATIENCE = 3`
  consecutive sources, after a minimum of `MIN_SOURCES = 8`, capped at
  `MAX_SOURCES = 64`. Components of ≤ 8 nodes: exhaustive sampling.
- **Deterministic xorshift64 RNG** (seed derived from the size) → reproducible
  across runs.

> **Method note.** The classic double sweep estimates the *maximum* diameter;
> for a *percentile*, representative sources are sampled instead of chaining
> sweeps towards the periphery (which would bias the estimate upwards). A
> "canonical" sketch-based variant (ANF / HyperANF [3]) is a possible
> evolution, with the same interface.

### 4.5 Score

For the component kept, with `n` qualified pivots and average bridge distance
`ad`:

```
score_raw  = n / (ad + 1)                 # not normalised
eff        = directed effective diameter of the WCC
score      = n / (ad / eff + 1)           # normalised, match criterion
```

`score` (normalised) is comparable across APKs and serves as the threshold
criterion; `score_raw`, `n`, `ad` and `eff` are all exposed in the evidence
for sorting and calibration in post-processing.

---

## 5. Rule DSL

The `intimacy` feature takes two **groups** of APIs (`first`, `second`), each a
single string or a list of equivalent primitives; a node belongs to the group
if it matches one of its members. Parameters:

| key | default | role |
|---|---|---|
| `first` | *(required)* | source group (e.g. crypto primitives) |
| `second` | *(required)* | target group (e.g. network sinks) |
| `label` | `"coupling"` | name of the coupling, carried into the evidence |
| `exclude-entrypoints` | `true` | drops entry points as pivots |
| `exclude-allowlisted` | `false` | drops pivots in a benign-SDK package |
| `max-dist` | *(none)* | optional bound on bridge distances |
| `min-score` | `0.0` | match threshold on the **normalised** score |

Example (T1521, Encrypted Channel):

```yaml
intimacy:
  label: crypto-network
  first:
    - Ljavax/crypto/Cipher;->doFinal
    - Ljavax/crypto/Mac;->doFinal
  second:
    - Ljava/net/HttpURLConnection;->getOutputStream
    - Ljavax/net/ssl/SSLContext;->init
    # … (see § 6)
  exclude-entrypoints: true
  exclude-allowlisted: true
  min-score: 0.0
```

With `min-score: 0.0`, the rule matches as soon as a qualified pivot exists and
**exposes the score**; sorting and thresholding are then done offline, rather
than fixing a threshold blindly.

---

## 6. Sink groups

The network group targets **system APIs that cannot be obfuscated**: a bundled
network library renamed by R8/ProGuard (e.g. an okhttp obfuscated into `q6.z`)
escapes literal matching, but always ends up calling the JDK or the framework,
which are not obfuscated. Current network group:

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

A welcome side effect: in a clean app, the network goes through a
**recognisable** okhttp (allowlisted) → caller dropped; in malware, it goes
through an **obfuscated, bundled** network stack (not allowlisted) → caller
kept. **The obfuscation of the network library itself becomes a
discriminant.**

Rules using these groups: T1521 (`crypto-network`), T1521.001
(`symmetric-crypto-network`), T1646 (`collection-network`), T1637.001
(`digest-network`).

---

## 7. Output (evidence)

An `intimacy` evidence has the form:

```json
{
  "kind": "intimacy",
  "value": "crypto-network @ Lx/u;->a(LLL)V (n=114, ad=12.1, eff=4.0, raw=8.670)",
  "reachable": true,
  "score": 28.24,
  "paths": [ [ "<pivot>", "…", "<crypto caller>" ],
             [ "<pivot>", "…", "<network caller>" ] ]
}
```

- `score`: **normalised** score (numeric field, for sorting and calibration);
- `value`: label + pivot + `n`, `ad`, `eff`, `raw` (human-readable);
- `paths`: the two legs of the bridge through the best pivot (traceability).

---

## 8. Empirical results

Two reference samples, same rules.

| APK | rule | pivot | n | eff | raw | **score** |
|---|---|---|---|---|---|---|
| Flixoid (benign + Popa proxy) | T1646 collection-network | `findlink/LinkActivity;->loadData` | 2 | 7.0 | 0.25 | **1.0** |
| Flixoid | T1637.001 digest-network | `findlink/LinkActivity;->loadData` | 5 | 7.0 | 0.45 | **2.0** |
| iKeyMonitor (stalkerware) | T1637.001 digest-network | `t4/c;->l` | 12 | 4.0 | 1.16 | **3.6** |
| iKeyMonitor | T1521 / .001 crypto-network | `x/u;->a` | 114 | 4.0 | 8.67 | **28.2** |
| iKeyMonitor | T1646 collection-network | `n7/a;->g` | 122 | 4.0 | 11.35 | **35.5** |

Reading:

- **Clear separation.** Malicious couplings (crypto→network, exfiltration) are
  an order of magnitude above benign ones.
- **The main driver is `n`**: 2 pivots in Flixoid against 122 in iKeyMonitor —
  the malware has dozens of methods that encrypt-and-send.
- **The pivots are semantically right.** In iKeyMonitor, `n7/a.g` is the
  custom HTTP client (calls `HttpURLConnection`/`HttpsURLConnection`), `x/u.a`
  couples crypto and TLS, `t4/c.l` couples digest and HTTP. In Flixoid, the
  pivot is legitimate application code (film search through the Trakt API),
  hence a low but non-zero score — a real coupling, but a benign one.
- **False positive corrected (§ 4.1).** An earlier version targeted the
  primitives themselves and climbed to the first non-allowlisted ancestor; on
  Flixoid, `findlink.loadFullIronSource` (a mere IronSource launcher) came out
  as the pivot although all the coupling was inside ironsource. Targeting the
  **direct callers** of the primitives removes this case.

---

## 9. Limits and future work

- **Overlap at the bottom of the distribution.** Flixoid reaches 2.0;
  iKeyMonitor's DGA goes down to 3.6. Strong signals (≥ 28) are clear, but the
  low range needs careful calibration.
- **Normalising `n` by `|WCC|`.** The score is dominated by `n`, which depends
  on code size and density. A large benign APK could inflate `n`. Normalising
  by the size of the component would make the score fully scale-invariant. To
  be decided **on data**, not a priori.
- **Threshold calibration.** The real contribution: on a benign vs stalkerware
  corpus (bulk mode), set `min-score` through a **Mann-Whitney** test on the
  two distributions — IntDroid's validation approach [1].
- **Diameter estimator.** The sampled multi-sweep is a bound; a HyperANF [3]
  version would give a canonical, citable q-effective diameter.
- **Reflection / dynamic loading.** Like any flow- and context-insensitive
  static analysis, `intimacy` follows neither reflection nor code loaded at run
  time — a limit shared with IntDroid [1].
- **Memoising the diameter.** The effective diameter is recomputed per rule;
  memoising it per WCC (`OnceCell`) is an optimisation if profiling justifies
  it.

---

## 10. References

[1] D. Zou, Y. Wu, S. Yang, A. Chauhan, W. Yang, J. Zhong, S. Dou, H. Jin.
"IntDroid: Android Malware Detection Based on API Intimacy Analysis." *ACM
Transactions on Software Engineering and Methodology (TOSEM)*, vol. 30, no. 3,
article 39, May 2021, pp. 1–32. DOI: 10.1145/3442588.

[2] J. Leskovec, J. Kleinberg, C. Faloutsos. "Graphs over Time: Densification
Laws, Shrinking Diameters and Possible Explanations." *Proc. 11th ACM SIGKDD
Int. Conf. on Knowledge Discovery in Data Mining (KDD '05)*, 2005, pp. 177–187.
(q-effective diameter, q = 0.9.)

[3] C. R. Palmer, P. B. Gibbons, C. Faloutsos. "ANF: A Fast and Scalable Tool
for Data Mining in Massive Graphs." *Proc. 8th ACM SIGKDD Int. Conf. on
Knowledge Discovery and Data Mining (KDD '02)*, 2002. (Estimation of the
neighbourhood function; basis of HyperANF. Pagination to be confirmed at the
source.)
