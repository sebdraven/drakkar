//! Call graph inter-procédural (petgraph).
use crate::model::MethodRef;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::unionfind::UnionFind;
use petgraph::visit::Bfs;
use petgraph::Direction;
use std::collections::{HashMap, HashSet, VecDeque};

/// Callbacks de cycle de vie / framework qui servent de points d'entrée Android.
/// Le framework les invoque ; ils ne sont pas appelés explicitement dans le code.
pub const ENTRYPOINT_CALLBACKS: &[&str] = &[
    // Composants
    "onCreate",
    "onStart",
    "onStartCommand",
    "onResume",
    "onBind",
    "onReceive",
    "onHandleIntent",
    "onHandleWork",
    // Accessibility / notifications
    "onAccessibilityEvent",
    "onInterrupt",
    "onServiceConnected",
    "onNotificationPosted",
    "onNotificationRemoved",
    // Concurrence
    "run",
    "doInBackground",
    "onStartJob",
    "call",
    // Listeners courants
    "onLocationChanged",
    "onSensorChanged",
    "handleMessage",
];

/// Edge = un call site (offset dans le caller).
#[derive(Debug, Clone)]
pub struct CallSite {
    pub offset: u64,
}

pub struct CallGraph {
    pub graph: DiGraph<MethodRef, CallSite>,
    index: HashMap<String, NodeIndex>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self { graph: DiGraph::new(), index: HashMap::new() }
    }

    fn node(&mut self, m: MethodRef) -> NodeIndex {
        // Clé = api() (class->name) et NON signature() : le descripteur d'une même
        // méthode diverge entre sa vue caller (descripteur exact, dex.rs) et sa vue
        // callee (reconstruit depuis le shorty). Indexer sur signature() dédoublait
        // chaque méthode en 2 nœuds et fragmentait le graphe inter-proc (reachability
        // toujours false). api() fusionne les surcharges (sur-approximation assumée,
        // cohérente avec le matching MITRE qui se fait déjà au niveau class->name).
        let key = m.api();
        if let Some(&idx) = self.index.get(&key) {
            idx
        } else {
            let idx = self.graph.add_node(m);
            self.index.insert(key, idx);
            idx
        }
    }

    pub fn add_call(&mut self, caller: MethodRef, callee: MethodRef, site: u64) {
        let a = self.node(caller);
        let b = self.node(callee);
        self.graph.add_edge(a, b, CallSite { offset: site });
    }

    /// `to` est-il atteignable depuis `from` dans le graphe d'appel ?
    /// Matching par sous-chaîne sur la forme `api()` (class->method).
    pub fn reaches(&self, from_api: &str, to_api: &str) -> bool {
        let starts: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| self.graph[n].api().contains(from_api))
            .collect();
        for start in starts {
            let mut bfs = Bfs::new(&self.graph, start);
            while let Some(nx) = bfs.next(&self.graph) {
                if self.graph[nx].api().contains(to_api) {
                    return true;
                }
            }
        }
        false
    }

    /// Au moins une méthode du graphe matche `api` (sous-chaîne).
    pub fn has_api(&self, api: &str) -> bool {
        self.graph.node_indices().any(|n| self.graph[n].api().contains(api))
    }

    /// Renvoie les nœuds entrypoint : méthode dont le nom est un callback framework
    /// ET dont la classe est un composant déclaré au manifest (ou une sous-classe
    /// directe — ici on matche par égalité de classe avec les composants).
    pub fn entrypoints(&self, components: &[String]) -> Vec<NodeIndex> {
        let comp: HashSet<&str> = components.iter().map(String::as_str).collect();
        self.graph
            .node_indices()
            .filter(|&n| {
                let m = &self.graph[n];
                ENTRYPOINT_CALLBACKS.contains(&m.name.as_str()) && comp.contains(m.class.as_str())
            })
            .collect()
    }

    /// Racines de repli quand aucun composant n'est déclaré (DEX brut sans
    /// manifeste) : TOUT nœud dont le nom est un callback framework, quelle que
    /// soit sa classe.
    ///
    /// Sur-approximation assumée — un `run` de SDK tiers ou une déclaration de
    /// callee non définie dans le DEX (`Landroid/os/Handler;->handleMessage`)
    /// deviennent racines. Elle est appliquée à l'identique sur tous les
    /// échantillons mesurés sous ce régime, donc les taux d'orphelins restent
    /// comparables entre eux ; ils ne le sont PAS avec ceux du régime manifest,
    /// d'où la colonne `roots_mode` qui accompagne chaque mesure.
    pub fn heuristic_entrypoints(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&n| ENTRYPOINT_CALLBACKS.contains(&self.graph[n].name.as_str()))
            .collect()
    }

    /// Cherche si une API (sous-chaîne de `class->name`) est atteignable depuis au
    /// moins un entrypoint validé par le manifest. Renvoie le statut + les chemins
    /// trouvés (un par entrypoint atteignant l'API), chaque chemin étant la liste
    /// ordonnée des signatures entrypoint -> ... -> API.
    pub fn reachability(&self, api: &str, entrypoints: &[NodeIndex]) -> Reachability {
        // Cibles : tous les nœuds matchant l'API.
        let targets: HashSet<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| self.graph[n].api().contains(api))
            .collect();
        if targets.is_empty() {
            return Reachability { reachable: false, paths: Vec::new() };
        }

        let mut paths = Vec::new();
        for &start in entrypoints {
            if let Some(path) = self.bfs_path(start, &targets) {
                paths.push(path);
            }
        }
        Reachability { reachable: !paths.is_empty(), paths }
    }

    /// Clôture dirigée R(M) : nœuds atteignables depuis au moins un entrypoint.
    /// BFS avant multi-source. Le complément = les orphelins.
    pub fn reachable_set(&self, entrypoints: &[NodeIndex]) -> HashSet<NodeIndex> {
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();
        for &e in entrypoints {
            if visited.insert(e) {
                queue.push_back(e);
            }
        }
        while let Some(cur) = queue.pop_front() {
            for nb in self.graph.neighbors_directed(cur, Direction::Outgoing) {
                if visited.insert(nb) {
                    queue.push_back(nb);
                }
            }
        }
        visited
    }

    /// Résout des racines `(classe, méthode)` en nœuds du graphe. Les nœuds sont
    /// keyés sur `api()` en interne ; on matche ici sur les champs `class`/`name`
    /// pour ne pas dépendre du format d'`api()`. Sert à réinjecter les handlers UI
    /// (`ui_callbacks`) comme racines supplémentaires avant `orphan_audit`.
    pub fn nodes_for(&self, roots: &[(String, String)]) -> Vec<NodeIndex> {
        let want: HashSet<(&str, &str)> =
            roots.iter().map(|(c, m)| (c.as_str(), m.as_str())).collect();
        self.graph
            .node_indices()
            .filter(|&n| {
                let m = &self.graph[n];
                want.contains(&(m.class.as_str(), m.name.as_str()))
            })
            .collect()
    }

    /// Nœuds `<clinit>` : initialiseurs statiques, exécutés par le runtime au
    /// chargement de leur classe — donc des racines implicites, jamais appelées
    /// par le code. À unir aux entrypoints avant `orphan_audit`, sinon toute la
    /// sous-arborescence d'init ressort orpheline en un bloc.
    pub fn clinit_nodes(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&n| self.graph[n].name == "<clinit>")
            .collect()
    }

    /// Partitionne les nœuds hors R(M) en composantes faiblement connexes.
    /// Décision d'orphelinage = atteignabilité DIRIGÉE ; la WCC ne sert qu'à
    /// grouper/décrire. `crossing_api` (sous-chaîne, ex. "loadLibrary") marque
    /// les îlots contenant le franchissement — vide pour ne rien marquer.
    pub fn orphan_audit(&self, entrypoints: &[NodeIndex], crossing_api: &str) -> OrphanReport {
        let reachable = self.reachable_set(entrypoints);
        let labels = self.wcc_labels();

        let mut by_wcc: HashMap<usize, Vec<NodeIndex>> = HashMap::new();
        for n in self.graph.node_indices() {
            if !reachable.contains(&n) {
                by_wcc.entry(labels[n.index()]).or_default().push(n);
            }
        }

        let mut islands: Vec<OrphanIsland> = Vec::new();
        for nodes in by_wcc.into_values() {
            let mut roots: Vec<String> = Vec::new();
            let mut author_nodes = 0usize;
            let mut touches = false;
            let mut by_prefix: HashMap<&str, usize> = HashMap::new();
            for &n in &nodes {
                let m = &self.graph[n];
                *by_prefix.entry(package_prefix(&m.class)).or_insert(0) += 1;
                if !is_allowlisted_pkg(&m.class) {
                    author_nodes += 1;
                }
                if !crossing_api.is_empty() && m.api().contains(crossing_api) {
                    touches = true;
                }
                // Degré entrant nul = aucun appelant dans tout le graphe = racine
                // implicite (callback semé par le framework, pas par le code).
                if self
                    .graph
                    .neighbors_directed(n, Direction::Incoming)
                    .next()
                    .is_none()
                {
                    roots.push(m.signature());
                }
            }
            roots.sort();
            // Comptage décroissant, nom croissant à égalité (ordre stable).
            let mut prefix_histogram: Vec<(String, usize)> = by_prefix
                .into_iter()
                .map(|(p, c)| (p.to_string(), c))
                .collect();
            prefix_histogram.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            islands.push(OrphanIsland {
                size: nodes.len(),
                author_nodes,
                touches_crossing: touches,
                prefix_histogram,
                roots,
            });
        }
        islands.sort_by(|a, b| {
            b.touches_crossing
                .cmp(&a.touches_crossing)
                .then(b.size.cmp(&a.size))
        });

        let orphan = self.graph.node_count() - reachable.len();
        OrphanReport {
            total_nodes: self.graph.node_count(),
            reachable: reachable.len(),
            orphan,
            islands,
        }
    }

    /// Co-atteignabilité : existe-t-il un nœud « pivot » d'où partent deux chemins
    /// atteignant respectivement `first_api` ET `second_api` ? C'est le cœur du
    /// motif « une même fonction chiffre puis envoie » : on ne prouve pas le flux de
    /// données (ce serait du taint), mais la co-localisation dans une même région
    /// de code, ce qui est bien plus fort que deux `reaches` indépendants.
    ///
    /// Implémentation : deux BFS INVERSÉS (arêtes entrantes) depuis les cibles de
    /// chaque API donnent l'ensemble de leurs ancêtres + la distance minimale. Le
    /// pivot est un nœud de l'intersection des deux ensembles d'ancêtres. Coût :
    /// 2× BFS sur le graphe, contre N×2 BFS avants dans l'approche naïve.
    ///
    /// Les `PivotConstraints` évitent le pivot trivial (un entrypoint-racine atteint
    /// tout son sous-arbre, rendant la co-atteignabilité vraie pour presque tout).
    pub fn reaches_both(
        &self,
        first_api: &str,
        second_api: &str,
        entrypoints: &[NodeIndex],
        c: &PivotConstraints,
    ) -> CoReach {
        let targets_a: HashSet<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| self.graph[n].api().contains(first_api))
            .collect();
        let targets_b: HashSet<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| self.graph[n].api().contains(second_api))
            .collect();
        if targets_a.is_empty() || targets_b.is_empty() {
            return CoReach::empty();
        }

        // Ancêtres + distance minimale à une cible, via BFS sur les arêtes entrantes.
        let dist_a = self.reverse_bfs_dist(&targets_a);
        let dist_b = self.reverse_bfs_dist(&targets_b);

        let ep: HashSet<NodeIndex> = entrypoints.iter().copied().collect();

        // Meilleur pivot qualifié = celui qui minimise (dist_a + dist_b) : le plus
        // « bas » / proche des deux primitifs, donc le plus plausible comme fonction
        // applicative unique enchaînant crypto et réseau.
        let mut best: Option<(u32, NodeIndex)> = None;
        for (&node, &da) in &dist_a {
            let db = match dist_b.get(&node) {
                Some(&d) => d,
                None => continue, // pas un ancêtre commun
            };
            // Garde-fou 1 : le pivot ne doit pas être un entrypoint-racine.
            if c.exclude_entrypoints && ep.contains(&node) {
                continue;
            }
            // Garde-fou 2 : le pivot doit être proche des deux primitifs.
            if let Some(maxd) = c.max_dist {
                if da > maxd || db > maxd {
                    continue;
                }
            }
            // Garde-fou 3 : le pivot ne doit pas appartenir à un SDK tiers bénin
            // (sinon on détecte la mécanique interne d'IronSource/GMS, pas l'app).
            if c.exclude_allowlisted && is_allowlisted_pkg(&self.graph[node].class) {
                continue;
            }
            let score = da + db;
            if best.map_or(true, |(s, _)| score < s) {
                best = Some((score, node));
            }
        }

        match best {
            Some((_, pivot)) => CoReach {
                reachable: true,
                pivot: Some(self.graph[pivot].signature()),
                path_first: self.bfs_path(pivot, &targets_a).unwrap_or_default(),
                path_second: self.bfs_path(pivot, &targets_b).unwrap_or_default(),
            },
            None => CoReach::empty(),
        }
    }

    /// Intimité (adaptée d'IntDroid, Wu et al. TOSEM 2021) entre deux primitifs
    /// via leurs pivots communs, calculée PAR COMPOSANTE FAIBLEMENT CONNEXE (WCC).
    ///
    /// Le CFG n'est pas connexe : `first_api` et `second_api` apparaissent dans
    /// plusieurs sous-systèmes disjoints (code app, chaque SDK…). Agréger les pivots
    /// sur tout le graphe mélangerait « à quel point IronSource couple crypto et
    /// réseau » avec « à quel point l'app le fait ». On isole donc par WCC :
    ///   - `n`   = pivots communs qualifiés DANS la WCC (fonctions atteignant les
    ///            deux primitifs), via intersection des ancêtres (2 BFS inversés) ;
    ///   - `ad`  = longueur moyenne du pont (dist_pivot->a + dist_pivot->b) ;
    ///   - `eff` = diamètre effectif DIRIGÉ (90e percentile) de la WCC, estimé par
    ///            multi-sweep échantillonné à budget adaptatif (cf.
    ///            `effective_diameter_directed`). Rend `ad` comparable entre
    ///            composantes/APK de tailles différentes.
    /// score brut = n / (ad + 1) ; score normalisé = n / (ad/eff + 1). On retourne
    /// la WCC au score normalisé maximal. Les deux scores + `eff` sont exposés pour
    /// calibration statistique en post-traitement (Mann-Whitney, cf. IntDroid).
    pub fn intimacy(
        &self,
        first_apis: &[String],
        second_apis: &[String],
        entrypoints: &[NodeIndex],
        c: &PivotConstraints,
    ) -> Intimacy {
        // Un nœud appartient au groupe s'il matche l'un des membres (API équivalentes).
        let prim_a: HashSet<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| {
                let a = self.graph[n].api();
                first_apis.iter().any(|x| a.contains(x.as_str()))
            })
            .collect();
        let prim_b: HashSet<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&n| {
                let a = self.graph[n].api();
                second_apis.iter().any(|x| a.contains(x.as_str()))
            })
            .collect();
        if prim_a.is_empty() || prim_b.is_empty() {
            return Intimacy::zero();
        }
        // GARDE-FOU couplage : la cible n'est PAS le primitif système lui-même mais
        // ses appelants directs non-allowlistés. Sans ça, un launcher applicatif
        // (findlink.loadFullIronSource) qui délègue à ironsource — lequel fait tout le
        // couplage crypto↔réseau — remontait comme pivot « applicatif » (faux positif).
        // On exige que le code qui INVOQUE crypto et réseau soit non-SDK.
        let targets_a = self.nonallowlisted_callers(&prim_a);
        let targets_b = self.nonallowlisted_callers(&prim_b);
        if targets_a.is_empty() || targets_b.is_empty() {
            return Intimacy::zero();
        }
        let dist_a = self.reverse_bfs_dist(&targets_a);
        let dist_b = self.reverse_bfs_dist(&targets_b);
        let ep: HashSet<NodeIndex> = entrypoints.iter().copied().collect();
        let labels = self.wcc_labels();

        // Regroupe les pivots qualifiés par WCC : (n, somme des ponts, meilleur pont,
        // nœud du meilleur pont). Le meilleur pont sert de pivot représentatif.
        let mut per_wcc: HashMap<usize, (usize, u64, u32, NodeIndex)> = HashMap::new();
        for (&node, &da) in &dist_a {
            let db = match dist_b.get(&node) {
                Some(&d) => d,
                None => continue,
            };
            if c.exclude_entrypoints && ep.contains(&node) {
                continue;
            }
            if let Some(maxd) = c.max_dist {
                if da > maxd || db > maxd {
                    continue;
                }
            }
            if c.exclude_allowlisted && is_allowlisted_pkg(&self.graph[node].class) {
                continue;
            }
            let bridge = da + db;
            let wid = labels[node.index()];
            let e = per_wcc.entry(wid).or_insert((0, 0, u32::MAX, node));
            e.0 += 1;
            e.1 += bridge as u64;
            if bridge < e.2 {
                e.2 = bridge;
                e.3 = node;
            }
        }
        if per_wcc.is_empty() {
            return Intimacy::zero();
        }

        // Pour chaque WCC candidate : diamètre effectif dirigé + score normalisé.
        // On retient la WCC au score normalisé maximal.
        let mut best: Option<(f64, usize, f64, f64, NodeIndex)> = None; // (norm, n, ad, eff, pivot)
        for (&wid, &(n, sum_bridge, _bb, pivot)) in &per_wcc {
            let members = wcc_members(&labels, wid);
            let eff = self.effective_diameter_directed(&members);
            let ad = sum_bridge as f64 / n as f64;
            let ad_rel = ad / eff.max(1.0);
            let score_norm = n as f64 / (ad_rel + 1.0);
            if best.map_or(true, |(s, ..)| score_norm > s) {
                best = Some((score_norm, n, ad, eff, pivot));
            }
        }

        let (score, n_pivots, avg_dist, eff_diam, pivot_node) = best.unwrap();
        let score_raw = n_pivots as f64 / (avg_dist + 1.0);
        Intimacy {
            score,
            score_raw,
            n_pivots,
            avg_dist,
            eff_diam,
            pivot: Some(self.graph[pivot_node].signature()),
            path_first: self.bfs_path(pivot_node, &targets_a).unwrap_or_default(),
            path_second: self.bfs_path(pivot_node, &targets_b).unwrap_or_default(),
        }
    }

    /// Labellisation des composantes faiblement connexes (WCC) par union-find sur
    /// les arêtes prises en NON-dirigé. Retourne `label[node.index()] = racine`
    /// (un index de nœud représentant la composante ; non dense mais unique/WCC).
    /// Recalculé à chaque appel — négligeable (O(E·α)) devant les BFS de diamètre ;
    /// à mémoïser (OnceCell) si le profilage le justifie.
    fn wcc_labels(&self) -> Vec<usize> {
        let n = self.graph.node_count();
        let mut uf = UnionFind::new(n);
        for e in self.graph.edge_indices() {
            if let Some((a, b)) = self.graph.edge_endpoints(e) {
                uf.union(a.index(), b.index());
            }
        }
        (0..n).map(|i| uf.find(i)).collect()
    }

    /// Diamètre effectif DIRIGÉ d'une composante : 90e percentile des distances
    /// dirigées finies, estimé par multi-sweep échantillonné à budget adaptatif.
    ///
    /// Méthode : on tire des sources dans la composante ; depuis chacune, un BFS
    /// FORWARD (arêtes sortantes) fournit toutes les distances dirigées finies
    /// (paires non atteignables jamais comptées — gère nativement l'asymétrie du
    /// dirigé). Les distances alimentent un histogramme d'où l'on lit le p90. Le
    /// budget `k` est adaptatif : on s'arrête quand le p90 se stabilise (invariant
    /// sur `PATIENCE` sources consécutives) après un minimum de sources, ou au cap.
    ///
    /// Note de méthode : le double-sweep classique estime le diamètre MAX ; pour un
    /// *percentile* on échantillonne des sources représentatives plutôt que de
    /// chaîner les sweeps vers la périphérie (qui biaiserait vers le haut).
    fn effective_diameter_directed(&self, members: &[NodeIndex]) -> f64 {
        let m = members.len();
        if m <= 1 {
            return 0.0;
        }
        const MIN_SOURCES: usize = 8;
        const MAX_SOURCES: usize = 64;
        const PATIENCE: u32 = 3;

        let exhaustive = m <= MIN_SOURCES;
        let cap = if exhaustive { m } else { MAX_SOURCES.min(m) };

        let mut hist: Vec<u64> = Vec::new();
        let mut total: u64 = 0;
        // RNG déterministe (xorshift) seedé par la taille : reproductible entre runs.
        let mut rng: u64 = 0x9E3779B97F4A7C15 ^ (m as u64).wrapping_mul(0x2545F4914F6CDD1D);
        let mut prev_p90 = u32::MAX;
        let mut stable: u32 = 0;
        let mut cur_p90 = 0u32;

        for used in 0..cap {
            let src = if exhaustive {
                members[used]
            } else {
                members[(xorshift64(&mut rng) as usize) % m]
            };
            self.accumulate_forward_dist(src, &mut hist, &mut total);
            cur_p90 = percentile_from_hist(&hist, total, 0.9);
            if used + 1 >= MIN_SOURCES {
                if cur_p90 == prev_p90 {
                    stable += 1;
                    if stable >= PATIENCE {
                        break;
                    }
                } else {
                    stable = 0;
                }
            }
            prev_p90 = cur_p90;
        }
        cur_p90 as f64
    }

    /// BFS forward (arêtes sortantes) depuis `source` : ajoute chaque distance
    /// dirigée finie (> 0) à l'histogramme `hist[d] += 1`. Reste dans la WCC de
    /// `source` par construction (une arête relie deux nœuds de la même WCC).
    fn accumulate_forward_dist(&self, source: NodeIndex, hist: &mut Vec<u64>, total: &mut u64) {
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(NodeIndex, u32)> = VecDeque::new();
        visited.insert(source);
        queue.push_back((source, 0));
        while let Some((cur, d)) = queue.pop_front() {
            if d > 0 {
                let di = d as usize;
                if hist.len() <= di {
                    hist.resize(di + 1, 0);
                }
                hist[di] += 1;
                *total += 1;
            }
            for nb in self.graph.neighbors_directed(cur, Direction::Outgoing) {
                if visited.insert(nb) {
                    queue.push_back((nb, d + 1));
                }
            }
        }
    }

    /// Appelants directs (prédécesseurs) NON-ALLOWLISTÉS d'un ensemble de nœuds.
    /// Recentre la cible d'une intimité du primitif système (API partagée, appelée
    /// aussi bien par un SDK bénin que par l'app) vers le code applicatif qui
    /// l'invoque réellement. C'est le garde-fou qui distingue « findlink délègue à
    /// ironsource qui chiffre » (appelant = ironsource, exclu) de « neunative chiffre
    /// depuis son propre code » (appelant = neunative, gardé).
    fn nonallowlisted_callers(&self, prims: &HashSet<NodeIndex>) -> HashSet<NodeIndex> {
        let mut callers = HashSet::new();
        for &p in prims {
            for pred in self.graph.neighbors_directed(p, Direction::Incoming) {
                if !is_allowlisted_pkg(&self.graph[pred].class) {
                    callers.insert(pred);
                }
            }
        }
        callers
    }

    /// BFS multi-source sur les arêtes ENTRANTES : pour chaque nœud ancêtre d'une
    /// cible, la distance (en sauts d'appel) à la cible la plus proche.
    fn reverse_bfs_dist(&self, targets: &HashSet<NodeIndex>) -> HashMap<NodeIndex, u32> {
        let mut dist: HashMap<NodeIndex, u32> = HashMap::new();
        let mut queue = VecDeque::new();
        for &t in targets {
            dist.insert(t, 0);
            queue.push_back(t);
        }
        while let Some(cur) = queue.pop_front() {
            let d = dist[&cur];
            for prev in self.graph.neighbors_directed(cur, Direction::Incoming) {
                if !dist.contains_key(&prev) {
                    dist.insert(prev, d + 1);
                    queue.push_back(prev);
                }
            }
        }
        dist
    }

    /// BFS de `start` vers le premier nœud de `targets`, avec reconstruction du
    /// chemin (liste de signatures). None si aucune cible atteinte.
    fn bfs_path(&self, start: NodeIndex, targets: &HashSet<NodeIndex>) -> Option<Vec<String>> {
        let mut visited = HashSet::new();
        let mut pred: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        let mut queue = VecDeque::new();
        visited.insert(start);
        queue.push_back(start);

        while let Some(cur) = queue.pop_front() {
            if targets.contains(&cur) {
                // Reconstruction du chemin start -> cur.
                let mut chain = vec![cur];
                let mut node = cur;
                while let Some(&p) = pred.get(&node) {
                    chain.push(p);
                    node = p;
                }
                chain.reverse();
                return Some(chain.into_iter().map(|n| self.graph[n].signature()).collect());
            }
            for next in self.graph.neighbors_directed(cur, Direction::Outgoing) {
                if visited.insert(next) {
                    pred.insert(next, cur);
                    queue.push_back(next);
                }
            }
        }
        None
    }
}

/// Résultat de reachability pour une API depuis les entrypoints.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Reachability {
    pub reachable: bool,
    /// Un chemin par entrypoint atteignant l'API (signatures ordonnées).
    pub paths: Vec<Vec<String>>,
}

/// Résultat d'`orphan_audit` : nœuds hors R(M), groupés en composantes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OrphanReport {
    pub total_nodes: usize,
    pub reachable: usize,
    pub orphan: usize,
    pub islands: Vec<OrphanIsland>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OrphanIsland {
    pub size: usize,
    /// Nombre de nœuds hors SDK tiers catalogué (code d'auteur probable). La
    /// PROPORTION author_nodes/size distingue un vrai îlot d'auteur d'un îlot
    /// tiers pollué par quelques nœuds — un OU booléen basculait tout un
    /// méga-îlot en « auteur » dès un seul nœud non catalogué.
    pub author_nodes: usize,
    /// Contient le franchissement recherché (ex. System.loadLibrary).
    pub touches_crossing: bool,
    /// De quoi l'îlot est FAIT : ses nœuds comptés par préfixe de package,
    /// comptage décroissant. Sur un méga-îlot de plusieurs milliers de nœuds,
    /// ni la taille ni la liste des racines ne disent s'il s'agit du code
    /// d'auteur, d'un SDK non catalogué ou d'un mélange — cette distribution si.
    pub prefix_histogram: Vec<(String, usize)>,
    /// Nœuds de degré entrant nul — les racines implicites de l'îlot.
    pub roots: Vec<String>,
}

/// Contraintes de qualification du pivot pour `reaches_both`. Les trois sont
/// combinables ; leurs valeurs proviennent de la règle (feature `co-reachable`).
#[derive(Debug, Clone)]
pub struct PivotConstraints {
    /// Le pivot ne peut pas être un entrypoint framework (évite la racine triviale).
    pub exclude_entrypoints: bool,
    /// Distance d'appel maximale du pivot à chacun des deux primitifs (None = ∞).
    pub max_dist: Option<u32>,
    /// Le pivot ne peut pas appartenir à un SDK tiers bénin catalogué.
    pub exclude_allowlisted: bool,
}

impl Default for PivotConstraints {
    fn default() -> Self {
        // Défaut prudent : on exige juste un pivot non-racine.
        Self { exclude_entrypoints: true, max_dist: None, exclude_allowlisted: false }
    }
}

/// Résultat de `reaches_both` : le pivot commun (s'il existe) et les deux chemins
/// pivot -> primitif, pour la traçabilité d'evidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CoReach {
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_first: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_second: Vec<String>,
}

impl CoReach {
    fn empty() -> Self {
        CoReach { reachable: false, pivot: None, path_first: Vec::new(), path_second: Vec::new() }
    }
}

/// Résultat de `intimacy` : les scores (brut + normalisé par diamètre effectif)
/// et leurs composantes, pour le tri/calibration en post-traitement, plus le
/// meilleur pivot de la WCC retenue (traçabilité).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Intimacy {
    /// Score normalisé = n / (ad/eff + 1). C'est le critère de match (vs min_score)
    /// et la mesure comparable entre composantes/APK.
    pub score: f64,
    /// Score brut = n / (ad + 1), non normalisé (distances absolues).
    pub score_raw: f64,
    /// Nombre de pivots communs qualifiés dans la WCC retenue.
    pub n_pivots: usize,
    /// Longueur moyenne du pont (dist_pivot->a + dist_pivot->b) dans la WCC.
    pub avg_dist: f64,
    /// Diamètre effectif dirigé (90e percentile) de la WCC retenue.
    pub eff_diam: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_first: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub path_second: Vec<String>,
}

impl Intimacy {
    fn zero() -> Self {
        Intimacy {
            score: 0.0,
            score_raw: 0.0,
            n_pivots: 0,
            avg_dist: 0.0,
            eff_diam: 0.0,
            pivot: None,
            path_first: Vec::new(),
            path_second: Vec::new(),
        }
    }
}

/// Préfixes de classes (descripteur Dalvik) de SDK tiers réputés bénins. Un pivot
/// dont la classe commence par l'un d'eux est de la plomberie de SDK, pas du code
/// applicatif — utilisé par le garde-fou `exclude-allowlisted`. Liste volontairement
/// conservatrice ; à externaliser dans un fichier de conf quand elle grossira.
const BENIGN_SDK_PREFIXES: &[&str] = &[
    "Lcom/google/android/gms/",
    "Lcom/google/android/exoplayer2/",
    "Lcom/google/firebase/",
    "Landroidx/",
    "Landroid/support/",
    "Lhelper/sqlite/",
    "Lcom/ironsource/",
    "Lcom/unity3d/",
    "Lokhttp3/",
    "Lokio/",
    "Lretrofit2/",
    "Lcom/squareup/",
    "Lio/reactivex/",
    "Lkotlin/",
    "Lkotlinx/",
];

fn is_allowlisted_pkg(class: &str) -> bool {
    BENIGN_SDK_PREFIXES.iter().any(|p| class.starts_with(p))
}

/// Préfixe de package d'un descripteur Dalvik : au plus les 3 premiers
/// segments, nom de classe exclu — `Lorg/xmlpush/v3/PushService;` ->
/// `Lorg/xmlpush/v3`, `Lcom/x/Foo$1;` -> `Lcom/x`. Une classe sans package
/// (`LFoo;`) est son propre préfixe.
///
/// Granularité volontairement grossière : on cherche à nommer les gros blocs
/// d'un îlot, pas à cataloguer ses paquets feuille.
fn package_prefix(class: &str) -> &str {
    let trimmed = class.strip_suffix(';').unwrap_or(class);
    let mut end = 0;
    for (i, _) in trimmed.match_indices('/').take(3) {
        end = i;
    }
    if end == 0 {
        trimmed
    } else {
        &trimmed[..end]
    }
}

/// Nœuds appartenant à la WCC `wid` (selon la labellisation `wcc_labels`).
fn wcc_members(labels: &[usize], wid: usize) -> Vec<NodeIndex> {
    labels
        .iter()
        .enumerate()
        .filter(|(_, &l)| l == wid)
        .map(|(i, _)| NodeIndex::new(i))
        .collect()
}

/// q-percentile d'une distribution de distances représentée en histogramme
/// (`hist[d]` = nombre d'observations à distance d). Retourne la plus petite
/// distance d telle que la masse cumulée atteigne `q × total`.
fn percentile_from_hist(hist: &[u64], total: u64, q: f64) -> u32 {
    if total == 0 {
        return 0;
    }
    let threshold = (q * total as f64).ceil() as u64;
    let mut cum = 0u64;
    for (d, &c) in hist.iter().enumerate() {
        cum += c;
        if cum >= threshold {
            return d as u32;
        }
    }
    hist.len().saturating_sub(1) as u32
}

/// PRNG xorshift64 : déterministe, non cryptographique, suffisant pour
/// l'échantillonnage reproductible des sources de sweep.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::package_prefix;

    #[test]
    fn prefix_stops_before_class_name() {
        assert_eq!(package_prefix("Lorg/xmlpush/v3/PushService;"), "Lorg/xmlpush/v3");
        assert_eq!(package_prefix("Lhelper/sqlite/database/DbHelper;"), "Lhelper/sqlite/database");
        // Au-delà de 3 segments, on tronque.
        assert_eq!(package_prefix("Lcom/google/android/gms/ads/Foo;"), "Lcom/google/android");
        // Moins de 3 segments : le nom de classe reste exclu.
        assert_eq!(package_prefix("Lcom/x/Foo$1;"), "Lcom/x");
        assert_eq!(package_prefix("LFoo;"), "LFoo");
    }
}
