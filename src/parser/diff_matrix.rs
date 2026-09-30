//! Comparaison **tous-contre-tous** d'un répertoire d'échantillons.
//!
//! POURQUOI UNE FONCTION ET PAS UNE BOUCLE SHELL
//! ---------------------------------------------
//! Une boucle qui appelle `--diff-strings` pour chaque paire reparse chaque
//! échantillon `n-1` fois. Ici chaque entrée est parsée **une seule fois**, puis
//! les `n(n-1)/2` comparaisons se font sur des ensembles en mémoire — des
//! intersections de `HashSet`, donc négligeables. Sur 115 échantillons, ça fait
//! 115 parsings au lieu de 13 110.
//!
//! DEUX MÉTRIQUES, DEUX QUESTIONS
//! ------------------------------
//!   - `opcodes` : Jaccard sur les empreintes de méthodes (séquence de
//!     mnémoniques). Répond à « même moteur ? » — insensible au renommage de
//!     package et à ProGuard.
//!   - `strings` : Jaccard sur le pool de chaînes, bruit structurel retiré.
//!     Répond à « mêmes constantes ? » — c'est là que se lisent endpoints, clés
//!     et jetons de marque. Voit les `static final`, contrairement aux diffs
//!     d'instructions.
//!
//! Les deux sont calculées d'un seul passage ; `--matrix-metric` choisit celle
//! qui pilote la matrice et le regroupement.
//!
//! FILTRE DES BIBLIOTHÈQUES
//! ------------------------
//! Sur un lot hétérogène, un `--diff-include` unique ne convient pas : le
//! préfixe applicatif change d'une génération à l'autre (`com/cocospy`,
//! `com/duiyun`, `com/dy`). On retombe donc sur l'**exclusion** des préfixes de
//! bibliothèques connus, comme le mode dégradé de `diff_dex`. C'est
//! sur-inclusif — du code tiers non listé passe — mais c'est appliqué
//! identiquement partout, donc les comparaisons restent entre elles cohérentes.

use crate::parser::diff_strings::classify;
use crate::parser::disasm::normalize;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

/// Métrique qui pilote la matrice et le regroupement.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Metric {
    /// Empreintes de méthodes — « même moteur ? »
    Opcodes,
    /// Pool de chaînes hors bruit — « mêmes constantes ? »
    Strings,
}

impl Metric {
    pub fn label(self) -> &'static str {
        match self {
            Self::Opcodes => "opcodes",
            Self::Strings => "chaînes",
        }
    }
}

pub struct MatrixOptions {
    pub metric: Metric,
    /// Substitutions appliquées aux descripteurs et aux chaînes avant
    /// comparaison (ex. `com/duiyun=com/dy`). Sans elles, deux namespaces
    /// différents divergent sur chaque descripteur.
    pub normalize: Vec<(String, String)>,
    /// Seuil de regroupement (lien simple). Deux échantillons au-dessus sont
    /// dans le même groupe, par transitivité.
    pub threshold: f64,
    pub recursive: bool,
    /// Nombre de paires listées dans le classement. 0 = toutes.
    pub top: usize,
}

impl Default for MatrixOptions {
    fn default() -> Self {
        Self {
            metric: Metric::Opcodes,
            normalize: Vec::new(),
            threshold: 0.85,
            recursive: false,
            top: 40,
        }
    }
}

/// Un échantillon, réduit à ce qui sert la comparaison. Parsé UNE fois.
struct Sample {
    name: String,
    opcodes: HashSet<u64>,
    strings: HashSet<String>,
    classes: usize,
    methods: usize,
}

#[derive(Serialize)]
pub struct SampleInfo {
    pub name: String,
    pub classes: usize,
    pub methods: usize,
    /// Chaînes distinctes hors bruit structurel.
    pub strings: usize,
}

#[derive(Serialize)]
pub struct PairScore {
    pub a: String,
    pub b: String,
    pub jaccard_opcodes: f64,
    pub jaccard_strings: f64,
    /// Chaînes divergentes hors bruit, les deux sens confondus. C'est le
    /// décompte « combien de constantes séparent ces deux binaires ».
    pub divergent_strings: usize,
}

#[derive(Serialize)]
pub struct MatrixReport {
    pub dir: String,
    pub metric: Metric,
    pub threshold: f64,
    pub samples: Vec<SampleInfo>,
    /// Échantillons illisibles, nommés plutôt que silencieusement absents.
    pub failed: Vec<String>,
    pub pairs: Vec<PairScore>,
    /// Groupes par lien simple au-dessus du seuil, sur la métrique choisie.
    pub groups: Vec<Vec<String>>,
}

// ── Extraction ───────────────────────────────────────────────────────────────

const LIB_PREFIXES: &[&str] = &[
    "Landroid/",
    "Landroidx/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ldalvik/",
    "Lrx/",
    "Lio/reactivex/",
    "Lokhttp3/",
    "Lokio/",
    "Lretrofit2/",
    "Lcom/google/",
    "Lcom/alibaba/",
    "Lcom/umeng/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/xmlpull/",
    "Luk/co/chrisjenx/",
    "Lgov/nist/",
];

fn is_application_class(descriptor: &str) -> bool {
    !LIB_PREFIXES.iter().any(|p| descriptor.starts_with(p))
}

/// Parse un échantillon et n'en garde que les deux ensembles utiles.
fn load(path: &Path, opts: &MatrixOptions) -> Result<Sample> {
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "?".into());

    // ── Empreintes de méthodes ──
    let (dex_paths, _tmp) = collect_dex_paths(path)?;
    let mut opcodes = HashSet::new();
    let mut classes = 0usize;
    let mut methods = 0usize;

    for dp in &dex_paths {
        let dex = match crate::parser::dex_facade::DexBin::open(dp) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(sample = %name, error = %e, "dex illisible, ignoré");
                continue;
            }
        };
        for class in dex.classes() {
            let Ok(class) = class else { continue };
            let descriptor = normalize(class.descriptor, &opts.normalize);
            if !is_application_class(&descriptor) {
                continue;
            }
            classes += 1;
            for method in &class.methods {
                let Some(code) = &method.code else { continue };
                let Ok(instructions) = dex_bytecode::decode_all(code.insns, 0) else {
                    continue;
                };
                let mut h = DefaultHasher::new();
                for ins in &instructions {
                    ins.mnemonic().hash(&mut h);
                }
                opcodes.insert(h.finish());
                methods += 1;
            }
        }
    }

    // ── Pool de chaînes, bruit structurel retiré ──
    let pool = super::dex_strings::extract_any(path)
        .with_context(|| format!("pool de chaînes de {}", path.display()))?;
    let strings: HashSet<String> = pool
        .strings
        .iter()
        .map(|s| normalize(s, &opts.normalize))
        .filter(|s| !classify(s).is_noise())
        .collect();

    Ok(Sample {
        name,
        opcodes,
        strings,
        classes,
        methods,
    })
}

fn jaccard<T: Eq + Hash>(a: &HashSet<T>, b: &HashSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

// ── Traitement ───────────────────────────────────────────────────────────────

pub fn run(dir: &Path, opts: &MatrixOptions) -> Result<MatrixReport> {
    let inputs = super::dyn_entrypoints::collect_inputs(dir, opts.recursive)?;
    if inputs.len() < 2 {
        bail!(
            "{} contient {} entrée(s) analysable(s) — il en faut au moins deux",
            dir.display(),
            inputs.len()
        );
    }

    // Parsing : UNE fois par échantillon. C'est tout le coût du mode.
    let mut samples = Vec::new();
    let mut failed = Vec::new();
    for (i, p) in inputs.iter().enumerate() {
        eprintln!("[{}/{}] {}", i + 1, inputs.len(), p.display());
        // Un DEX abîmé peut faire paniquer le crate : on isole pour qu'un
        // échantillon pourri ne tue pas le lot.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| load(p, opts)));
        match outcome {
            Ok(Ok(s)) => samples.push(s),
            Ok(Err(e)) => {
                eprintln!("        [FAIL] {e:#}");
                failed.push(p.display().to_string());
            }
            Err(_) => {
                eprintln!("        [PANIC] parsing abandonné");
                failed.push(p.display().to_string());
            }
        }
    }
    if samples.len() < 2 {
        bail!("moins de deux échantillons lisibles — rien à comparer");
    }

    // Comparaisons : n(n-1)/2 intersections d'ensembles, en mémoire.
    let n = samples.len();
    let mut pairs = Vec::with_capacity(n * (n - 1) / 2);
    let mut sim = vec![vec![1.0f64; n]; n];

    for i in 0..n {
        for j in (i + 1)..n {
            let jo = jaccard(&samples[i].opcodes, &samples[j].opcodes);
            let js = jaccard(&samples[i].strings, &samples[j].strings);
            let div = samples[i].strings.difference(&samples[j].strings).count()
                + samples[j].strings.difference(&samples[i].strings).count();

            let m = match opts.metric {
                Metric::Opcodes => jo,
                Metric::Strings => js,
            };
            sim[i][j] = m;
            sim[j][i] = m;

            pairs.push(PairScore {
                a: samples[i].name.clone(),
                b: samples[j].name.clone(),
                jaccard_opcodes: jo,
                jaccard_strings: js,
                divergent_strings: div,
            });
        }
    }

    // Classement par la métrique choisie, décroissant.
    pairs.sort_by(|x, y| {
        let (a, b) = match opts.metric {
            Metric::Opcodes => (y.jaccard_opcodes, x.jaccard_opcodes),
            Metric::Strings => (y.jaccard_strings, x.jaccard_strings),
        };
        a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
    });

    let groups = single_linkage(&sim, &samples, opts.threshold);

    Ok(MatrixReport {
        dir: dir.display().to_string(),
        metric: opts.metric,
        threshold: opts.threshold,
        samples: samples
            .iter()
            .map(|s| SampleInfo {
                name: s.name.clone(),
                classes: s.classes,
                methods: s.methods,
                strings: s.strings.len(),
            })
            .collect(),
        failed,
        pairs,
        groups,
    })
}

/// Regroupement par **lien simple** : deux échantillons au-dessus du seuil sont
/// dans le même groupe, et la relation est propagée par transitivité.
///
/// ⚠️ Le lien simple est volontairement permissif — il suffit d'UNE arête
/// au-dessus du seuil pour fusionner deux groupes. C'est ce qu'on veut ici
/// (trouver les lignées), mais ça peut enchaîner deux familles distinctes via un
/// intermédiaire ambigu. Les groupes sont une aide à la lecture, pas une preuve.
fn single_linkage(sim: &[Vec<f64>], samples: &[Sample], threshold: f64) -> Vec<Vec<String>> {
    let n = samples.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        if parent[x] != x {
            let r = find(parent, parent[x]);
            parent[x] = r;
        }
        parent[x]
    }

    // `sim` est un paramètre : rien ne garantit que sa taille vaut `n`. Itérer
    // dessus au lieu de `0..n` remplacerait un panic par un regroupement faux.
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        for j in (i + 1)..n {
            if sim[i][j] >= threshold {
                let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }

    let mut buckets: std::collections::HashMap<usize, Vec<String>> = Default::default();
    for (i, s) in samples.iter().enumerate() {
        let r = find(&mut parent, i);
        buckets.entry(r).or_default().push(s.name.clone());
    }
    let mut groups: Vec<Vec<String>> = buckets.into_values().collect();
    for g in groups.iter_mut() {
        g.sort();
    }
    // Les groupes les plus gros d'abord — c'est là qu'est l'information.
    groups.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
    groups
}

// ── Entrées ──────────────────────────────────────────────────────────────────

fn collect_dex_paths(input: &Path) -> Result<(Vec<PathBuf>, Option<tempfile::TempDir>)> {
    use std::io::Read;

    let mut magic = [0u8; 4];
    {
        let mut f =
            std::fs::File::open(input).with_context(|| format!("open {}", input.display()))?;
        if f.read(&mut magic)? < 4 {
            bail!("{} trop court", input.display());
        }
    }
    if &magic == b"dex\n" {
        return Ok((vec![input.to_path_buf()], None));
    }
    if magic == [0x50, 0x4b, 0x03, 0x04] {
        let tmp = tempfile::tempdir().context("create tempdir")?;
        let file = std::fs::File::open(input)?;
        let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
        let mut paths = Vec::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)?;
            let name = entry.name().to_string();
            if !(name.starts_with("classes") && name.ends_with(".dex")) {
                continue;
            }
            let dest = tmp.path().join(name.replace('/', "__"));
            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf)?;
            std::fs::write(&dest, &buf)?;
            paths.push(dest);
        }
        if paths.is_empty() {
            bail!("aucun classes*.dex dans {}", input.display());
        }
        return Ok((paths, Some(tmp)));
    }
    bail!("{} n'est ni un DEX ni un APK", input.display())
}

// ── Rendu ────────────────────────────────────────────────────────────────────

pub fn render(r: &MatrixReport, opts: &MatrixOptions) -> String {
    let n = r.samples.len();
    let mut s = String::new();

    s.push_str(&format!(
        "== Matrice de similarité — métrique « {} » ==\n\n",
        r.metric.label()
    ));
    s.push_str(&format!("Répertoire  {}\n", r.dir));
    s.push_str(&format!(
        "Échantillons {}   paires {}   seuil de groupe {:.2}\n\n",
        n,
        r.pairs.len(),
        r.threshold
    ));

    // ── Légende des indices ──
    s.push_str("Échantillons :\n");
    for (i, si) in r.samples.iter().enumerate() {
        s.push_str(&format!(
            "  {:>2}  {:<28} {:>5} classes  {:>6} méthodes  {:>6} chaînes\n",
            i + 1,
            si.name,
            si.classes,
            si.methods,
            si.strings
        ));
    }

    if !r.failed.is_empty() {
        s.push_str(&format!("\nIllisibles ({}) :\n", r.failed.len()));
        for f in &r.failed {
            s.push_str(&format!("  {f}\n"));
        }
    }

    // ── Matrice triangulaire ──
    // Reconstruite depuis les paires : la lecture reste exacte même si l'ordre
    // du classement a changé.
    let idx = |name: &str| r.samples.iter().position(|x| x.name == name);
    let mut m = vec![vec![1.0f64; n]; n];
    for p in &r.pairs {
        if let (Some(i), Some(j)) = (idx(&p.a), idx(&p.b)) {
            let v = match r.metric {
                Metric::Opcodes => p.jaccard_opcodes,
                Metric::Strings => p.jaccard_strings,
            };
            m[i][j] = v;
            m[j][i] = v;
        }
    }

    s.push_str("\nMatrice (valeurs ×100, diagonale omise) :\n     ");
    for i in 0..n {
        s.push_str(&format!("{:>4}", i + 1));
    }
    s.push('\n');
    for (i, row) in m.iter().enumerate() {
        s.push_str(&format!("  {:>2} ", i + 1));
        for (j, v) in row.iter().enumerate() {
            if i == j {
                s.push_str("   .");
            } else {
                s.push_str(&format!("{:>4.0}", v * 100.0));
            }
        }
        s.push('\n');
    }

    // ── Classement des paires ──
    let shown = if opts.top == 0 {
        r.pairs.len()
    } else {
        opts.top.min(r.pairs.len())
    };
    s.push_str(&format!(
        "\nPaires, {} décroissant ({} sur {}) :\n",
        r.metric.label(),
        shown,
        r.pairs.len()
    ));
    s.push_str(&format!(
        "  {:<26} {:<26} {:>8} {:>8} {:>10}\n",
        "A", "B", "opcodes", "chaînes", "div. str."
    ));
    for p in r.pairs.iter().take(shown) {
        s.push_str(&format!(
            "  {:<26} {:<26} {:>8.4} {:>8.4} {:>10}\n",
            truncate(&p.a, 26),
            truncate(&p.b, 26),
            p.jaccard_opcodes,
            p.jaccard_strings,
            p.divergent_strings
        ));
    }

    // ── Groupes ──
    s.push_str(&format!(
        "\nGroupes (lien simple, {} ≥ {:.2}) :\n",
        r.metric.label(),
        r.threshold
    ));
    for (k, g) in r.groups.iter().enumerate() {
        if g.len() == 1 {
            s.push_str(&format!("  [{}] isolé : {}\n", k + 1, g[0]));
        } else {
            s.push_str(&format!(
                "  [{}] {} membres : {}\n",
                k + 1,
                g.len(),
                g.join(", ")
            ));
        }
    }

    s.push_str(&format!(
        "\n{}\n",
        "⚠ Le lien simple fusionne deux groupes dès UNE arête au-dessus du seuil.\n\
         \x20 Les groupes aident à lire, ils ne prouvent rien — vérifier les paires."
    ));

    s
}

fn truncate(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    format!(
        "{}…",
        s.chars().take(max.saturating_sub(1)).collect::<String>()
    )
}

/// Légende (`--diff-matrix DIR --legend`).
pub fn legend() -> String {
    "\
== Matrice de similarité (--diff-matrix) — légende ==

PRINCIPE : chaque échantillon du répertoire est parsé UNE SEULE FOIS et réduit à
deux ensembles ; les n(n-1)/2 comparaisons sont ensuite des intersections en
mémoire. Sur 115 échantillons : 115 parsings au lieu de 13 110.

Métriques (les deux sont toujours calculées ; --matrix-metric choisit celle qui
pilote la matrice et le regroupement) :
  opcodes   Jaccard sur les empreintes de méthodes — séquence de mnémoniques,
            opérandes jetées. Répond à « même moteur ? ». Insensible au
            renommage de package et à ProGuard.
  chaînes   Jaccard sur le pool de chaînes, bruit structurel retiré. Répond à
            « mêmes constantes ? ». Voit les valeurs de champs `static final`
            (endpoints C2), invisibles aux diffs d'instructions.

Colonne `div. str.` : nombre de chaînes divergentes hors bruit, les deux sens
confondus. C'est le décompte « combien de constantes séparent ces deux
binaires » — sur un couple de marques d'un même atelier, il est très petit.

Options :
  --matrix-metric opcodes|strings   Défaut : opcodes.
  --matrix-normalize A=B            Substitution appliquée aux descripteurs ET
                                    aux chaînes avant comparaison. Répétable.
                                    Indispensable sur un lot multi-namespace
                                    (com/duiyun ↔ com/dy), sinon les
                                    descripteurs font chuter la similarité.
  --matrix-threshold F              Seuil de regroupement. Défaut 0.85.
  --matrix-top N                    Paires listées. 0 = toutes. Défaut 40.
  --recursive                       Descendre dans les sous-répertoires.

FILTRE DES BIBLIOTHÈQUES : sur un lot hétérogène, un --diff-include unique ne
convient pas (le préfixe applicatif change selon la génération). On applique donc
l'exclusion des préfixes de bibliothèques connus, identiquement partout. C'est
sur-inclusif, mais cohérent d'une paire à l'autre.

⚠ REGROUPEMENT : le lien simple fusionne deux groupes dès qu'UNE arête dépasse le
seuil. C'est ce qu'on veut pour trouver des lignées, mais un intermédiaire
ambigu peut enchaîner deux familles distinctes. Les groupes sont une aide à la
lecture, pas une preuve — toujours vérifier les paires qui les relient.\
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[u64]) -> HashSet<u64> {
        v.iter().copied().collect()
    }

    #[test]
    fn jaccard_bornes() {
        assert_eq!(jaccard(&set(&[1, 2, 3]), &set(&[1, 2, 3])), 1.0);
        assert_eq!(jaccard(&set(&[1, 2]), &set(&[3, 4])), 0.0);
        assert_eq!(jaccard(&set(&[]), &set(&[])), 1.0);
        assert!((jaccard(&set(&[1, 2, 3]), &set(&[2, 3, 4])) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn lien_simple_propage_par_transitivite() {
        // a~b et b~c au-dessus du seuil, mais a et c en dessous : un seul groupe.
        let sim = vec![
            vec![1.0, 0.9, 0.1],
            vec![0.9, 1.0, 0.9],
            vec![0.1, 0.9, 1.0],
        ];
        let samples: Vec<Sample> = ["a", "b", "c"]
            .iter()
            .map(|n| Sample {
                name: n.to_string(),
                opcodes: HashSet::new(),
                strings: HashSet::new(),
                classes: 0,
                methods: 0,
            })
            .collect();
        let g = single_linkage(&sim, &samples, 0.85);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0], vec!["a", "b", "c"]);
    }

    #[test]
    fn lien_simple_separe_sous_le_seuil() {
        let sim = vec![vec![1.0, 0.2], vec![0.2, 1.0]];
        let samples: Vec<Sample> = ["a", "b"]
            .iter()
            .map(|n| Sample {
                name: n.to_string(),
                opcodes: HashSet::new(),
                strings: HashSet::new(),
                classes: 0,
                methods: 0,
            })
            .collect();
        assert_eq!(single_linkage(&sim, &samples, 0.85).len(), 2);
    }
}
