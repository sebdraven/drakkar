//! Diff sémantique de deux DEX (ou APK) par empreinte d'opcodes.
//!
//! But : chiffrer « même arbre source » entre deux builds d'un même produit qui
//! diffèrent par le nom de package (ex. `com.dy` ↔ `com.duiyun`) et/ou par
//! ProGuard, sans se laisser tromper par ces renommages.
//!
//! Méthode — **Shinho Lee, Wookhyun Jung, Sangwon Kim, Eui Tak Kim, « Android
//! Malware Similarity Clustering using Method based Opcode Sequence and Jaccard
//! Index », Proc. 2019 International Conference on Information and Communication
//! Technology Convergence (ICTC), 16-18 octobre 2019, p. 178-183** (référence
//! vérifiée à la source le 27/07/2026) : on désassemble le DEX, et de chaque
//! **méthode** on ne retient que la **séquence de mnémoniques d'opcodes** —
//! registres, index de string/type/méthode et autres opérandes sont jetés. C'est
//! l'invariant : changer le nom du package/classe/méthode ou ajouter une
//! variable modifie tout le bytecode mais PAS l'opcode. Une méthode devient donc
//! un « mot » (le hash de sa séquence d'opcodes), un DEX une « phrase » (la
//! liste de ses mots).
//!
//! La même équipe a publié **Dexofuzzy** (Virus Bulletin, 25 octobre 2019), un
//! fuzzy hash ssdeep sur le flux d'opcodes, avec une implémentation Python de
//! référence sur PyPI — utilisable comme contrôle croisé de ce module.
//!
//! Deux niveaux de mesure sont produits :
//!   - GLOBAL : indice de Jaccard sur l'ensemble des empreintes de méthodes
//!     (ordre-insensible) = « part de méthodes identiques » ; plus un Jaccard sur
//!     les n-grammes de mots façon papier (défaut n=2), comparable à la
//!     littérature (seuil empirique 0.85).
//!   - PAR CLASSE : appariement des classes par empreinte (hash du multiset trié
//!     de leurs empreintes de méthodes) — exact d'abord, puis flou par Jaccard —
//!     pour dire lesquelles sont identiques, proches, ou propres à un seul côté.
//!
//! IMPORTANT — retirer le code des bibliothèques est une condition de validité,
//! pas une option : sinon les libs communes (RxJava, OkHttp…) gonflent
//! artificiellement la similarité. Passer `--diff-include` avec les préfixes
//! applicatifs des DEUX côtés est la façon la plus sûre de le garantir.
//! L'argument est posé par « Android Malware Clustering Through Malicious
//! Payload Mining », RAID 2017 — ⚠️ liste d'auteurs à relever sur le PDF avant
//! toute citation. (Une version antérieure de cet en-tête portait « Argus 2017 »,
//! qui n'est PAS une citation : c'était un raccourci vers le laboratoire Argus,
//! rattachement non confirmé.)

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Paramètres du diff.
pub struct DiffOptions {
    /// Préfixes de descripteurs Dalvik à INCLURE (ex. `Lcom/dy/`, `Lcom/duiyun/`).
    /// Si non vide, seules les classes dont le descripteur commence par l'un
    /// d'eux sont comparées (mode inclusion). Si vide, on retombe sur une
    /// exclusion best-effort des bibliothèques connues.
    pub include_prefixes: Vec<String>,
    /// Seuil de Jaccard (sur les méthodes) au-delà duquel deux classes non
    /// identiques sont dites « proches ».
    /// ⚠️ 0.85 est un paramètre DE CET OUTIL, pas un seuil publié : il n'a pas
    /// été retrouvé dans le papier ICTC. Ne pas l'attribuer à la littérature.
    pub threshold: f64,
    /// Taille de fenêtre pour le n-gram global façon papier (défaut 2).
    pub ngram: usize,
    /// Substitutions `(depuis, vers)` appliquées au descripteur de classe pour
    /// construire la CLÉ D'APPARIEMENT (ex. `com/duiyun` → `com/dy`).
    ///
    /// N'affecte ni les empreintes, ni les mesures, ni les noms affichés —
    /// uniquement la mise en correspondance des classes. Indispensable entre
    /// deux lots de namespaces différents : sans elle, l'appariement par nom ne
    /// peut rien apparier et on retombe sur le glouton par empreinte.
    pub normalize: Vec<(String, String)>,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            include_prefixes: Vec::new(),
            threshold: 0.85,
            ngram: 2,
            normalize: Vec::new(),
        }
    }
}

/// Empreinte d'une classe applicative : son nom, l'ensemble des empreintes de ses
/// méthodes (hash de séquence d'opcodes), et un hash agrégé du multiset trié.
struct ClassPrint {
    name: String,
    /// Nom normalisé par `DiffOptions::normalize`, utilisé UNIQUEMENT comme clé
    /// d'appariement. `name` reste brut pour l'affichage, pour qu'on lise bien
    /// `Lcom/dy/g;` ↔ `Lcom/duiyun/g;` dans le rapport.
    key: String,
    /// Empreintes de méthodes, ordre de lecture conservé (pour le n-gram global).
    method_seq: Vec<u64>,
    /// Même chose en ensemble, pour le Jaccard par classe.
    method_set: HashSet<u64>,
    /// Hash du multiset trié de method_seq : deux classes au même code (à
    /// l'ordre des méthodes près) ont le même class_hash.
    class_hash: u64,
}

/// Une paire de classes appariées de façon non exacte, avec leur similarité.
#[derive(Serialize)]
pub struct NearPair {
    pub class_a: String,
    pub class_b: String,
    pub jaccard: f64,
    pub methods_a: usize,
    pub methods_b: usize,
}

/// Une paire de classes strictement identiques (même empreinte de code).
#[derive(Serialize)]
pub struct IdenticalPair {
    pub class_a: String,
    pub class_b: String,
    pub methods: usize,
}

/// Rapport de diff, sérialisable.
#[derive(Serialize)]
pub struct DiffReport {
    pub input_a: String,
    pub input_b: String,
    /// Classes applicatives retenues (après filtre) de chaque côté.
    pub classes_a: usize,
    pub classes_b: usize,
    /// Méthodes (avec code) retenues de chaque côté.
    pub methods_a: usize,
    pub methods_b: usize,

    // ── Mesures globales ──
    /// Jaccard sur l'ensemble des empreintes de méthodes, ordre-insensible.
    /// C'est la réponse directe à « quelle part de méthodes est identique ».
    pub jaccard_methods: f64,
    /// Jaccard sur les n-grammes de mots-méthodes (ordre-sensible), façon papier.
    pub jaccard_ngram: f64,
    /// n utilisé pour le n-gram ci-dessus.
    pub ngram: usize,

    // ── Appariement par classe ──
    pub threshold: f64,
    pub identical_classes: usize,
    /// Parmi les identiques : appariées par NOM normalisé **et** empreinte. Le
    /// cas normal.
    pub identical_by_name: usize,
    /// Parmi les identiques : appariées par empreinte SEULE, noms différents.
    /// C'est un renommage RÉEL de classe — à regarder.
    ///
    /// ⚠️ C'est aussi là que se logeaient les faux appariements avant le
    /// correctif : les POJO (`<init>` + accesseurs) partagent tous la même
    /// empreinte, et un glouton par empreinte seule les chaîne en cycles de
    /// permutation. Un chiffre élevé ici sans renommage attendu doit alerter.
    pub identical_by_hash: usize,
    pub near_classes: usize,
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
    /// Détail des classes identiques (peut être long ; utile pour voir
    /// `Lcom/dy/g;` ↔ `Lcom/duiyun/g;`).
    pub identical: Vec<IdenticalPair>,
    /// Détail des classes proches, triées par Jaccard décroissant.
    pub near: Vec<NearPair>,
}

/// Point d'entrée : diff de deux entrées (DEX brut ou APK).
pub fn run(input_a: &Path, input_b: &Path, opts: &DiffOptions) -> Result<DiffReport> {
    let (a, _tmp_a) = load_class_prints(input_a, opts)?;
    let (b, _tmp_b) = load_class_prints(input_b, opts)?;

    let methods_a: usize = a.iter().map(|c| c.method_seq.len()).sum();
    let methods_b: usize = b.iter().map(|c| c.method_seq.len()).sum();

    // ── Global : ensembles d'empreintes de méthodes ──
    let set_a: HashSet<u64> = a.iter().flat_map(|c| c.method_set.iter().copied()).collect();
    let set_b: HashSet<u64> = b.iter().flat_map(|c| c.method_set.iter().copied()).collect();
    let jaccard_methods = jaccard(&set_a, &set_b);

    // ── Global : n-grammes de mots-méthodes (ordre de lecture) ──
    let seq_a: Vec<u64> = a.iter().flat_map(|c| c.method_seq.iter().copied()).collect();
    let seq_b: Vec<u64> = b.iter().flat_map(|c| c.method_seq.iter().copied()).collect();
    let ngram = opts.ngram.max(1);
    let ng_a = ngrams(&seq_a, ngram);
    let ng_b = ngrams(&seq_b, ngram);
    let jaccard_ngram = jaccard(&ng_a, &ng_b);

    // ── Appariement par classe, en QUATRE passes ordonnées ──
    //
    // 🔴 Le NOM passe AVANT l'empreinte. Les DTO (`<init>` + `getX` + `setX`)
    // ont tous la MÊME séquence de mnémoniques, donc la même empreinte de
    // classe : un glouton par empreinte seule les chaîne en CYCLE DE
    // PERMUTATION et apparie des classes sans rapport. Mesuré sur safespy lot A
    // ↔ lot B : trois cycles disjoints de 5, 12 et 3 classes dans `*.json`.
    // Les mesures globales (Jaccard) n'en souffraient pas — le multiset est le
    // même — mais la liste `identical` était fausse classe par classe.
    let mut b_by_hash: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut b_by_key: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, c) in b.iter().enumerate() {
        b_by_hash.entry(c.class_hash).or_default().push(i);
        b_by_key.entry(c.key.as_str()).or_default().push(i);
    }
    let mut b_matched = vec![false; b.len()];
    let mut a_matched = vec![false; a.len()];

    let mut identical = Vec::new();
    let mut identical_by_name = 0usize;
    let mut identical_by_hash = 0usize;
    let mut near = Vec::new();
    let mut only_in_a = Vec::new();

    // PASSE 1 — même clé de nom ET même empreinte.
    for (ia, ca) in a.iter().enumerate() {
        let found = b_by_key.get(ca.key.as_str()).and_then(|v| {
            v.iter()
                .copied()
                .find(|&i| !b_matched[i] && b[i].class_hash == ca.class_hash)
        });
        if let Some(i) = found {
            a_matched[ia] = true;
            b_matched[i] = true;
            identical_by_name += 1;
            identical.push(IdenticalPair {
                class_a: ca.name.clone(),
                class_b: b[i].name.clone(),
                methods: ca.method_seq.len(),
            });
        }
    }

    // PASSE 2 — même empreinte, nom différent : renommage réel de classe.
    for (ia, ca) in a.iter().enumerate() {
        if a_matched[ia] {
            continue;
        }
        let found = b_by_hash
            .get(&ca.class_hash)
            .and_then(|v| v.iter().copied().find(|&i| !b_matched[i]));
        if let Some(i) = found {
            a_matched[ia] = true;
            b_matched[i] = true;
            identical_by_hash += 1;
            identical.push(IdenticalPair {
                class_a: ca.name.clone(),
                class_b: b[i].name.clone(),
                methods: ca.method_seq.len(),
            });
        }
    }

    // PASSE 3 — appariement flou : meilleure classe B non prise, par Jaccard sur
    // les ensembles de méthodes.
    for (ia, ca) in a.iter().enumerate() {
        if a_matched[ia] {
            continue;
        }
        let mut best: Option<(usize, f64)> = None;
        for (i, cb) in b.iter().enumerate() {
            if b_matched[i] {
                continue;
            }
            let j = jaccard(&ca.method_set, &cb.method_set);
            if best.map_or(true, |(_, bj)| j > bj) {
                best = Some((i, j));
            }
        }
        if let Some((i, j)) = best {
            if j >= opts.threshold {
                a_matched[ia] = true;
                b_matched[i] = true;
                near.push(NearPair {
                    class_a: ca.name.clone(),
                    class_b: b[i].name.clone(),
                    jaccard: j,
                    methods_a: ca.method_seq.len(),
                    methods_b: b[i].method_seq.len(),
                });
            }
        }
    }

    // PASSE 4 — sans contrepartie.
    for (ia, ca) in a.iter().enumerate() {
        if !a_matched[ia] {
            only_in_a.push(ca.name.clone());
        }
    }

    let only_in_b: Vec<String> = b
        .iter()
        .enumerate()
        .filter(|(i, _)| !b_matched[*i])
        .map(|(_, c)| c.name.clone())
        .collect();

    near.sort_by(|x, y| y.jaccard.partial_cmp(&x.jaccard).unwrap_or(std::cmp::Ordering::Equal));

    Ok(DiffReport {
        input_a: input_a.display().to_string(),
        input_b: input_b.display().to_string(),
        classes_a: a.len(),
        classes_b: b.len(),
        methods_a,
        methods_b,
        jaccard_methods,
        jaccard_ngram,
        ngram,
        threshold: opts.threshold,
        identical_classes: identical.len(),
        identical_by_name,
        identical_by_hash,
        near_classes: near.len(),
        only_in_a,
        only_in_b,
        identical,
        near,
    })
}

/// Indice de Jaccard sur deux ensembles : |A∩B| / |A∪B|. Vaut 1.0 si les deux
/// sont vides (deux « riens » sont identiques).
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

/// Ensemble des n-grammes (hachés) d'une séquence de mots. Fenêtre glissante de
/// taille n ; si la séquence est plus courte que n, elle donne un unique n-gram
/// (la séquence entière), pour ne pas perdre les toutes petites classes.
fn ngrams(seq: &[u64], n: usize) -> HashSet<u64> {
    let mut set = HashSet::new();
    if seq.is_empty() {
        return set;
    }
    if seq.len() < n {
        set.insert(hash_window(seq));
        return set;
    }
    for w in seq.windows(n) {
        set.insert(hash_window(w));
    }
    set
}

fn hash_window(w: &[u64]) -> u64 {
    let mut h = DefaultHasher::new();
    w.hash(&mut h);
    h.finish()
}

/// Charge les empreintes de classes applicatives d'une entrée (DEX brut ou APK).
/// Retourne aussi le tempdir éventuel, à garder vivant tant qu'on lit les DEX.
fn load_class_prints(
    input: &Path,
    opts: &DiffOptions,
) -> Result<(Vec<ClassPrint>, Option<tempfile::TempDir>)> {
    let (dex_paths, tmp) = collect_dex_paths(input)?;
    let mut prints = Vec::new();
    for dp in &dex_paths {
        collect_from_dex(dp, opts, &mut prints)
            .with_context(|| format!("parse {}", dp.display()))?;
    }
    if prints.is_empty() {
        bail!(
            "aucune classe applicative retenue dans {} — vérifie --diff-include \
             (préfixes au format descripteur Dalvik, ex. Lcom/dy/)",
            input.display()
        );
    }
    Ok((prints, tmp))
}

/// Une classe est-elle applicative (à comparer) selon les options ?
fn is_application_class(descriptor: &str, opts: &DiffOptions) -> bool {
    if !opts.include_prefixes.is_empty() {
        // Mode inclusion : uniquement les préfixes fournis.
        return opts.include_prefixes.iter().any(|p| descriptor.starts_with(p));
    }
    // Mode exclusion best-effort : on retire les bibliothèques les plus courantes
    // du corpus. À défaut d'heuristique fiable sur les libs ProGuardées (noms
    // courts a/b/c), préférer --diff-include pour un diff propre.
    const LIB_PREFIXES: &[&str] = &[
        "Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Lkotlinx/",
        "Ldalvik/", "Lrx/", "Lio/reactivex/", "Lokhttp3/", "Lokio/", "Lretrofit2/",
        "Lcom/google/", "Lcom/alibaba/", "Lcom/umeng/", "Lorg/apache/", "Lorg/json/",
        "Lorg/xmlpull/", "Luk/co/chrisjenx/", "Lgov/nist/",
    ];
    !LIB_PREFIXES.iter().any(|p| descriptor.starts_with(p))
}

/// Parse un DEX et accumule les ClassPrint des classes applicatives.
fn collect_from_dex(path: &Path, opts: &DiffOptions, out: &mut Vec<ClassPrint>) -> Result<()> {
    let dex = dex::DexReader::from_file(path)
        .with_context(|| format!("open dex {}", path.display()))?;

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable class");
                continue;
            }
        };
        let name = class.jtype().type_descriptor().to_string();
        if !is_application_class(&name, opts) {
            continue;
        }

        let mut method_seq = Vec::new();
        for method in class.methods() {
            // Pas de code pour abstract / native : rien à empreindre.
            let code = match method.code() {
                Some(c) => c,
                None => continue,
            };
            let bytes = u16_to_le_bytes(code.insns());
            let instructions = match dex_bytecode::decode_all(&bytes, 0) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(class = %name, error = %e, "decode failed");
                    continue;
                }
            };
            // Empreinte de méthode = hash de la séquence de mnémoniques seuls.
            let mut h = DefaultHasher::new();
            for ins in &instructions {
                ins.mnemonic().hash(&mut h);
            }
            method_seq.push(h.finish());
        }

        // Classe sans aucune méthode à code : on l'ignore (interfaces vides,
        // classes de constantes) — elle n'apporte rien au diff sémantique.
        if method_seq.is_empty() {
            continue;
        }

        let method_set: HashSet<u64> = method_seq.iter().copied().collect();
        let class_hash = {
            let mut sorted = method_seq.clone();
            sorted.sort_unstable();
            let mut h = DefaultHasher::new();
            sorted.hash(&mut h);
            h.finish()
        };
        let key = crate::parser::disasm::normalize(&name, &opts.normalize);
        out.push(ClassPrint { name, key, method_seq, method_set, class_hash });
    }
    Ok(())
}

/// Résout l'entrée en une liste de chemins de DEX à lire. DEX brut → lui-même ;
/// APK (zip) → ses `classes*.dex` extraits dans un tempdir. Le type est reniflé
/// sur les octets de tête, jamais sur l'extension.
fn collect_dex_paths(input: &Path) -> Result<(Vec<PathBuf>, Option<tempfile::TempDir>)> {
    let mut magic = [0u8; 8];
    {
        let mut f = std::fs::File::open(input)
            .with_context(|| format!("open {}", input.display()))?;
        let n = f.read(&mut magic)?;
        if n < 4 {
            bail!("{} trop court pour être un DEX ou un APK", input.display());
        }
    }

    // DEX : magic "dex\n" (0x64 65 78 0a).
    if &magic[0..4] == b"dex\n" {
        return Ok((vec![input.to_path_buf()], None));
    }
    // ZIP/APK : signature locale "PK\x03\x04".
    if magic[0..4] == [0x50, 0x4b, 0x03, 0x04] {
        let tmp = tempfile::tempdir().context("create tempdir")?;
        let paths = extract_dexes(input, tmp.path())?;
        if paths.is_empty() {
            bail!("aucun classes*.dex dans l'APK {}", input.display());
        }
        return Ok((paths, Some(tmp)));
    }
    bail!(
        "{} n'est ni un DEX (dex\\n) ni un APK (PK) — magic {:02x?}",
        input.display(),
        &magic[0..4]
    )
}

/// Extrait les seuls `classes*.dex` d'un APK vers `out_dir`.
fn extract_dexes(apk: &Path, out_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(apk).with_context(|| format!("open {}", apk.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if !(name.starts_with("classes") && name.ends_with(".dex")) {
            continue;
        }
        let dest = out_dir.join(name.replace('/', "__"));
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        std::fs::write(&dest, &buf)?;
        out.push(dest);
    }
    Ok(out)
}

/// Code units (u16) → octets little-endian (format attendu par dex-bytecode).
fn u16_to_le_bytes(insns: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(insns.len() * 2);
    for &u in insns {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Légende des mesures (mode `--diff-dex --legend`).
pub fn legend() -> String {
    "\
== Diff DEX — légende ==

Principe : de chaque méthode on ne garde que la SÉQUENCE DE MNÉMONIQUES d'opcodes
(registres et opérandes jetés). Renommer package/classe/méthode ou ajouter une
variable ne change PAS l'opcode → le diff est insensible à com.dy↔com.duiyun et
à ProGuard.
Réf. : Lee, Jung, Kim & Kim, « Android Malware Similarity Clustering using Method
based Opcode Sequence and Jaccard Index », ICTC 2019, p. 178-183.

Filtre (obligatoire pour un résultat valide — cf. « Android Malware Clustering
Through Malicious Payload Mining », RAID 2017) :
  --diff-include <PRÉFIXE>   Ne comparer que les classes dont le descripteur
                             Dalvik commence par ce préfixe. Répétable. Passer
                             les préfixes des DEUX côtés, ex. :
                               --diff-include Lcom/dy/ --diff-include Lcom/duiyun/
                             Sans lui : exclusion best-effort des libs connues.

Mesures globales :
  jaccard_methods   Part de méthodes strictement identiques (ordre-insensible).
                    C'est la réponse directe à « même arbre source ? ».
  jaccard_ngram     Jaccard sur les n-grammes de mots-méthodes (ordre pris en
                    compte), comme dans le papier (défaut n=2).
                    ⚠️ Le seuil 0.85 de --diff-threshold est un paramètre de cet
                    outil, PAS un seuil empirique publié.

Appariement par classe :
  identiques   Même empreinte de code (multiset de méthodes égal), ex.
               Lcom/dy/g; ↔ Lcom/duiyun/g;. Le décompte est ventilé en :
                 par nom      nom normalisé égal ET empreinte égale — le cas
                              normal ;
                 par empreinte  empreinte égale mais noms différents = renommage
                              RÉEL de classe. ⚠️ Un chiffre élevé ici sans
                              renommage attendu signale des appariements
                              douteux : les POJO (<init> + accesseurs) partagent
                              tous la même empreinte.
  --diff-normalize A=B  Substitution appliquée au descripteur pour construire la
                        CLÉ d'appariement (ex. com/duiyun=com/dy). Répétable.
                        N'affecte ni les empreintes, ni les mesures, ni les noms
                        affichés. Sans elle, entre deux namespaces différents,
                        l'appariement par nom ne peut rien apparier.
  proches      Jaccard des méthodes ≥ --diff-threshold (défaut 0.85).
  only_in_a /  Classes sans contrepartie de l'autre côté — c'est là que se
  only_in_b    lisent les vraies divergences de code entre les deux lots.

Note : l'appariement est nom-agnostique (par opcodes), donc --diff-include ne
sert qu'au FILTRE et à l'affichage, pas à la mise en correspondance.\
"
    .to_string()
}
