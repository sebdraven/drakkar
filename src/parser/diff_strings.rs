//! Comparaison des **pools de chaînes** de deux DEX (ou APK).
//!
//! POURQUOI CE MODULE
//! ------------------
//! `--diff-dex` et `--diff-explain` ne lisent que les **instructions**. Or en
//! Dalvik, un champ `static final String` initialisé par une constante de
//! compilation n'est jamais écrit par un `const-string` : sa valeur vit dans le
//! tableau `encoded_static_values` du `class_def_item`. Ces deux outils sont
//! donc **structurellement aveugles** à toute une classe de constantes — et
//! notamment aux endpoints C2 du corpus, portés par exactement ce motif.
//!
//! Constaté sur `com.dy.spyzie.v4` ↔ `com.sc.safespy.v3` lot B : deux endpoints
//! connus comme différents (`i.spyzie.io` / `i.safespy.com`) n'apparaissaient
//! dans aucune sortie.
//!
//! Le pool de chaînes, lui, contient TOUT — littéraux d'instruction, valeurs
//! statiques, descripteurs, noms de méthodes et de champs. Le comparer ferme
//! l'angle mort.
//!
//! CE QU'IL DIT ET NE DIT PAS
//! --------------------------
//! Il dit **ce qui** diffère, pas **où**. Le pool est un tableau plat, sans
//! rattachement à une classe ni à un champ. Pour l'attribution il faudrait lire
//! `class_def.static_values`, ce qui reste à faire dans `diff_explain`.
//! Les deux sont complémentaires, pas redondants.
//!
//! LE CLASSEMENT EST CE QUI REND LA SORTIE LISIBLE
//! ----------------------------------------------
//! Un pool brut est majoritairement du bruit structurel : descripteurs Dalvik,
//! noms de méthodes, signatures. Les catégoriser sépare le signal du reste —
//! même principe que les catégories de gravité de `diff_explain`, qui ont fait
//! passer ce module d'illisible à exploitable. Par défaut le bruit structurel
//! est masqué ; `--strings-noise` le rétablit.

use crate::parser::diff_explain::ColorMode;
use crate::parser::disasm::normalize;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

// ── Classement ───────────────────────────────────────────────────────────────

/// Nature d'une chaîne du pool. L'ordre de déclaration est l'ordre de GRAVITÉ :
/// ce qui porte de l'infrastructure d'abord, le bruit d'obfuscation en dernier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum StringKind {
    /// Contient `://`, ou ressemble à un hôte. **La catégorie qui compte** :
    /// c'est là que se lisent les endpoints C2 et les domaines de marque.
    Url,
    /// Hexadécimal long : clé d'API, identifiant de compte, empreinte.
    Key,
    /// Commence par `/` : chemin de fichier, route d'API.
    Path,
    /// Littéral quelconque — message, jeton de marque, chaîne de debug.
    Literal,
    /// Identifiant nu (`[A-Za-z_$][A-Za-z0-9_$]*`) : nom de méthode, de champ,
    /// de classe simple. Bruit structurel, masqué par défaut.
    Identifier,
    /// Descripteur Dalvik (`Lx/y;`, `[I`, `(Ljava/lang/String;)V`, primitifs).
    /// Bruit structurel, masqué par défaut.
    Descriptor,
}

impl StringKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Url => "url/hôte",
            Self::Key => "clé/identifiant",
            Self::Path => "chemin",
            Self::Literal => "littéral",
            Self::Identifier => "identifiant",
            Self::Descriptor => "descripteur",
        }
    }

    fn color(self) -> &'static str {
        match self {
            Self::Url => RED,
            Self::Key => MAGENTA,
            Self::Path => YELLOW,
            Self::Literal => CYAN,
            Self::Identifier | Self::Descriptor => DIM,
        }
    }

    /// Bruit structurel du format DEX, sans intérêt pour la comparaison de
    /// constantes. Masqué sauf `--strings-noise`.
    pub fn is_noise(self) -> bool {
        matches!(self, Self::Identifier | Self::Descriptor)
    }
}

/// Classe une chaîne. Les tests sont ordonnés du plus spécifique au plus large.
pub fn classify(s: &str) -> StringKind {
    // Descripteur ou signature Dalvik : test en premier car `Lcom/x/Y;`
    // ressemblerait sinon à un chemin ou à un identifiant.
    if is_descriptor(s) {
        return StringKind::Descriptor;
    }
    if s.contains("://") || looks_like_host(s) {
        return StringKind::Url;
    }
    if s.starts_with('/') {
        return StringKind::Path;
    }
    if is_long_hex(s) {
        return StringKind::Key;
    }
    if is_identifier(s) {
        return StringKind::Identifier;
    }
    StringKind::Literal
}

fn is_descriptor(s: &str) -> bool {
    if s.starts_with('(') {
        return true; // signature de méthode
    }
    let core = s.trim_start_matches('[');
    if core.len() == 1 && "VZBSCIJFD".contains(core) {
        return true; // primitif, éventuellement en tableau
    }
    core.starts_with('L') && core.ends_with(';') && core.contains('/')
}

/// `exemple.com`, `i.spyzie.io`, `sp.kuuvv.com` — au moins un point, un TLD
/// alphabétique de 2 à 24 caractères, pas d'espace, et pas une simple version
/// numérique (`1.0.0`) ni un nom de classe pointé (dernier segment capitalisé).
fn looks_like_host(s: &str) -> bool {
    if s.len() < 4 || s.contains(' ') || s.contains('/') || !s.contains('.') {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    let tld = parts[parts.len() - 1];
    if !(2..=24).contains(&tld.len()) || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    // `com.dy.util.a` est un nom de classe, pas un hôte : le premier segment
    // d'un paquet Java est un TLD à l'envers. Heuristique : si le premier
    // segment est un TLD courant, c'est un nom de paquet.
    const PKG_HEADS: &[&str] = &[
        "com", "org", "net", "io", "android", "androidx", "java", "javax",
    ];
    if PKG_HEADS.contains(&parts[0]) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn is_long_hex(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_identifier(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    cs.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

// ── Couleur ──────────────────────────────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const MAGENTA: &str = "\x1b[35m";
const CYAN: &str = "\x1b[36m";

fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{RESET}")
    } else {
        s.to_string()
    }
}

// ── Structures ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StringEntry {
    pub kind: StringKind,
    pub value: String,
}

#[derive(Serialize)]
pub struct StringDiffReport {
    pub input_a: String,
    pub input_b: String,
    /// Chaînes DISTINCTES de chaque côté (le pool contient des doublons).
    pub distinct_a: usize,
    pub distinct_b: usize,
    /// Entrées annoncées par l'en-tête, et illisibles — signale un DEX abîmé.
    pub declared_a: usize,
    pub declared_b: usize,
    pub unreadable_a: usize,
    pub unreadable_b: usize,
    pub common: usize,
    /// Jaccard sur les ensembles de chaînes distinctes.
    pub jaccard: f64,
    pub only_in_a: Vec<StringEntry>,
    pub only_in_b: Vec<StringEntry>,
    /// Comptes par catégorie, toutes divergences confondues, par gravité.
    pub by_kind: Vec<(String, usize)>,
}

pub struct StringDiffOptions {
    /// Substitutions appliquées AVANT comparaison (ex. `com/duiyun=com/dy`).
    /// Indispensable entre deux namespaces différents, sinon chaque descripteur
    /// ressort en divergence.
    pub normalize: Vec<(String, String)>,
    /// Masquer le bruit structurel du format DEX — descripteurs et identifiants
    /// nus — pour ne garder que les vraies constantes.
    pub literals_only: bool,
    /// Ignorer les chaînes plus courtes que N caractères. Utile pour couper les
    /// fragments d'un caractère et les descripteurs primitifs.
    pub min_len: usize,
    pub color: ColorMode,
    pub max_value: usize,
}

impl Default for StringDiffOptions {
    fn default() -> Self {
        Self {
            normalize: Vec::new(),
            literals_only: false,
            min_len: 0,
            color: ColorMode::Auto,
            max_value: 120,
        }
    }
}

// ── Traitement ───────────────────────────────────────────────────────────────

pub fn run(a: &Path, b: &Path, opts: &StringDiffOptions) -> Result<StringDiffReport> {
    let pa = super::dex_strings::extract_any(a)
        .with_context(|| format!("pool de chaînes de {}", a.display()))?;
    let pb = super::dex_strings::extract_any(b)
        .with_context(|| format!("pool de chaînes de {}", b.display()))?;

    let sa: HashSet<String> = pa
        .strings
        .iter()
        .map(|s| normalize(s, &opts.normalize))
        .collect();
    let sb: HashSet<String> = pb
        .strings
        .iter()
        .map(|s| normalize(s, &opts.normalize))
        .collect();

    let inter = sa.intersection(&sb).count();
    let union = sa.len() + sb.len() - inter;
    let jaccard = if union == 0 {
        1.0
    } else {
        inter as f64 / union as f64
    };

    let mut only_in_a = collect(&sa, &sb, opts);
    let mut only_in_b = collect(&sb, &sa, opts);
    only_in_a.sort_by(|x, y| x.kind.cmp(&y.kind).then(x.value.cmp(&y.value)));
    only_in_b.sort_by(|x, y| x.kind.cmp(&y.kind).then(x.value.cmp(&y.value)));

    // Comptes par catégorie sur l'union des divergences.
    let mut counts: std::collections::HashMap<StringKind, usize> = std::collections::HashMap::new();
    for e in only_in_a.iter().chain(only_in_b.iter()) {
        *counts.entry(e.kind).or_insert(0) += 1;
    }
    let mut kinds: Vec<(StringKind, usize)> = counts.into_iter().collect();
    kinds.sort_by_key(|(k, _)| *k);

    Ok(StringDiffReport {
        input_a: a.display().to_string(),
        input_b: b.display().to_string(),
        distinct_a: sa.len(),
        distinct_b: sb.len(),
        declared_a: pa.declared,
        declared_b: pb.declared,
        unreadable_a: pa.unreadable,
        unreadable_b: pb.unreadable,
        common: inter,
        jaccard,
        only_in_a,
        only_in_b,
        by_kind: kinds
            .into_iter()
            .map(|(k, n)| (k.label().to_string(), n))
            .collect(),
    })
}

fn collect(
    from: &HashSet<String>,
    other: &HashSet<String>,
    opts: &StringDiffOptions,
) -> Vec<StringEntry> {
    from.difference(other)
        .filter(|s| s.chars().count() >= opts.min_len)
        .map(|s| StringEntry {
            kind: classify(s),
            value: s.clone(),
        })
        .filter(|e| !(opts.literals_only && e.kind.is_noise()))
        .collect()
}

// ── Rendu ────────────────────────────────────────────────────────────────────

pub fn render(r: &StringDiffReport, opts: &StringDiffOptions) -> String {
    let c = opts.color.enabled();
    let mut s = String::new();

    s.push_str(&format!(
        "{}\n",
        paint(c, BOLD, "== Diff des pools de chaînes ==")
    ));
    s.push_str(&format!("A  {}\n", r.input_a));
    s.push_str(&format!("B  {}\n\n", r.input_b));

    s.push_str(&format!(
        "Chaînes distinctes   A={}  B={}   communes {}   Jaccard {:.4}\n",
        paint(c, CYAN, &r.distinct_a.to_string()),
        paint(c, CYAN, &r.distinct_b.to_string()),
        paint(c, GREEN, &r.common.to_string()),
        r.jaccard
    ));
    if r.unreadable_a > 0 || r.unreadable_b > 0 {
        s.push_str(&format!(
            "  {} entrées illisibles : A={} sur {} annoncées, B={} sur {} — DEX abîmé, \
             la comparaison est partielle\n",
            paint(c, YELLOW, "⚠"),
            r.unreadable_a,
            r.declared_a,
            r.unreadable_b,
            r.declared_b
        ));
    }
    if opts.literals_only {
        s.push_str(&format!(
            "  {}\n",
            paint(
                c,
                DIM,
                "(descripteurs et identifiants masqués par --strings-literals)"
            )
        ));
    }
    if opts.min_len > 0 {
        s.push_str(&format!(
            "  {}\n",
            paint(
                c,
                DIM,
                &format!("(chaînes de moins de {} caractères ignorées)", opts.min_len)
            )
        ));
    }

    for (title, list) in [
        ("Seulement dans A", &r.only_in_a),
        ("Seulement dans B", &r.only_in_b),
    ] {
        s.push_str(&format!("\n{} ({}) :\n", paint(c, BOLD, title), list.len()));
        if list.is_empty() {
            s.push_str(&format!("  {}\n", paint(c, GREEN, "aucune")));
            continue;
        }
        for e in list {
            s.push_str(&format!(
                "  {:<16} {}\n",
                paint(c, e.kind.color(), e.kind.label()),
                paint(c, e.kind.color(), &truncate(&e.value, opts.max_value))
            ));
        }
    }

    if !r.by_kind.is_empty() {
        s.push_str(&format!("\n{}\n", paint(c, BOLD, "Par catégorie :")));
        for (label, n) in &r.by_kind {
            s.push_str(&format!("  {:<18} {}\n", label, n));
        }
    }

    let total: usize = r.only_in_a.len() + r.only_in_b.len();
    s.push_str(&format!("\n{}\n", paint(c, BOLD, "Verdict :")));
    s.push_str(&format!(
        "  {} chaîne(s) divergente(s) hors bruit structurel.\n",
        paint(c, if total == 0 { GREEN } else { RED }, &total.to_string())
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

/// Légende (`--diff-strings --legend`).
pub fn legend() -> String {
    "\
== Diff des pools de chaînes (--diff-strings) — légende ==

POURQUOI : --diff-dex et --diff-explain ne lisent que les INSTRUCTIONS. Un champ
`static final String` initialisé par une constante de compilation n'est pas écrit
par un `const-string` — sa valeur vit dans `encoded_static_values` du
`class_def_item`. Les endpoints C2 du corpus sont portés par exactement ce motif,
donc invisibles à ces deux outils. Le pool de chaînes, lui, contient tout.

CE QU'IL NE DIT PAS : où. Le pool est un tableau plat, sans rattachement à une
classe ni à un champ. Pour l'attribution, il faudra lire class_def.static_values.

Options :
  --strings-normalize A=B  Substitution appliquée AVANT comparaison
                           (ex. com/duiyun=com/dy). Répétable. Sans elle, entre
                           deux namespaces différents, tous les descripteurs
                           ressortent en divergence.
  --strings-literals       Masquer le bruit structurel : descripteurs Dalvik et
                           identifiants nus. Ne garde que les vraies constantes.
  --strings-min-len N      Ignorer les chaînes de moins de N caractères.

Catégories, par gravité décroissante :
  url/hôte         Contient `://` ou ressemble à un hôte. LA catégorie qui
                   compte : endpoints C2, domaines de marque.        [rouge]
  clé/identifiant  Hexadécimal de 16 caractères ou plus : clé d'API,
                   identifiant de compte, empreinte.                [magenta]
  chemin           Commence par `/` : chemin de fichier, route.       [jaune]
  littéral         Tout autre littéral — message, jeton de marque,
                   chaîne de debug.                                    [cyan]
  identifiant      Identifiant nu : nom de méthode, de champ.        [atténué]
  descripteur      Descripteur ou signature Dalvik.                  [atténué]
Les deux dernières sont du bruit structurel : `--strings-literals` les masque.

Un DEX abîmé (dump mémoire tronqué) est lu au mieux : le nombre d'entrées
illisibles est affiché, et la comparaison est alors PARTIELLE — à ne pas lire
comme une absence de divergence.\
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classe_les_urls() {
        assert_eq!(classify("https://i.safespy.com/api/"), StringKind::Url);
        assert_eq!(classify("sp.kuuvv.com"), StringKind::Url);
        assert_eq!(classify("ws.phonedata.me"), StringKind::Url);
    }

    #[test]
    fn ne_confond_pas_paquet_et_hote() {
        // Nom de paquet Java : premier segment = TLD à l'envers.
        assert_ne!(classify("com.dy.util.a"), StringKind::Url);
        assert_ne!(classify("org.apache.http"), StringKind::Url);
        // Version numérique : pas de TLD alphabétique.
        assert_ne!(classify("1.0.0-rc01"), StringKind::Url);
    }

    #[test]
    fn classe_descripteurs_et_signatures() {
        assert_eq!(classify("Lcom/dy/services/g;"), StringKind::Descriptor);
        assert_eq!(classify("[Ljava/lang/String;"), StringKind::Descriptor);
        assert_eq!(classify("(Landroid/os/Handler;)V"), StringKind::Descriptor);
        assert_eq!(classify("I"), StringKind::Descriptor);
        assert!(StringKind::Descriptor.is_noise());
    }

    #[test]
    fn classe_cles_et_chemins() {
        assert_eq!(classify("5f02a2ae570df3abd6000171"), StringKind::Key);
        assert_eq!(classify("/sdcard/spyzie/Logs/"), StringKind::Path);
    }

    #[test]
    fn jeton_de_marque_est_un_identifiant_pas_un_litteral() {
        // `spyzie` est un identifiant nu -> bruit par défaut. C'est voulu : sans
        // ça, tous les noms de méthodes ProGuard remonteraient. Le jeton de
        // marque se retrouve via --strings-noise, ou via --diff-explain qui,
        // lui, sait dire dans quelle méthode il est.
        assert_eq!(classify("spyzie"), StringKind::Identifier);
        assert_eq!(classify("三星浏览器数据源改变"), StringKind::Literal);
    }

    #[test]
    fn gravite_met_les_urls_en_tete() {
        let mut v = vec![StringKind::Descriptor, StringKind::Url, StringKind::Path];
        v.sort();
        assert_eq!(v[0], StringKind::Url);
        assert_eq!(v[2], StringKind::Descriptor);
    }
}
