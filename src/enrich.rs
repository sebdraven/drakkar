//! Enrichissement de la datation par les services externes — VirusTotal et
//! Koodous — à partir du seul SHA-256 du fichier.
//!
//! **Nature des grandeurs récupérées.** Tout ce que produit
//! [`crate::parser::dating`] est une *borne basse* : le build est postérieur à la
//! génération de la clé, à la sortie du format DEX, à la publication des
//! bibliothèques. Les dates de première soumission fournies ici sont les
//! premières **bornes hautes** : le fichier existait à cette date. Borne basse +
//! borne haute = un intervalle, ce qui rend l'échantillon comparable aux autres.
//!
//! Réserve à conserver en analyse : la latence de soumission est très variable.
//! Un échantillon peut rester des années hors des plateformes avant d'y
//! apparaître. C'est une borne haute **lâche**, jamais une date de build.
//!
//! **Conception.** Les deux API sont contingentées (VT en clé publique : 4
//! requêtes/minute, 500/jour). Trois conséquences structurantes :
//!
//!  - **cache disque d'abord** : une réponse déjà obtenue n'est jamais
//!    redemandée, donc un lot interrompu reprend là où il s'est arrêté ;
//!  - **appels sérialisés et throttlés**, jamais parallélisés par rayon ;
//!  - **séparé de l'extraction** : l'inventaire local se relance en quelques
//!    secondes, le réseau non. Les deux passes ne partagent que le SHA-256.
//!
//! Les jetons sont lus dans l'environnement (`VT_API_KEY`, `KOODOUS_TOKEN`) et
//! jamais acceptés en argument de ligne de commande : argv est visible dans `ps`
//! et finit dans l'historique du shell.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Variable d'environnement portant la clé VirusTotal.
pub const VT_ENV: &str = "VT_API_KEY";
/// Variable d'environnement portant le jeton Koodous.
pub const KOODOUS_ENV: &str = "KOODOUS_TOKEN";

const VT_URL: &str = "https://www.virustotal.com/api/v3/files/";
const KOODOUS_URL: &str = "https://developer.koodous.com/apks/";

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// Service interrogé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    VirusTotal,
    Koodous,
}

impl Source {
    /// Analyse une liste `vt,koodous` (insensible à la casse, ordre indifférent).
    pub fn parse_list(s: &str) -> Result<Vec<Source>> {
        let mut out = BTreeSet::new();
        for part in s.split(',') {
            match part.trim().to_ascii_lowercase().as_str() {
                "" => continue,
                "vt" | "virustotal" => {
                    out.insert(Source::VirusTotal);
                }
                "koodous" | "kd" => {
                    out.insert(Source::Koodous);
                }
                other => anyhow::bail!("source inconnue : {other} (attendu : vt, koodous)"),
            }
        }
        if out.is_empty() {
            anyhow::bail!("aucune source indiquee (attendu : vt, koodous)");
        }
        Ok(out.into_iter().collect())
    }

    pub fn label(&self) -> &'static str {
        match self {
            Source::VirusTotal => "vt",
            Source::Koodous => "koodous",
        }
    }

    fn env_var(&self) -> &'static str {
        match self {
            Source::VirusTotal => VT_ENV,
            Source::Koodous => KOODOUS_ENV,
        }
    }

    /// Sous-répertoire de cache dédié : les réponses des deux services ne se
    /// mélangent pas et se purgent indépendamment.
    fn cache_subdir(&self) -> &'static str {
        self.label()
    }
}

// ---------------------------------------------------------------------------
// Options et modèle
// ---------------------------------------------------------------------------

pub struct EnrichOptions {
    pub sources: Vec<Source>,
    /// Racine du cache. Un sous-répertoire par service.
    pub cache_dir: PathBuf,
    /// Requêtes par minute et **par service**. 4 = quota public VirusTotal.
    pub rate_per_min: u32,
    /// Ignore le cache et refait tous les appels.
    pub force: bool,
}

/// Ligne d'enrichissement pour un échantillon.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrichedRow {
    pub file_sha256: String,

    /// Première soumission à VirusTotal — **borne haute** du build.
    pub vt_first_submission: Option<String>,
    pub vt_last_submission: Option<String>,
    pub vt_times_submitted: Option<u64>,
    /// Moteurs classant l'échantillon comme malveillant à la dernière analyse.
    pub vt_malicious: Option<u64>,
    /// Moteurs ayant rendu un verdict, toutes catégories confondues.
    pub vt_engines: Option<u64>,
    /// `found`, `absent` (404 : inconnu du service) ou message d'erreur.
    pub vt_status: Option<String>,

    /// Première apparition sur Koodous — **borne haute** du build.
    pub koodous_created_at: Option<String>,
    pub koodous_detected: Option<bool>,
    pub koodous_corrupted: Option<bool>,
    pub koodous_rating: Option<i64>,
    pub koodous_tags: Vec<String>,
    pub koodous_status: Option<String>,
}

// ---------------------------------------------------------------------------
// Lecture des hachages en entrée
// ---------------------------------------------------------------------------

/// Extrait les SHA-256 d'une entrée, `-` désignant stdin.
///
/// Trois formes acceptées, détectées automatiquement : le CSV produit par
/// `--dating --format csv` (colonne `file_sha256`), une liste d'un hachage par
/// ligne, ou un répertoire de `*.dating.json`. L'ordre d'entrée est conservé et
/// les doublons éliminés — un même hachage ne consomme jamais deux fois le quota.
pub fn read_hashes(input: &Path) -> Result<Vec<String>> {
    let text = if input.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("lecture de stdin")?;
        s
    } else if input.is_dir() {
        return hashes_from_dir(input);
    } else {
        std::fs::read_to_string(input).with_context(|| format!("lecture {}", input.display()))?
    };

    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return Ok(Vec::new());
    };

    // En-tête CSV ? On repère la colonne par son nom plutôt que par sa position :
    // l'ordre des colonnes peut bouger.
    let sha_col = first
        .split(',')
        .position(|h| h.trim().eq_ignore_ascii_case("file_sha256"));

    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    match sha_col {
        Some(col) => {
            for line in lines {
                if let Some(field) = split_csv_line(line).get(col) {
                    push_hash(field, &mut out, &mut seen);
                }
            }
        }
        None => {
            // Pas d'en-tête : la première ligne est une donnée comme les autres.
            push_hash(first, &mut out, &mut seen);
            for line in lines {
                push_hash(line, &mut out, &mut seen);
            }
        }
    }

    Ok(out)
}

fn push_hash(value: &str, out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    let v = value.trim().trim_matches('"').to_ascii_lowercase();
    if is_sha256(&v) && seen.insert(v.clone()) {
        out.push(v);
    }
}

/// Collecte les hachages depuis un répertoire de rapports `*.dating.json`.
fn hashes_from_dir(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if !p.is_file() {
            continue;
        }
        let is_dating = p
            .file_name()
            .map(|n| n.to_string_lossy().ends_with(".dating.json"))
            .unwrap_or(false);
        if !is_dating {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if let Some(h) = v.get("file_sha256").and_then(|x| x.as_str()) {
            push_hash(h, &mut out, &mut seen);
        }
    }
    out.sort();
    Ok(out)
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Découpe une ligne CSV en respectant les champs entre guillemets.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

// ---------------------------------------------------------------------------
// Boucle principale
// ---------------------------------------------------------------------------

/// Interroge les services pour chaque hachage et renvoie une ligne par échantillon.
///
/// Les clés absentes de l'environnement désactivent la source correspondante avec
/// un avertissement, plutôt que d'interrompre : un enrichissement partiel reste
/// exploitable.
pub fn run(hashes: &[String], opts: &EnrichOptions) -> Result<Vec<EnrichedRow>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .build();

    // Résolution des jetons, une fois pour toutes.
    let mut active: Vec<(Source, String)> = Vec::new();
    for s in &opts.sources {
        match std::env::var(s.env_var()) {
            Ok(k) if !k.trim().is_empty() => active.push((*s, k)),
            _ => eprintln!(
                "[!] {} desactive : {} absente de l'environnement",
                s.label(),
                s.env_var()
            ),
        }
    }
    if active.is_empty() {
        anyhow::bail!("aucune source utilisable - exporte {VT_ENV} et/ou {KOODOUS_ENV}");
    }

    // Intervalle minimal entre deux appels d'un même service.
    let interval = Duration::from_millis(60_000 / opts.rate_per_min.max(1) as u64);
    let mut last_call: Vec<Option<Instant>> = vec![None; active.len()];

    let mut rows = Vec::with_capacity(hashes.len());
    let mut network_calls = 0usize;
    let mut cache_hits = 0usize;

    for (i, sha) in hashes.iter().enumerate() {
        let mut row = EnrichedRow {
            file_sha256: sha.clone(),
            ..Default::default()
        };

        for (idx, (source, key)) in active.iter().enumerate() {
            let cached = if opts.force {
                None
            } else {
                read_cache(&opts.cache_dir, *source, sha)
            };

            let body = match cached {
                Some(b) => {
                    cache_hits += 1;
                    Ok(b)
                }
                None => {
                    // Throttle : on n'attend que si l'intervalle n'est pas écoulé.
                    if let Some(t) = last_call[idx] {
                        let elapsed = t.elapsed();
                        if elapsed < interval {
                            std::thread::sleep(interval - elapsed);
                        }
                    }
                    last_call[idx] = Some(Instant::now());
                    network_calls += 1;
                    let fetched = fetch(&agent, *source, sha, key);
                    if let Ok(b) = &fetched {
                        write_cache(&opts.cache_dir, *source, sha, b);
                    }
                    fetched
                }
            };

            match body {
                Ok(text) => apply(&mut row, *source, &text),
                Err(e) => {
                    let msg = e.to_string();
                    match source {
                        Source::VirusTotal => row.vt_status = Some(msg),
                        Source::Koodous => row.koodous_status = Some(msg),
                    }
                }
            }
        }

        let vt_col = row
            .vt_first_submission
            .clone()
            .or_else(|| row.vt_status.clone())
            .unwrap_or_else(|| "-".into());
        let kd_col = row
            .koodous_created_at
            .clone()
            .or_else(|| row.koodous_status.clone())
            .unwrap_or_else(|| "-".into());
        eprintln!(
            "[{}/{}] {}  vt={vt_col}  koodous={kd_col}",
            i + 1,
            hashes.len(),
            &sha[..16.min(sha.len())]
        );

        rows.push(row);
    }

    eprintln!(
        "\n[*] enrichissement termine - {} echantillon(s), {network_calls} appel(s) reseau, {cache_hits} depuis le cache",
        hashes.len()
    );
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Appels réseau
// ---------------------------------------------------------------------------

/// Un appel, une réponse brute. Le corps est renvoyé tel quel pour être mis en
/// cache sans perte : l'interprétation peut changer, pas la réponse du service.
fn fetch(agent: &ureq::Agent, source: Source, sha: &str, key: &str) -> Result<String> {
    let (url, header, value) = match source {
        Source::VirusTotal => (format!("{VT_URL}{sha}"), "x-apikey", key.to_string()),
        Source::Koodous => (
            format!("{KOODOUS_URL}{sha}/"),
            "Authorization",
            format!("Token {key}"),
        ),
    };

    match agent.get(&url).set(header, &value).call() {
        Ok(resp) => resp.into_string().context("lecture du corps de reponse"),
        Err(ureq::Error::Status(404, _)) => anyhow::bail!("absent"),
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            anyhow::bail!("jeton refuse ({})", source.env_var())
        }
        Err(ureq::Error::Status(429, _)) => {
            anyhow::bail!("quota depasse - baisse --rate ou reprends plus tard")
        }
        Err(ureq::Error::Status(code, _)) => anyhow::bail!("HTTP {code}"),
        Err(e) => anyhow::bail!("reseau : {e}"),
    }
}

/// Extrait les champs utiles d'une réponse et les pose dans la ligne.
///
/// Le JSON est navigué sans structure typée : un champ ajouté ou déplacé côté
/// service ne doit pas faire échouer l'extraction des autres.
fn apply(row: &mut EnrichedRow, source: Source, body: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        match source {
            Source::VirusTotal => row.vt_status = Some("reponse illisible".into()),
            Source::Koodous => row.koodous_status = Some("reponse illisible".into()),
        }
        return;
    };

    match source {
        Source::VirusTotal => {
            let a = &v["data"]["attributes"];
            row.vt_first_submission = a["first_submission_date"]
                .as_i64()
                .map(crate::parser::cert::fmt_unix_utc);
            row.vt_last_submission = a["last_submission_date"]
                .as_i64()
                .map(crate::parser::cert::fmt_unix_utc);
            row.vt_times_submitted = a["times_submitted"].as_u64();
            let stats = &a["last_analysis_stats"];
            row.vt_malicious = stats["malicious"].as_u64();
            row.vt_engines = stats.as_object().map(|o| {
                o.values()
                    .filter_map(serde_json::Value::as_u64)
                    .sum::<u64>()
            });
            row.vt_status = Some("found".into());
        }
        Source::Koodous => {
            row.koodous_created_at = v["created_at"].as_str().map(|s| s.to_string());
            row.koodous_detected = v["is_detected"].as_bool();
            row.koodous_corrupted = v["is_corrupted"].as_bool();
            row.koodous_rating = v["rating"].as_i64();
            row.koodous_tags = v["tags"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            row.koodous_status = Some("found".into());
        }
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// La réponse brute est conservée telle quelle : elle vaut plus longtemps que
/// l'interprétation qu'on en fait aujourd'hui.
fn cache_path(cache_dir: &Path, source: Source, sha: &str) -> PathBuf {
    cache_dir
        .join(source.cache_subdir())
        .join(format!("{sha}.json"))
}

fn read_cache(cache_dir: &Path, source: Source, sha: &str) -> Option<String> {
    std::fs::read_to_string(cache_path(cache_dir, source, sha)).ok()
}

fn write_cache(cache_dir: &Path, source: Source, sha: &str, body: &str) {
    let path = cache_path(cache_dir, source, sha);
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let _ = std::fs::write(path, body);
}

// ---------------------------------------------------------------------------
// Rendus
// ---------------------------------------------------------------------------

/// CSV d'enrichissement : une ligne par échantillon, jointure par `file_sha256`
/// avec le CSV de datation.
pub fn to_csv(rows: &[EnrichedRow]) -> String {
    let mut out = String::from(
        "file_sha256,vt_first_submission,vt_last_submission,vt_times_submitted,\
vt_malicious,vt_engines,vt_status,\
koodous_created_at,koodous_detected,koodous_corrupted,koodous_rating,\
koodous_tags,koodous_status\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_field(&r.file_sha256),
            csv_field(r.vt_first_submission.as_deref().unwrap_or_default()),
            csv_field(r.vt_last_submission.as_deref().unwrap_or_default()),
            opt_str(r.vt_times_submitted),
            opt_str(r.vt_malicious),
            opt_str(r.vt_engines),
            csv_field(r.vt_status.as_deref().unwrap_or_default()),
            csv_field(r.koodous_created_at.as_deref().unwrap_or_default()),
            opt_str(r.koodous_detected),
            opt_str(r.koodous_corrupted),
            opt_str(r.koodous_rating),
            csv_field(&r.koodous_tags.join("|")),
            csv_field(r.koodous_status.as_deref().unwrap_or_default()),
        ));
    }
    out
}

fn opt_str<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Légende autonome : nature de chaque champ d'enrichissement.
pub fn legend() -> String {
    let mut s = String::new();
    s.push_str("Legende - enrichissement VirusTotal / Koodous\n");
    s.push_str("  Jointure avec le CSV de datation par la colonne file_sha256.\n\n");
    s.push_str("  BORNE HAUTE (le fichier existait deja a cette date)\n");
    s.push_str("    vt_first_submission   premiere soumission a VirusTotal\n");
    s.push_str("    koodous_created_at    premiere apparition sur Koodous\n");
    s.push_str("    Borne LACHE : la latence de soumission varie de quelques heures a\n");
    s.push_str("    plusieurs annees. A croiser avec toolchain_floor_api (borne basse)\n");
    s.push_str("    pour obtenir un intervalle, jamais a lire comme une date de build.\n\n");
    s.push_str("  CONTEXTE (ne date rien)\n");
    s.push_str("    vt_last_submission    derniere soumission - activite, pas anciennete\n");
    s.push_str("    vt_times_submitted    nombre de soumissions - proxy de diffusion\n");
    s.push_str("    vt_malicious          moteurs classant l'echantillon malveillant\n");
    s.push_str("    vt_engines            moteurs ayant rendu un verdict\n");
    s.push_str("    koodous_detected      verdict de detection Koodous\n");
    s.push_str("    koodous_corrupted     DEX, ressource ou certificat non detecte\n");
    s.push_str("    koodous_rating        vote des analystes\n");
    s.push_str("    koodous_tags          etiquettes communautaires\n\n");
    s.push_str("  STATUT\n");
    s.push_str("    *_status              found | absent (inconnu du service) | erreur\n");
    s.push_str("    'absent' est une information : l'echantillon n'a jamais ete soumis.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liste_de_sources() {
        assert_eq!(
            Source::parse_list("vt,koodous").unwrap(),
            vec![Source::VirusTotal, Source::Koodous]
        );
        assert_eq!(
            Source::parse_list(" VT ").unwrap(),
            vec![Source::VirusTotal]
        );
        // Doublons elimines.
        assert_eq!(
            Source::parse_list("vt,virustotal").unwrap(),
            vec![Source::VirusTotal]
        );
        assert!(Source::parse_list("otx").is_err());
        assert!(Source::parse_list("").is_err());
    }

    #[test]
    fn decoupe_csv_avec_guillemets() {
        let f = split_csv_line(r#"a,"b,c",d"#);
        assert_eq!(f, vec!["a", "b,c", "d"]);
    }

    #[test]
    fn validation_sha256() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"a".repeat(63)));
        assert!(!is_sha256(&"z".repeat(64)));
    }
}
