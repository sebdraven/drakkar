//! Extraction **ciblée** d'entrées arbitraires d'un APK, par motif de chemin.
//!
//! Là où [`super::native_extract`] ne sort que les `.so` ELF, ce module extrait
//! **n'importe quelle entrée** du zip dont le chemin correspond à un motif —
//! sans jamais déballer l'archive entière.
//!
//! Le besoin vient des conteneurs à plugin : un hôte DroidPlugin embarque l'APK
//! qu'il exécutera dans `res/raw/plugin`, un packer range son DEX chiffré dans
//! `assets/`, un dropper cache son second étage sous un nom anodin. Dans les
//! trois cas on veut **une seule entrée**, identifiée par son chemin, et son
//! empreinte pour la rattacher au corpus — pas les 800 fichiers de l'archive.
//!
//! Deux garanties de conception :
//!
//! * **Rien n'est écrit sans qu'on le demande.** [`extract_matching`] rend les
//!   octets en mémoire ; l'écriture sur disque est un appel séparé
//!   ([`ExtractedEntry::write_to`]), et le nom de sortie est dérivé du chemin
//!   dans l'archive, jamais choisi par l'archive elle-même.
//! * **Pas de traversée de chemin.** Un nom d'entrée contenant `..` ou commençant
//!   par `/` est refusé à l'écriture — une archive malveillante ne peut pas
//!   écrire hors du répertoire de sortie (Zip Slip).
//!
//! Toutes les étiquettes produites sont définies dans [`legend`].

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use super::apkzip::TolerantZip;
use super::output_file_name;

/// Une entrée extraite de l'APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedEntry {
    /// Chemin complet dans l'archive : `res/raw/plugin`, `assets/payload.jar`.
    pub entry: String,
    /// Nom de fichier seul : `plugin`, `payload.jar`.
    pub file: String,
    /// Taille décompressée, en octets.
    pub size: u64,
    /// Taille stockée dans l'archive (après compression).
    pub compressed_size: u64,
    /// SHA-256 du contenu décompressé — l'identifiant à rapprocher du corpus.
    pub sha256: String,
    /// Type déduit des octets de tête, sans se fier à l'extension :
    /// `apk/zip`, `dex`, `elf`, `png`, `gzip`, `xml-bin`, `pdf`, `inconnu`.
    ///
    /// `String` et non `&'static str` : le type doit rester désérialisable, or
    /// `&'static str` impose `'de: 'static` et casse `Deserialize`.
    pub kind: String,
    /// Entropie de Shannon sur les octets (0.0–8.0). > 7,9 = chiffré ou
    /// compressé ; un DEX en clair tourne autour de 6.
    pub entropy: f64,
    /// Octets complets, en mémoire. Exclus de la sérialisation (binaire).
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

impl ExtractedEntry {
    /// Nom de fichier de sortie, dérivé du chemin dans l'archive : les
    /// séparateurs deviennent `_`, ce qui évite de recréer l'arborescence et
    /// garde une trace de l'emplacement d'origine.
    ///
    /// `res/raw/plugin` → `res_raw_plugin`. Borné par [`output_file_name`].
    pub fn output_name(&self) -> String {
        output_file_name(&self.entry.replace(['/', '\\'], "_"), &self.entry)
    }

    /// Écrit l'entrée dans `dir` sous [`Self::output_name`]. Le répertoire est
    /// créé au besoin. Rend le chemin écrit.
    ///
    /// Refuse toute entrée dont le chemin d'archive contient `..` ou est absolu
    /// (Zip Slip) — même si le nom de sortie est aplati, on ne veut pas d'un
    /// chemin d'archive hostile dans les journaux ni dans le nom produit.
    pub fn write_to(&self, dir: &Path) -> Result<PathBuf> {
        if self.entry.split(['/', '\\']).any(|c| c == "..") || self.entry.starts_with('/') {
            bail!("chemin d'entrée refusé (traversée) : {}", self.entry);
        }
        std::fs::create_dir_all(dir).with_context(|| format!("création {}", dir.display()))?;
        let dest = dir.join(self.output_name());
        std::fs::write(&dest, &self.bytes)
            .with_context(|| format!("écriture {}", dest.display()))?;
        Ok(dest)
    }
}

/// Résultat d'une passe d'extraction ciblée.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryExtraction {
    /// Motifs demandés, tels que fournis.
    pub patterns: Vec<String>,
    /// Entrées retenues.
    pub entries: Vec<ExtractedEntry>,
    /// Nombre total d'entrées de l'archive (dénominateur du filtrage).
    pub scanned: usize,
    /// Entrées retenues par un motif que même le lecteur tolérant n'a pas pu
    /// décompresser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
}

impl EntryExtraction {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

/// Correspondance d'un chemin d'archive à un motif.
///
/// Trois formes, dans cet ordre de test :
/// 1. **égalité exacte** — `res/raw/plugin` ;
/// 2. **glob** si le motif contient `*` ou `?` — `assets/*.so`, `res/raw/*` ;
/// 3. **sous-chaîne** sinon — `plugin` retient `res/raw/plugin`.
///
/// La comparaison est insensible à la casse : les archives Android mélangent
/// les conventions, et rater une entrée parce qu'elle est en majuscules serait
/// un faux négatif silencieux.
pub fn matches(entry: &str, pattern: &str) -> bool {
    let e = entry.to_ascii_lowercase();
    let p = pattern.to_ascii_lowercase();
    if e == p {
        return true;
    }
    if p.contains('*') || p.contains('?') {
        return glob_match(&e, &p);
    }
    e.contains(&p)
}

/// Glob minimal : `*` (zéro ou plus, `/` compris) et `?` (exactement un).
/// Implémentation itérative avec retour arrière — pas de dépendance externe.
fn glob_match(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Type de contenu déduit des octets de tête. L'extension n'est jamais
/// consultée : dans un conteneur à plugin, l'APG embarqué s'appelle `plugin`,
/// sans extension.
fn sniff(bytes: &[u8]) -> &'static str {
    match bytes {
        [0x50, 0x4B, 0x03, 0x04, ..] | [0x50, 0x4B, 0x05, 0x06, ..] => "apk/zip",
        [0x64, 0x65, 0x78, 0x0A, ..] => "dex", // "dex\n"
        [0x64, 0x65, 0x79, 0x0A, ..] => "dey", // "dey\n" (conteneur Jiagu)
        [0x7F, 0x45, 0x4C, 0x46, ..] => "elf",
        [0x89, 0x50, 0x4E, 0x47, ..] => "png",
        [0x1F, 0x8B, ..] => "gzip",
        [0x25, 0x50, 0x44, 0x46, ..] => "pdf",
        [0x03, 0x00, 0x08, 0x00, ..] => "xml-bin", // AXML
        [0x02, 0x00, 0x0C, 0x00, ..] => "arsc",
        _ => "inconnu",
    }
}

/// Entropie de Shannon sur la distribution des octets, en bits par octet.
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Extrait de l'APK en mémoire toutes les entrées correspondant à l'un des
/// motifs. Aucune écriture sur disque.
pub fn extract_matching_bytes(apk: &[u8], patterns: &[String]) -> Result<EntryExtraction> {
    let nominal = zip::ZipArchive::new(std::io::Cursor::new(apk))
        .context("lecture APK (zip) depuis la mémoire")
        .and_then(|mut archive| extract_archive(&mut archive, patterns));
    match nominal {
        Ok(extraction) => Ok(extraction),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "extraction en échec par le crate zip, repli sur le lecteur tolérant"
            );
            let zip = TolerantZip::from_bytes(apk.to_vec())?;
            Ok(extract_tolerant(&zip, patterns))
        }
    }
}

/// Extrait d'un APK sur disque les entrées correspondant à l'un des motifs.
/// Les octets restent en mémoire — l'écriture est un choix explicite de
/// l'appelant ([`ExtractedEntry::write_to`]).
///
/// Repli sur [`TolerantZip`] dès que le crate `zip` refuse l'archive à
/// l'ouverture, une entrée à `by_index`, ou ses octets à `read_to_end`.
pub fn extract_matching(path: &Path, patterns: &[String]) -> Result<EntryExtraction> {
    let file =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let nominal = zip::ZipArchive::new(file)
        .context("lecture APK (zip)")
        .and_then(|mut archive| extract_archive(&mut archive, patterns));
    match nominal {
        Ok(extraction) => Ok(extraction),
        Err(e) => {
            tracing::warn!(
                apk = %path.display(),
                error = %e,
                "extraction en échec par le crate zip, repli sur le lecteur tolérant"
            );
            Ok(extract_tolerant(&TolerantZip::open(path)?, patterns))
        }
    }
}

/// Liste les chemins de toutes les entrées de l'archive, sans rien extraire.
/// Sert à trouver quoi demander quand on ne connaît pas encore l'arborescence.
pub fn list_entries(path: &Path) -> Result<Vec<String>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let nominal = (|| -> Result<Vec<String>> {
        let mut archive = zip::ZipArchive::new(file).context("lecture APK (zip)")?;
        let mut names = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            let entry = archive
                .by_index(i)
                .with_context(|| format!("entrée zip #{i}"))?;
            names.push(entry.name().to_string());
        }
        Ok(names)
    })();
    let mut names = match nominal {
        Ok(names) => names,
        Err(e) => {
            tracing::warn!(
                apk = %path.display(),
                error = %e,
                "liste en échec par le crate zip, repli sur le lecteur tolérant"
            );
            let zip = TolerantZip::open(path)?;
            zip.entries().iter().map(|e| e.name.clone()).collect()
        }
    };
    names.retain(|name| !name.ends_with('/'));
    names.sort();
    Ok(names)
}

fn extract_archive<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    patterns: &[String],
) -> Result<EntryExtraction> {
    let mut entries = Vec::new();
    let scanned = archive.len();

    for i in 0..scanned {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("entrée zip #{i}"))?;
        let name = entry.name().to_string();
        if !selected(&name, patterns) {
            continue;
        }

        let size = entry.size();
        let compressed_size = entry.compressed_size();
        let mut bytes = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("lecture {name}"))?;
        entries.push(extracted(name, size, compressed_size, bytes));
    }

    Ok(EntryExtraction {
        patterns: patterns.to_vec(),
        entries,
        scanned,
        unreadable: Vec::new(),
    })
}

/// `size` est la longueur réellement décompressée : le central directory d'une
/// archive trafiquée peut mentir. Une entrée illisible va dans `unreadable`.
fn extract_tolerant(zip: &TolerantZip, patterns: &[String]) -> EntryExtraction {
    let mut out = EntryExtraction {
        patterns: patterns.to_vec(),
        scanned: zip.len(),
        ..EntryExtraction::default()
    };
    for (i, entry) in zip.entries().iter().enumerate() {
        let name = &entry.name;
        if !selected(name, patterns) {
            continue;
        }
        match zip.read(i) {
            Ok(bytes) => {
                let size = bytes.len() as u64;
                let found = extracted(name.clone(), size, entry.comp_size, bytes);
                out.entries.push(found);
            }
            Err(e) => {
                tracing::warn!(
                    entry = %name,
                    error = %e,
                    "entrée illisible par le lecteur tolérant"
                );
                out.unreadable.push(name.clone());
            }
        }
    }
    out
}

fn selected(name: &str, patterns: &[String]) -> bool {
    !name.ends_with('/') && patterns.iter().any(|p| matches(name, p))
}

fn extracted(name: String, size: u64, compressed_size: u64, bytes: Vec<u8>) -> ExtractedEntry {
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let file = name.rsplit('/').next().unwrap_or(name.as_str()).to_string();
    ExtractedEntry {
        entry: name,
        file,
        size,
        compressed_size,
        sha256,
        kind: sniff(&bytes).to_string(),
        entropy: entropy(&bytes),
        bytes,
    }
}

/// Légende autonome des étiquettes produites par ce module.
pub fn legend() -> &'static str {
    "\
entry            Chemin complet de l'entrée dans l'APK (ex. res/raw/plugin, assets/payload.jar).
file             Nom de fichier seul, sans le répertoire.
size             Taille décompressée, en octets.
compressed_size  Taille stockée dans l'archive (après compression).
sha256           SHA-256 du contenu DÉCOMPRESSÉ — identifiant à rapprocher du corpus.
kind             Type déduit des OCTETS DE TÊTE, jamais de l'extension : apk/zip, dex, dey,
                 elf, png, gzip, pdf, xml-bin, arsc, inconnu. Un APK embarqué s'appelle
                 souvent \"plugin\" sans extension — d'où le reniflage.
entropy          Entropie de Shannon (0.0-8.0). > 7.9 = chiffré ou déjà compressé ;
                 un DEX en clair est vers 6.0. Un écart signale un payload.
scanned          Nombre total d'entrées de l'archive (dénominateur du filtrage).
unreadable       Entrées retenues mais illisibles, y compris par le lecteur ZIP tolérant.

Lecture : crate zip d'abord ; s'il refuse l'archive, une entrée ou ses octets (local
header abîmé, drapeau de chiffrement, méthode inventée), lecteur ZIP tolérant calqué sur
le chargeur d'Android. size est alors la longueur réellement décompressée, et
compressed_size la taille déclarée par le central directory.

Motifs (--extract-entry, répétable) :
  égalité exacte   res/raw/plugin
  glob             assets/*.so   res/raw/*      (* = zéro ou plus, / compris ; ? = un)
  sous-chaîne      plugin        (retient res/raw/plugin)
La comparaison est insensible à la casse.

Sécurité : une entrée dont le chemin contient \"..\" ou commence par \"/\" est refusée à
l'écriture (Zip Slip). Le nom de sortie est dérivé du chemin d'archive avec les
séparateurs remplacés par \"_\" : res/raw/plugin -> res_raw_plugin. Au-delà de 200
octets : <préfixe>__<sha256 du chemin d'archive><.ext>, où préfixe = début du nom
aplati coupé sur un caractère UTF-8, sha256 = SHA-256 COMPLET (64 hex) du chemin
d'archive (pas du contenu), .ext = extension d'origine si elle fait au plus 16 octets.
Le récapitulatif affiche toujours le chemin d'archive au-dessus du fichier écrit."
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_apk(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default();
            for (name, data) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    /// Un mini-zip valide, pour simuler un APK embarqué en ressource brute.
    fn inner_apk() -> Vec<u8> {
        make_apk(&[("classes.dex", b"dex\n035\0payload".to_vec())])
    }

    #[test]
    fn exact_glob_and_substring() {
        assert!(matches("res/raw/plugin", "res/raw/plugin"));
        assert!(matches("res/raw/plugin", "RES/RAW/PLUGIN")); // casse ignorée
        assert!(matches("res/raw/plugin", "plugin")); // sous-chaîne
        assert!(matches("res/raw/plugin", "res/raw/*")); // glob
        assert!(matches("assets/libjiagu.so", "assets/*.so"));
        assert!(!matches("res/raw/plugin", "assets/*"));
        assert!(!matches("classes.dex", "plugin"));
    }

    #[test]
    fn extracts_embedded_apk_with_hash_and_kind() {
        let inner = inner_apk();
        let apk = make_apk(&[
            ("classes.dex", b"dex\n035\0host".to_vec()),
            ("res/raw/plugin", inner.clone()),
            ("assets/agreement.html", b"<html></html>".to_vec()),
        ]);

        let ex = extract_matching_bytes(&apk, &["res/raw/plugin".into()]).unwrap();
        assert_eq!(ex.count(), 1);
        assert_eq!(ex.scanned, 3);

        let e = &ex.entries[0];
        assert_eq!(e.entry, "res/raw/plugin");
        assert_eq!(e.file, "plugin");
        assert_eq!(e.kind, "apk/zip"); // reniflé, malgré l'absence d'extension
        assert_eq!(e.sha256, format!("{:x}", Sha256::digest(&inner)));
        assert_eq!(e.output_name(), "res_raw_plugin");
        assert_eq!(e.bytes, inner);
    }

    #[test]
    fn sniffs_dex_and_elf_without_extension() {
        let apk = make_apk(&[
            ("a", b"dex\n035\0....".to_vec()),
            ("b", b"dey\n036\0....".to_vec()),
            ("c", b"\x7FELF\x02\x01\x01\0".to_vec()),
        ]);
        let ex = extract_matching_bytes(&apk, &["*".into()]).unwrap();
        let kind = |n: &str| {
            ex.entries
                .iter()
                .find(|e| e.entry == n)
                .unwrap()
                .kind
                .as_str()
        };
        assert_eq!(kind("a"), "dex");
        assert_eq!(kind("b"), "dey");
        assert_eq!(kind("c"), "elf");
    }

    #[test]
    fn multiple_patterns_and_no_match() {
        let apk = make_apk(&[
            ("res/raw/plugin", inner_apk()),
            ("assets/libjiagu.so", b"\x7FELF....".to_vec()),
        ]);

        let ex = extract_matching_bytes(&apk, &["res/raw/*".into(), "assets/*.so".into()]).unwrap();
        assert_eq!(ex.count(), 2);

        let none = extract_matching_bytes(&apk, &["introuvable".into()]).unwrap();
        assert!(none.is_empty());
        assert_eq!(none.scanned, 2);
    }

    #[test]
    fn entropy_separates_plain_from_random() {
        let plain = vec![b'A'; 4096];
        assert!(entropy(&plain) < 0.1);

        // Suite pseudo-aléatoire déterministe (LCG) : entropie proche de 8.
        let mut x: u32 = 0x1234_5678;
        let rnd: Vec<u8> = (0..8192)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        assert!(entropy(&rnd) > 7.5);
    }

    #[test]
    fn refuses_path_traversal_on_write() {
        let e = ExtractedEntry {
            entry: "../../etc/passwd".into(),
            file: "passwd".into(),
            size: 3,
            compressed_size: 3,
            sha256: String::new(),
            kind: "inconnu".to_string(),
            entropy: 0.0,
            bytes: b"abc".to_vec(),
        };
        let tmp = tempfile::tempdir().unwrap();
        assert!(e.write_to(tmp.path()).is_err());
    }
}
