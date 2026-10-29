//! Extraction **en mémoire** des bibliothèques natives (`.so`) d'un APK.
//!
//! Là où [`super::native_arch`] ne lit que l'en-tête ELF (~64 octets) pour
//! détecter l'ABI, ce module **sort les octets complets** de chaque `.so`,
//! prêts à être passés à un moteur d'analyse native (désassembleur, exécution
//! symbolique Kharon) — le tout en RAM, sans jamais réécrire sur disque.
//!
//! Différence de périmètre décisive : on ne se restreint **pas** à `lib/<abi>/`.
//! Les packers rangent leur stub natif **hors** de `lib/` — 360 Jiagu place
//! `libjiagu*.so` dans `assets/`. Un extracteur limité à `lib/` rate donc
//! entièrement les échantillons packés. Ici on prend **tout `.so` ELF** du zip,
//! où qu'il soit, et l'ABI réelle est dérivée de l'en-tête ELF quand le chemin
//! ne la porte pas (cas `assets/`).
//!
//! # Sémantique du SHA-256
//!
//! Le `sha256` d'une lib porte sur le **contenu DÉCOMPRESSÉ** du `.so`, jamais
//! sur les octets stockés dans l'archive. Même sémantique que dans
//! [`super::assets`], et pour les deux mêmes raisons, aucune cosmétique :
//!
//! * c'est la seule forme requêtable — VirusTotal, MalwareBazaar et Koodous
//!   indexent le fichier déballé ; un hash d'octets compressés ne se croise avec
//!   rien ;
//! * « les octets stockés » n'est même pas une notion stable dès qu'un lecteur
//!   tolérant entre en jeu : sur une archive trafiquée la méthode déclarée est
//!   fausse et le lecteur essaie deflate puis stored, donc la même lib donnerait
//!   deux hashes selon le chemin de lecture emprunté. Le contenu déballé, lui,
//!   est identique par les deux lecteurs.
//!
//! Corollaire : une lib `stored` et le même contenu `deflate` ont le même
//! `sha256`. Il n'est jamais tronqué, jamais réduit à un préfixe.
//!
//! Toutes les étiquettes produites sont définies dans [`legend`] (légende
//! autonome).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
use std::path::Path;

use super::apkzip::TolerantZip;
use super::native_arch::{parse_elf_header, Abi, Bits, ElfArch, Machine};

/// Une bibliothèque native extraite (octets complets, en mémoire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedLib {
    /// Chemin dans l'APK : `lib/arm64-v8a/libfoo.so` ou `assets/libjiagu.so`.
    pub entry: String,
    /// Nom de fichier : `libfoo.so`.
    pub file: String,
    /// Dossier porteur : `"lib"` pour un rangement NDK `lib/<abi>/…`, sinon le
    /// 1er segment du chemin (`assets`, `(racine)`, …). Une valeur ≠ `"lib"`
    /// est un marqueur de packer.
    pub source: String,
    /// ABI déclarée par le répertoire `lib/<abi>/` si le rangement est standard,
    /// sinon `None` (l'ABI provient alors uniquement de l'ELF, cf. `arch`).
    pub declared_abi: Option<Abi>,
    /// Architecture lue dans l'en-tête ELF — source de vérité, y compris quand
    /// le chemin ne porte pas d'ABI.
    pub arch: ElfArch,
    /// SHA-256 COMPLET du contenu DÉCOMPRESSÉ du `.so` (64 caractères, jamais
    /// tronqué) — jamais des octets stockés dans l'archive, qui ne se croisent
    /// avec aucune base publique.
    pub sha256: String,
    /// Octets complets du `.so`, en mémoire. Exclu de la sérialisation (binaire,
    /// potentiellement volumineux).
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

impl ExtractedLib {
    /// `true` si la lib est rangée hors `lib/<abi>/` (signal packer).
    pub fn out_of_lib(&self) -> bool {
        self.source != "lib"
    }
}

/// Résultat d'extraction native pour un APK.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NativeExtraction {
    /// Une entrée par `.so` ELF extrait (octets inclus dans `ExtractedLib`).
    pub libs: Vec<ExtractedLib>,
    /// Entrées finissant en `.so` mais qui ne sont **pas** des ELF (ressource
    /// nommée `.so`, `.so` chiffré non déballé, …) — ignorées.
    pub skipped_non_elf: Vec<String>,
    /// Entrées en `.so` que même le lecteur tolérant n'a pas pu décompresser.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable: Vec<String>,
    /// Entrées en `.so` de longueur nulle : lues, vides, ni ELF ni illisibles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub empty: Vec<String>,
}

impl NativeExtraction {
    pub fn is_empty(&self) -> bool {
        self.libs.is_empty()
    }
    pub fn count(&self) -> usize {
        self.libs.len()
    }
    /// Libs rangées hors `lib/<abi>/` (packers : `assets/libjiagu*.so`, …).
    pub fn out_of_lib(&self) -> Vec<&ExtractedLib> {
        self.libs.iter().filter(|l| l.out_of_lib()).collect()
    }
    /// Libs dont l'architecture ELF correspond au couple (machine, bits) cible —
    /// utile pour ne charger que l'ABI voulue (ex. arm32 pour la SE).
    pub fn by_arch(&self, machine: Machine, bits: Bits) -> Vec<&ExtractedLib> {
        self.libs
            .iter()
            .filter(|l| l.arch.machine == machine && l.arch.bits == bits)
            .collect()
    }
}

/// Extrait les `.so` natifs d'un APK déjà chargé en mémoire (octets du zip).
pub fn extract_apk_bytes(apk: &[u8]) -> Result<NativeExtraction> {
    let nominal = zip::ZipArchive::new(std::io::Cursor::new(apk))
        .context("lecture APK (zip) depuis la mémoire")
        .and_then(|mut archive| extract_archive(&mut archive));
    match nominal {
        Ok(extraction) => Ok(extraction),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "extraction native en échec par le crate zip, repli sur le lecteur tolérant"
            );
            Ok(extract_tolerant(&TolerantZip::from_bytes(apk.to_vec())?))
        }
    }
}

/// Extrait les `.so` natifs d'un APK sur disque. L'archive est lue, mais aucun
/// `.so` n'est réécrit : les octets partent en RAM dans `ExtractedLib::bytes`.
///
/// Repli sur [`TolerantZip`] dès que le crate `zip` refuse l'archive à
/// l'ouverture, une entrée à `by_index`, ou ses octets à `read_to_end`.
pub fn extract_apk_file(path: &Path) -> Result<NativeExtraction> {
    let file =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let nominal = zip::ZipArchive::new(file)
        .context("lecture APK (zip)")
        .and_then(|mut archive| extract_archive(&mut archive));
    match nominal {
        Ok(extraction) => Ok(extraction),
        Err(e) => {
            tracing::warn!(
                apk = %path.display(),
                error = %e,
                "extraction native en échec par le crate zip, repli sur le lecteur tolérant"
            );
            Ok(extract_tolerant(&TolerantZip::open(path)?))
        }
    }
}

fn extract_archive<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Result<NativeExtraction> {
    let mut out = NativeExtraction::default();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("entrée zip #{i}"))?;
        let name = entry.name().to_string();
        // Répertoire, ou pas une `.so` → ignorer.
        if name.ends_with('/') || !name.ends_with(".so") {
            continue;
        }

        // Lecture complète du `.so` en RAM (jamais sur disque).
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .with_context(|| format!("lecture {name}"))?;
        out.push(name, bytes);
    }

    Ok(out)
}

/// Une entrée illisible est rangée dans `unreadable` au lieu de faire échouer
/// l'extraction des autres.
fn extract_tolerant(zip: &TolerantZip) -> NativeExtraction {
    let mut out = NativeExtraction::default();
    for (i, entry) in zip.entries().iter().enumerate() {
        let name = &entry.name;
        if name.ends_with('/') || !name.ends_with(".so") {
            continue;
        }
        match zip.read(i) {
            Ok(bytes) => out.push(name.clone(), bytes),
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

impl NativeExtraction {
    fn push(&mut self, name: String, bytes: Vec<u8>) {
        if bytes.is_empty() {
            self.empty.push(name);
            return;
        }
        // Filtre ELF : écarte les fausses `.so` (ressources, `.so` non déballé).
        let arch = match parse_elf_header(&bytes) {
            Some(a) => a,
            None => {
                self.skipped_non_elf.push(name);
                return;
            }
        };

        // Après le filtre ELF : seules les libs retenues sont hachées, les
        // entrées écartées vers `skipped_non_elf` restent de simples chemins.
        let sha256 = format!("{:x}", Sha256::digest(&bytes));

        let parts: Vec<&str> = name.split('/').collect();
        let file = parts.last().copied().unwrap_or(name.as_str()).to_string();

        // ABI déclarée uniquement pour un rangement NDK `lib/<abi>/…`. Hors lib/,
        // pas d'ABI de chemin : le 1er segment (assets, …) sert de `source`.
        let (source, declared_abi) = if parts.len() >= 3 && parts[0] == "lib" {
            ("lib".to_string(), Some(Abi::from_dir(parts[1])))
        } else {
            let dir = if parts.len() >= 2 {
                parts[0].to_string()
            } else {
                "(racine)".to_string()
            };
            (dir, None)
        };

        self.libs.push(ExtractedLib {
            entry: name,
            file,
            source,
            declared_abi,
            arch,
            sha256,
            bytes,
        });
    }
}

/// Légende autonome des étiquettes produites par ce module.
pub fn legend() -> &'static str {
    "\
entry            Chemin du .so dans l'APK (ex. lib/arm64-v8a/libfoo.so, assets/libjiagu.so).
file             Nom de fichier du .so.
source           Dossier porteur : \"lib\" = rangement NDK lib/<abi>/ ; sinon 1er segment du
                 chemin (assets, (racine), …). Toute valeur != \"lib\" = marqueur de packer.
declared_abi     ABI lue du répertoire lib/<abi>/ ; None si le .so est hors lib/.
arch             Architecture réelle lue dans l'en-tête ELF (machine + bits + boutisme) —
                 source de vérité, y compris quand le chemin ne porte pas d'ABI.
sha256           SHA-256 COMPLET (64 caractères hexadécimaux) du contenu DÉCOMPRESSÉ du .so —
                 JAMAIS des octets stockés dans l'archive. C'est la seule forme requêtable sur
                 VirusTotal, MalwareBazaar ou Koodous ; un hash d'octets compressés ne se croise
                 avec rien. Et « les octets stockés » n'est pas une notion stable dès qu'un
                 lecteur tolérant entre en jeu. Jamais tronqué, jamais un préfixe.
bytes            Octets complets du .so, en mémoire (jamais écrits sur disque, sauf
                 --extract-libs : nom = chemin aplati, / -> __ ; au-delà de 200 octets,
                 <préfixe>__<sha256 du chemin d'archive, 64 hex><.ext d'origine>, affiché
                 après le chemin d'archive).
skipped_non_elf  Entrées en .so qui ne sont pas des ELF (ressources, .so chiffré non déballé…).
unreadable       Entrées en .so illisibles, y compris par le lecteur ZIP tolérant (repli quand
                 le crate zip refuse l'archive ou une entrée : local header abîmé, drapeau de
                 chiffrement, méthode inventée). Absent si vide.
empty            Entrées en .so de longueur nulle (0 octet lu : stored vide ou flux deflate
                 vide). Lues sans erreur, ni ELF ni illisibles : comptées ni dans
                 skipped_non_elf ni dans unreadable. Absent si vide.
out_of_lib()     Vrai si la lib est rangée hors lib/<abi>/ (packers : assets/libjiagu*.so)."
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// En-tête ELF minimal (64 o), little-endian, `e_type = ET_DYN`.
    fn elf(class: u8, machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(b"\x7FELF");
        h[4] = class; // EI_CLASS : 1=32, 2=64
        h[5] = 1; // EI_DATA = little
        h[6] = 1; // EI_VERSION
        h[16] = 3; // e_type = ET_DYN (octet bas, LE)
        let m = machine.to_le_bytes();
        h[18] = m[0];
        h[19] = m[1];
        h
    }

    /// Construit un APK (zip) en mémoire depuis une liste (nom, octets).
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

    #[test]
    fn extracts_both_lib_and_out_of_lib() {
        let apk = make_apk(&[
            ("classes.dex", vec![0u8; 8]),
            ("lib/arm64-v8a/libx.so", elf(2, 183)), // aarch64, rangement NDK
            ("assets/libjiagu.so", elf(1, 40)),     // arm32 hors lib/ (Jiagu)
            ("assets/config.so", b"not-an-elf-file".to_vec()), // fausse .so
        ]);
        let ex = extract_apk_bytes(&apk).unwrap();

        assert_eq!(ex.count(), 2);

        // lib/<abi>/ standard
        let libx = ex
            .libs
            .iter()
            .find(|l| l.entry == "lib/arm64-v8a/libx.so")
            .unwrap();
        assert_eq!(libx.source, "lib");
        assert!(!libx.out_of_lib());
        assert_eq!(libx.declared_abi, Some(Abi::Arm64V8a));
        assert_eq!(libx.arch.machine, Machine::Aarch64);
        assert_eq!(libx.arch.bits, Bits::B64);
        assert!(!libx.bytes.is_empty());
        assert_eq!(libx.sha256.len(), 64);
        assert!(libx.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(libx.sha256, format!("{:x}", Sha256::digest(elf(2, 183))));

        // hors lib/ (packer) : arch dérivée de l'ELF, pas du chemin
        let jg = ex
            .libs
            .iter()
            .find(|l| l.entry == "assets/libjiagu.so")
            .unwrap();
        assert_eq!(jg.source, "assets");
        assert!(jg.out_of_lib());
        assert_eq!(jg.declared_abi, None);
        assert_eq!(jg.arch.machine, Machine::Arm);
        assert_eq!(jg.arch.bits, Bits::B32);
        assert_eq!(jg.sha256.len(), 64);
        assert!(jg.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(jg.sha256, format!("{:x}", Sha256::digest(elf(1, 40))));

        // fausse .so ignorée
        assert_eq!(ex.skipped_non_elf, vec!["assets/config.so".to_string()]);

        // helpers
        assert_eq!(ex.out_of_lib().len(), 1);
        assert_eq!(ex.by_arch(Machine::Arm, Bits::B32).len(), 1);
        assert_eq!(ex.by_arch(Machine::Aarch64, Bits::B64).len(), 1);
    }

    #[test]
    fn empty_on_pure_java_apk() {
        let apk = make_apk(&[("classes.dex", vec![0u8; 8])]);
        let ex = extract_apk_bytes(&apk).unwrap();
        assert!(ex.is_empty());
        assert!(ex.skipped_non_elf.is_empty());
    }

    #[test]
    fn an_empty_so_is_empty_not_skipped_nor_unreadable() {
        let apk = make_apk(&[("lib/armeabi/libvide.so", Vec::new())]);
        let ex = extract_apk_bytes(&apk).unwrap();
        assert_eq!(ex.empty, vec!["lib/armeabi/libvide.so".to_string()]);
        assert!(ex.skipped_non_elf.is_empty());
        assert!(ex.unreadable.is_empty());
    }

    #[test]
    fn root_level_so_marked_out_of_lib() {
        let apk = make_apk(&[("libpayload.so", elf(1, 40))]);
        let ex = extract_apk_bytes(&apk).unwrap();
        assert_eq!(ex.count(), 1);
        assert!(ex.libs[0].out_of_lib());
        assert_eq!(ex.libs[0].source, "(racine)");
    }
}
