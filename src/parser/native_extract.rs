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
//! Toutes les étiquettes produites sont définies dans [`legend`] (légende
//! autonome).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};
use std::path::Path;

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
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(apk))
        .context("lecture APK (zip) depuis la mémoire")?;
    extract_archive(&mut archive)
}

/// Extrait les `.so` natifs d'un APK sur disque. L'archive est lue, mais aucun
/// `.so` n'est réécrit : les octets partent en RAM dans `ExtractedLib::bytes`.
pub fn extract_apk_file(path: &Path) -> Result<NativeExtraction> {
    let file =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("lecture APK (zip)")?;
    extract_archive(&mut archive)
}

fn extract_archive<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Result<NativeExtraction> {
    let mut libs = Vec::new();
    let mut skipped_non_elf = Vec::new();

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

        // Filtre ELF : écarte les fausses `.so` (ressources, `.so` non déballé).
        let arch = match parse_elf_header(&bytes) {
            Some(a) => a,
            None => {
                skipped_non_elf.push(name);
                continue;
            }
        };

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

        libs.push(ExtractedLib {
            entry: name,
            file,
            source,
            declared_abi,
            arch,
            bytes,
        });
    }

    Ok(NativeExtraction {
        libs,
        skipped_non_elf,
    })
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
bytes            Octets complets du .so, en mémoire (jamais écrits sur disque).
skipped_non_elf  Entrées en .so qui ne sont pas des ELF (ressources, .so chiffré non déballé…).
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
    fn root_level_so_marked_out_of_lib() {
        let apk = make_apk(&[("libpayload.so", elf(1, 40))]);
        let ex = extract_apk_bytes(&apk).unwrap();
        assert_eq!(ex.count(), 1);
        assert!(ex.libs[0].out_of_lib());
        assert_eq!(ex.libs[0].source, "(racine)");
    }
}
