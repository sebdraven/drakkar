//! Extraction du **pool de chaînes** d'un DEX.
//!
//! POURQUOI UN PARSEUR MAISON
//! --------------------------
//! **Ça marche sur un DEX ABÎMÉ.** Les dumps mémoire Frida des échantillons
//! packés (SecNeo) ont souvent un en-tête reconstruit à la main et des sections
//! tronquées. `dex_facade` s'appuie sur `DexFile::parse`, qui matérialise d'un
//! coup `string_ids`, `type_ids`, `proto_ids`, `field_ids` et `method_ids` et
//! rend `Err` sur la première table qui déborde : le fichier entier est perdu.
//! Celui-ci lit entrée par entrée, rend ce qu'il peut et compte le reste dans
//! `unreadable`.
//!
//! FORMAT
//! ------
//! En-tête DEX : `string_ids_size` (u32 @ 0x38), `string_ids_off` (u32 @ 0x3C).
//! Chaque entrée de `string_ids` est un u32 pointant vers un `string_data_item` :
//! une longueur en **ULEB128** (en unités UTF-16, pas en octets) suivie des
//! octets **MUTF-8** terminés par un NUL.
//!
//! MUTF-8 vs UTF-8 : ils ne diffèrent que pour U+0000 (encodé sur 2 octets) et
//! les caractères hors BMP (paires de substitution encodées séparément). Pour de
//! la recherche de marqueurs, un décodage UTF-8 permissif suffit — les chaînes
//! concernées (ASCII, CJK du BMP) sont identiques dans les deux encodages.

use anyhow::{Context, Result};
use std::path::Path;

/// Résultat d'une extraction, avec ce qui a échoué plutôt qu'un silence.
#[derive(Debug, Default)]
pub struct StringPool {
    /// Chaînes lues, dans l'ordre du pool.
    pub strings: Vec<String>,
    /// Nombre annoncé par l'en-tête.
    pub declared: usize,
    /// Entrées illisibles (offset hors bornes, longueur aberrante).
    pub unreadable: usize,
}

/// Décode un ULEB128 à partir de `pos`. Renvoie (valeur, octets consommés).
fn uleb128(buf: &[u8], pos: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut i = 0;
    loop {
        let byte = *buf.get(pos + i)?;
        result |= ((byte & 0x7f) as u32) << shift;
        i += 1;
        if byte & 0x80 == 0 {
            return Some((result, i));
        }
        shift += 7;
        // Un ULEB128 de plus de 5 octets ne tient pas dans un u32 : entrée abîmée.
        if shift > 28 {
            return None;
        }
    }
}

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Extrait le pool de chaînes d'un tampon contenant un DEX.
pub fn from_bytes(buf: &[u8]) -> Result<StringPool> {
    if buf.len() < 0x70 || &buf[0..4] != b"dex\n" {
        anyhow::bail!("pas un DEX (magic `dex\\n` absent ou fichier trop court)");
    }

    let size = u32_at(buf, 0x38).context("string_ids_size illisible")? as usize;
    let off = u32_at(buf, 0x3C).context("string_ids_off illisible")? as usize;

    let mut pool = StringPool {
        declared: size,
        ..Default::default()
    };

    for i in 0..size {
        let entry = match u32_at(buf, off + i * 4) {
            Some(v) => v as usize,
            None => {
                pool.unreadable += 1;
                continue;
            }
        };
        // Longueur en unités UTF-16, puis les octets MUTF-8 jusqu'au NUL.
        let (_len_utf16, consumed) = match uleb128(buf, entry) {
            Some(v) => v,
            None => {
                pool.unreadable += 1;
                continue;
            }
        };
        let start = entry + consumed;
        let end = match buf[start.min(buf.len())..].iter().position(|&b| b == 0) {
            Some(p) => start + p,
            None => {
                pool.unreadable += 1;
                continue;
            }
        };
        // Décodage permissif : une entrée abîmée ne doit pas tuer le balayage.
        pool.strings
            .push(String::from_utf8_lossy(&buf[start..end]).into_owned());
    }

    tracing::debug!(
        declared = pool.declared,
        read = pool.strings.len(),
        unreadable = pool.unreadable,
        "string pool extracted"
    );
    Ok(pool)
}

/// Un fichier `.dex` sur disque.
pub fn extract(path: &Path) -> Result<StringPool> {
    let buf = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    from_bytes(&buf)
}

/// Un APK : agrège le pool de tous les `classes*.dex`.
pub fn extract_from_apk(path: &Path) -> Result<StringPool> {
    use std::io::Read;

    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
    let mut merged = StringPool::default();

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if !(name.starts_with("classes") && name.ends_with(".dex")) {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        match from_bytes(&buf) {
            Ok(p) => {
                merged.declared += p.declared;
                merged.unreadable += p.unreadable;
                merged.strings.extend(p.strings);
            }
            Err(e) => tracing::warn!(entry = %name, error = %e, "dex illisible, ignoré"),
        }
    }
    Ok(merged)
}

/// Route selon le contenu : APK ou DEX brut. Réutilise le reniflage de
/// `dyn_entrypoints` — reconnaissance au contenu, jamais à l'extension.
pub fn extract_any(path: &Path) -> Result<StringPool> {
    use super::dyn_entrypoints::{sniff, InputKind};
    match sniff(path) {
        Some(InputKind::Apk) => extract_from_apk(path),
        Some(InputKind::Dex) => extract(path),
        None => anyhow::bail!(
            "{} n'est ni un APK ni un DEX (reconnu au contenu)",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_simple() {
        assert_eq!(uleb128(&[0x00], 0), Some((0, 1)));
        assert_eq!(uleb128(&[0x7f], 0), Some((127, 1)));
        assert_eq!(uleb128(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(uleb128(&[0xff, 0x7f], 0), Some((16383, 2)));
    }

    #[test]
    fn uleb128_tronque() {
        assert_eq!(uleb128(&[0x80], 0), None);
    }

    #[test]
    fn refuse_non_dex() {
        assert!(from_bytes(b"PK\x03\x04").is_err());
    }
}
