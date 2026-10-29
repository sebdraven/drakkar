//! Lecteur ZIP tolérant, calqué sur le chargeur d'APK d'Android.
//!
//! # Pourquoi
//!
//! Plusieurs familles (Astrinox/Mirax, SaferRat, TrickMo, GodFather) trafiquent
//! délibérément la structure ZIP de l'APK pour casser les outils d'analyse, sans
//! gêner l'installation par Android. Formes observées sur le corpus :
//!
//! - bit 0 des *General Purpose Flags* activé : l'archive paraît chiffrée et
//!   réclamer un mot de passe (VirusTotal remonte `password: 123123`, `111111`) ;
//! - méthode de compression inexistante déclarée (ex. `0x64b4`) ;
//! - extra field parasite nommé `$JADXBLOCK` ;
//! - horodatages dans le futur (2030) ;
//! - noms de fichiers anormalement longs.
//!
//! Le crate `zip` valide ces champs et refuse l'archive. Android non : le
//! PackageManager passe par `system/libziparchive`, qui s'appuie sur le
//! *central directory* et se montre laxiste sur le reste.
//!
//! Ce module est un **filet de secours** : `parser::extract_apk` tente d'abord
//! le crate `zip`, et ne bascule ici que si celui-ci échoue. Aucun changement de
//! comportement sur les APK sains.
//!
//! # Principe
//!
//! 1. localiser l'EOCD en balayant la fin du fichier (support ZIP64) ;
//! 2. parcourir le central directory, seule source de vérité ;
//! 3. pour chaque entrée, sauter au local file header sans faire confiance à ses
//!    champs, et lire les données brutes ;
//! 4. décompresser en essayant deflate puis stored, quelle que soit la méthode
//!    déclarée ;
//! 5. ignorer le drapeau de chiffrement, le CRC et les horodatages.
//!
//! # Limites assumées
//!
//! - pas de déchiffrement (une archive réellement chiffrée échouera) ;
//! - pas de vérification d'intégrité : le CRC n'est pas contrôlé ;
//! - un `..` ou un chemin absolu dans un nom d'entrée est rejeté à l'extraction
//!   par l'appelant, pas ici.

use anyhow::{anyhow, bail, Context, Result};
use std::io::Read;
use std::path::Path;

const SIG_LFH: u32 = 0x0403_4b50;
const SIG_CDH: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_EOCD64_LOC: u32 = 0x0706_4b50;

const LFH_FIXED: usize = 30;
const CDH_FIXED: usize = 46;
const EOCD_FIXED: usize = 22;

/// Taille max d'un APK chargé en mémoire. Au-delà, on refuse plutôt que de
/// faire exploser la RAM en mode bulk (rayon parallélise déjà les APK).
const MAX_IN_MEMORY: u64 = 512 * 1024 * 1024;

/// Une entrée du central directory, telle que retenue par le lecteur.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    /// Méthode déclarée dans le central directory. Purement informatif : la
    /// décompression ne s'y fie pas.
    pub method: u16,
    /// Drapeaux GP déclarés. Le bit 0 (chiffrement) est délibérément ignoré,
    /// mais conservé ici pour le diagnostic.
    pub flags: u16,
    pub comp_size: u64,
    pub uncomp_size: u64,
    /// Offset du local file header dans l'archive.
    pub lfh_offset: u64,
}

impl Entry {
    /// Vrai si l'entrée porte un marqueur de trafiquage. Sert au diagnostic,
    /// pas au filtrage.
    pub fn looks_tampered(&self) -> bool {
        self.flags & 1 != 0 || !matches!(self.method, 0 | 8)
    }

    /// Taille décompressée déclarée nulle, sans data descriptor (bit 3) qui
    /// renverrait les tailles après les données.
    pub fn declares_empty(&self) -> bool {
        self.uncomp_size == 0 && self.flags & 0x8 == 0
    }
}

/// Archive ouverte en mémoire.
pub struct TolerantZip {
    data: Vec<u8>,
    entries: Vec<Entry>,
}

impl TolerantZip {
    /// Ouvre un APK depuis le disque.
    pub fn open(path: &Path) -> Result<Self> {
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if meta.len() > MAX_IN_MEMORY {
            bail!(
                "{} fait {} octets, au-delà de la limite du lecteur tolérant ({} octets)",
                path.display(),
                meta.len(),
                MAX_IN_MEMORY
            );
        }
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Self::from_bytes(data)
    }

    /// Ouvre une archive déjà en mémoire.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let (cd_offset, cd_entries) = find_central_directory(&data)?;
        let entries = parse_central_directory(&data, cd_offset, cd_entries);
        tracing::debug!(
            entries = entries.len(),
            annonces = cd_entries,
            "lecteur ZIP tolérant : central directory parsé"
        );
        Ok(Self { data, entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Nombre d'entrées portant un marqueur de trafiquage.
    pub fn tampered_count(&self) -> usize {
        self.entries.iter().filter(|e| e.looks_tampered()).count()
    }

    /// Lit et décompresse une entrée par son index.
    pub fn read(&self, index: usize) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| anyhow!("index d'entrée hors bornes : {index}"))?;
        self.read_entry(entry)
    }

    /// Lit et décompresse une entrée par son nom exact.
    pub fn read_by_name(&self, name: &str) -> Result<Vec<u8>> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| anyhow!("entrée absente de l'archive : {name}"))?;
        self.read_entry(entry)
    }

    fn read_entry(&self, entry: &Entry) -> Result<Vec<u8>> {
        let start = self.data_offset(entry)?;

        // Le central directory ment parfois sur la taille compressée. Quand elle
        // est absurde, on donne tout le reste de l'archive à l'inflateur : le
        // flux deflate porte sa propre fin.
        let remaining = self.data.len().saturating_sub(start);
        let declared = entry.comp_size as usize;
        // Entrée vide : stored de 0 octet, ou flux deflate qui ne rend rien.
        // Sans ce cas, le reste de l'archive serait pris pour ses données.
        if entry.declares_empty() {
            let stored = &self.data[start..start + declared.min(remaining)];
            if declared == 0 || inflates_to_nothing(stored) {
                return Ok(Vec::new());
            }
        }
        let span = if declared == 0 || declared > remaining {
            remaining
        } else {
            declared
        };
        let raw = &self.data[start..start + span];

        // On n'honore pas la méthode déclarée : deflate d'abord, stored ensuite.
        // Couvre les méthodes inventées (0x64b4) comme les entrées réellement
        // stockées dont le champ a été trafiqué.
        if let Some(out) = try_inflate(raw, entry.uncomp_size) {
            return Ok(out);
        }
        if entry.uncomp_size > 0 && (entry.uncomp_size as usize) <= remaining {
            return Ok(self.data[start..start + entry.uncomp_size as usize].to_vec());
        }
        if declared > 0 && declared <= remaining {
            return Ok(raw.to_vec());
        }
        bail!(
            "entrée {} : ni deflate ni stored n'ont donné de contenu exploitable",
            entry.name
        );
    }

    /// Offset des données compressées. On saute le local file header sans
    /// faire confiance à sa signature ni à ses champs.
    fn data_offset(&self, entry: &Entry) -> Result<usize> {
        let lfh = entry.lfh_offset as usize;
        if lfh + LFH_FIXED > self.data.len() {
            bail!(
                "entrée {} : offset de local header hors archive ({lfh})",
                entry.name
            );
        }
        let sig = read_u32(&self.data, lfh);
        if sig == SIG_LFH {
            let name_len = read_u16(&self.data, lfh + 26) as usize;
            let extra_len = read_u16(&self.data, lfh + 28) as usize;
            let off = lfh + LFH_FIXED + name_len + extra_len;
            if off <= self.data.len() {
                return Ok(off);
            }
            tracing::debug!(
                entry = %entry.name,
                "local header aux longueurs incohérentes, repli sur le nom du central directory"
            );
        } else {
            tracing::debug!(
                entry = %entry.name,
                sig = format!("{sig:#010x}"),
                "signature de local header invalide, repli sur le nom du central directory"
            );
        }
        // Repli : longueur de nom issue du central directory, extra supposé nul.
        let off = lfh + LFH_FIXED + entry.name.len();
        if off > self.data.len() {
            bail!("entrée {} : impossible de situer les données", entry.name);
        }
        Ok(off)
    }
}

/// Tente une décompression deflate brute. `hint` sert à préallouer.
fn try_inflate(raw: &[u8], hint: u64) -> Option<Vec<u8>> {
    if raw.is_empty() {
        return None;
    }
    let cap = if hint > 0 && hint < 256 * 1024 * 1024 {
        hint as usize
    } else {
        raw.len() * 4
    };
    let mut out = Vec::with_capacity(cap);
    let mut dec = flate2::read::DeflateDecoder::new(raw);
    match dec.read_to_end(&mut out) {
        Ok(_) if !out.is_empty() => Some(out),
        // Un flux tronqué peut quand même avoir produit du contenu utile.
        Err(_) if !out.is_empty() => Some(out),
        _ => None,
    }
}

/// Flux deflate valide et vide (`03 00`, ou bloc stored de longueur nulle).
fn inflates_to_nothing(raw: &[u8]) -> bool {
    let mut out = Vec::new();
    !raw.is_empty()
        && flate2::read::DeflateDecoder::new(raw)
            .read_to_end(&mut out)
            .is_ok()
        && out.is_empty()
}

/// Localise le central directory. Balaye l'EOCD depuis la fin, puis suit le
/// locator ZIP64 s'il est présent.
fn find_central_directory(data: &[u8]) -> Result<(usize, usize)> {
    if data.len() < EOCD_FIXED {
        bail!("fichier trop court pour être une archive ZIP");
    }
    // Le commentaire final fait au plus 64 Kio ; on balaye un peu plus large.
    let scan_from = data.len().saturating_sub(66 * 1024 + EOCD_FIXED);
    let mut eocd = None;
    let mut i = data.len() - EOCD_FIXED;
    loop {
        if read_u32(data, i) == SIG_EOCD {
            eocd = Some(i);
            break;
        }
        if i == scan_from {
            break;
        }
        i -= 1;
    }
    let eocd = eocd.ok_or_else(|| anyhow!("EOCD introuvable : ce n'est pas une archive ZIP"))?;

    let mut cd_offset = read_u32(data, eocd + 16) as u64;
    let mut cd_entries = read_u16(data, eocd + 10) as u64;

    // ZIP64 : les champs 32 bits saturés renvoient vers l'enregistrement étendu.
    let needs64 = cd_offset == 0xFFFF_FFFF || cd_entries == 0xFFFF;
    if needs64 && eocd >= 20 {
        let loc = eocd - 20;
        if read_u32(data, loc) == SIG_EOCD64_LOC {
            let rec = read_u64(data, loc + 8) as usize;
            if rec + 56 <= data.len() && read_u32(data, rec) == SIG_EOCD64 {
                cd_entries = read_u64(data, rec + 32);
                cd_offset = read_u64(data, rec + 48);
            }
        }
    }

    let cd_offset = cd_offset as usize;
    if cd_offset >= data.len() {
        bail!("offset de central directory hors archive ({cd_offset})");
    }
    Ok((cd_offset, cd_entries as usize))
}

/// Parcourt le central directory. Une entrée malformée est ignorée et le
/// parcours continue : on préfère un inventaire partiel à un échec total.
fn parse_central_directory(data: &[u8], start: usize, announced: usize) -> Vec<Entry> {
    let mut entries = Vec::with_capacity(announced.min(4096));
    let mut off = start;

    while off + CDH_FIXED <= data.len() {
        if read_u32(data, off) != SIG_CDH {
            break;
        }
        let flags = read_u16(data, off + 8);
        let method = read_u16(data, off + 10);
        let mut comp_size = read_u32(data, off + 20) as u64;
        let mut uncomp_size = read_u32(data, off + 24) as u64;
        let name_len = read_u16(data, off + 28) as usize;
        let extra_len = read_u16(data, off + 30) as usize;
        let comment_len = read_u16(data, off + 32) as usize;
        let mut lfh_offset = read_u32(data, off + 42) as u64;

        let name_start = off + CDH_FIXED;
        let name_end = name_start + name_len;
        let extra_end = name_end + extra_len;
        let next = extra_end + comment_len;
        if next > data.len() {
            break;
        }

        // Les noms trafiqués ne sont pas forcément de l'UTF-8 valide : on
        // remplace au lieu de rejeter l'entrée.
        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();

        // Extra field ZIP64 (header id 0x0001) : ne renseigne que les champs
        // saturés, dans l'ordre uncomp, comp, offset.
        if extra_len >= 4 {
            let mut p = name_end;
            while p + 4 <= extra_end {
                let id = read_u16(data, p);
                let len = read_u16(data, p + 2) as usize;
                let body = p + 4;
                if body + len > extra_end {
                    break;
                }
                if id == 0x0001 {
                    let mut q = body;
                    if uncomp_size == 0xFFFF_FFFF && q + 8 <= body + len {
                        uncomp_size = read_u64(data, q);
                        q += 8;
                    }
                    if comp_size == 0xFFFF_FFFF && q + 8 <= body + len {
                        comp_size = read_u64(data, q);
                        q += 8;
                    }
                    if lfh_offset == 0xFFFF_FFFF && q + 8 <= body + len {
                        lfh_offset = read_u64(data, q);
                    }
                    break;
                }
                p = body + len;
            }
        }

        if !name.is_empty() && !name.ends_with('/') {
            entries.push(Entry {
                name,
                method,
                flags,
                comp_size,
                uncomp_size,
                lfh_offset,
            });
        }
        off = next;
    }

    entries
}

#[inline]
fn read_u16(d: &[u8], off: usize) -> u16 {
    if off + 2 > d.len() {
        return 0;
    }
    u16::from_le_bytes([d[off], d[off + 1]])
}

#[inline]
fn read_u32(d: &[u8], off: usize) -> u32 {
    if off + 4 > d.len() {
        return 0;
    }
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

#[inline]
fn read_u64(d: &[u8], off: usize) -> u64 {
    if off + 8 > d.len() {
        return 0;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[off..off + 8]);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    /// res/raw/output.mp3 de Chrysaor : 0 octet. Une entrée stored, une deflate,
    /// puis une entrée pleine qui ne doit pas déteindre sur les vides.
    fn archive_with_empty_entries() -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            let deflated =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zw.start_file("res/raw/output.mp3", stored).unwrap();
            zw.start_file("assets/vide.bin", deflated).unwrap();
            zw.start_file("assets/plein.bin", deflated).unwrap();
            zw.write_all(b"contenu").unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn empty_entries_read_as_empty_not_unreadable() {
        let zip = TolerantZip::from_bytes(archive_with_empty_entries()).unwrap();
        assert_eq!(zip.len(), 3);
        assert!(zip.entries()[0].declares_empty());
        assert_eq!(zip.read(0).unwrap(), Vec::<u8>::new());
        assert_eq!(zip.read(1).unwrap(), Vec::<u8>::new());
        assert_eq!(zip.read(2).unwrap(), b"contenu");
    }

    #[test]
    fn an_empty_deflate_stream_is_recognised() {
        assert!(inflates_to_nothing(&[0x03, 0x00]));
        assert!(inflates_to_nothing(&[0x01, 0x00, 0x00, 0xff, 0xff]));
        assert!(!inflates_to_nothing(&[]));
        let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(b"x").unwrap();
        assert!(!inflates_to_nothing(&z.finish().unwrap()));
    }
}
