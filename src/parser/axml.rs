//! Décodeur AXML tolérant, calqué sur le chargeur de ressources d'Android.
//!
//! # Pourquoi
//!
//! Le repli `apkzip::TolerantZip` rend bien l'entrée `AndroidManifest.xml` des
//! archives trafiquées, mais le décodage du manifest binaire échoue ensuite.
//! Deux formes relevées sur le corpus :
//!
//! - chunk de type inconnu au milieu du flux d'éléments — `axmldecoder` ne sait
//!   pas l'ignorer et interrompt le document
//!   (`49002e994539fa11eab6b7a273cf90272dda43aa3dd9784fde4c23bf3645fdcb`) ;
//! - offset de string pool hors bornes — `axmldecoder` indexe la tranche à
//!   l'aveugle et panique
//!   (`c3b6af64627e711d0292ce3797947423c9adeb200cfe75a55600362236f612e5`).
//!
//! Android encaisse les deux. `ResXMLParser` avance chunk par chunk en se fiant
//! au seul `ResChunk_header::size` et saute ce qu'il ne connaît pas ;
//! `ResStringPool` contrôle chaque offset et rend `NULL` plutôt que de lire hors
//! du pool. Référence : AOSP `frameworks/base/libs/androidfw/ResourceTypes.cpp`.
//!
//! # Principe
//!
//! Même motif qu'`apkzip` : chemin nominal `axmldecoder`, bascule ici sur erreur
//! **ou** sur panic. Les APK sains ne voient rien changer.
//!
//! 1. parcourir les chunks en se fiant à `size`, ignorer les types inconnus ;
//! 2. borner tout accès au pool — index, offsets, longueurs déclarées ;
//! 3. nommer les attributs par le resource map quand le pool ne rend rien ;
//! 4. refermer les éléments restés ouverts à la fin du flux.
//!
//! # Limites assumées
//!
//! - pas de `resources.arsc` : une valeur qui référence une ressource sort sous
//!   sa forme numérique (`@0x7f0a0001`), jamais résolue. Depuis
//!   [`super::arsc`], l'identifiant peut être résolu à la main
//!   (`--resource-id`), mais le décodage du manifeste ne fait pas la jointure ;
//! - le CDATA est écarté, aucun consommateur ne le lit ;
//! - la profondeur d'imbrication est plafonnée à [`MAX_DEPTH`] : au-delà, le
//!   sous-arbre est écarté ;
//! - le repli nomme `manifest` une racine dont le tag est illisible. Un
//!   `AndroidManifest.xml` n'a pas d'autre racine possible, et le
//!   `PackageParser` d'Android ne contrôle pas davantage.

use anyhow::{anyhow, bail, Result};
use std::cell::Cell;
use std::sync::Once;

// ─────────────────────────────────────────────────────────────────────────────
// Arbre
// ─────────────────────────────────────────────────────────────────────────────

/// Un élément du manifest, indépendant du décodeur qui l'a produit.
#[derive(Debug, Clone, Default)]
pub struct Element {
    tag: String,
    attributes: Vec<(String, String)>,
    children: Vec<Element>,
}

impl Element {
    pub fn get_tag(&self) -> &str {
        &self.tag
    }

    pub fn get_children(&self) -> &[Element] {
        &self.children
    }

    pub fn get_attributes(&self) -> &[(String, String)] {
        &self.attributes
    }

    /// Attribut par nom exact, puis par suffixe (gère le préfixe `android:`).
    pub fn attr(&self, key: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|(k, _)| k == key)
            .or_else(|| {
                self.attributes
                    .iter()
                    .find(|(k, _)| k.split(':').next_back() == Some(key))
            })
            .map(|(_, v)| v.clone())
    }

    /// Attribut interprété en booléen. AXML encode `true` par `0xffffffff`.
    pub fn attr_bool(&self, key: &str) -> Option<bool> {
        match self.attr(key)?.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "0xffffffff" | "-1" => Some(true),
            "false" | "0" | "0x0" => Some(false),
            _ => None,
        }
    }

    /// Attribut interprété en entier non signé (décimal ou hexadécimal `0x…`).
    pub fn attr_u32(&self, key: &str) -> Option<u32> {
        let v = self.attr(key)?;
        let v = v.trim();
        match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => v.parse::<u32>().ok(),
        }
    }
}

/// Résultat du décodage : la racine, et par quel chemin elle a été obtenue.
pub struct Decoded {
    pub root: Element,
    /// Vrai quand `axmldecoder` a échoué et que le repli tolérant a pris le
    /// relais — l'arbre peut être partiel.
    pub tolerant: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Point d'entrée
// ─────────────────────────────────────────────────────────────────────────────

/// Décode un `AndroidManifest.xml` binaire.
pub fn decode(raw: &[u8]) -> Result<Decoded> {
    match nominal(raw) {
        Ok(root) => Ok(Decoded {
            root,
            tolerant: false,
        }),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "AXML refusé par axmldecoder, repli sur le décodeur tolérant"
            );
            Ok(Decoded {
                root: decode_tolerant(raw)?,
                tolerant: true,
            })
        }
    }
}

fn nominal(raw: &[u8]) -> Result<Element> {
    let doc = match quietly(|| axmldecoder::parse(raw)) {
        Ok(Ok(doc)) => doc,
        Ok(Err(e)) => bail!("{e}"),
        Err(_) => bail!("panic du décodeur"),
    };
    match doc.get_root().as_ref() {
        Some(axmldecoder::Node::Element(e)) => Ok(from_axmldecoder(e)),
        Some(_) => bail!("racine du document non élémentaire"),
        None => bail!("document sans racine"),
    }
}

fn from_axmldecoder(e: &axmldecoder::Element) -> Element {
    Element {
        tag: e.get_tag().to_string(),
        attributes: e
            .get_attributes()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        children: e
            .get_children()
            .iter()
            .filter_map(|n| match n {
                axmldecoder::Node::Element(c) => Some(from_axmldecoder(c)),
                _ => None,
            })
            .collect(),
    }
}

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}
static QUIET_HOOK: Once = Once::new();

/// Exécute `f` en retenant le message de panic **sur ce seul thread** : le repli
/// tolérant traite le cas, il n'y a rien à écrire sur stderr. Le hook installé
/// délègue au précédent hors de la région gardée, pour ne rien masquer ailleurs
/// (le mode bulk parallélise avec rayon).
fn quietly<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> std::thread::Result<T> {
    QUIET_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.with(|q| q.get()) {
                previous(info);
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let out = std::panic::catch_unwind(f);
    QUIET.with(|q| q.set(false));
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Décodeur tolérant
// ─────────────────────────────────────────────────────────────────────────────

const RES_STRING_POOL: u16 = 0x0001;
const RES_XML: u16 = 0x0003;
const RES_XML_START_NAMESPACE: u16 = 0x0100;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const RES_XML_END_ELEMENT: u16 = 0x0103;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;

const CHUNK_HEADER: usize = 8;
const NODE_HEADER: usize = 16;
const POOL_HEADER: usize = 28;
/// Taille de `ResXMLTree_attrExt`, soit le décalage nominal du premier attribut.
const ATTR_EXT: usize = 20;
/// Taille de `ResXMLTree_attribute`.
const ATTR_SIZE: usize = 20;

const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// Profondeur d'imbrication au-delà de laquelle le sous-arbre est écarté. Un
/// AXML trafiqué peut annoncer des milliers d'ouvertures sans fermeture, et les
/// consommateurs parcourent l'arbre récursivement.
const MAX_DEPTH: usize = 256;

fn decode_tolerant(data: &[u8]) -> Result<Element> {
    if data.len() < CHUNK_HEADER {
        bail!("AXML trop court : {} octets", data.len());
    }
    let typ = u16_at(data, 0).unwrap_or(0);
    if typ != RES_XML {
        tracing::debug!(
            typ = format!("{typ:#06x}"),
            "en-tête AXML inattendu, décodage tenté quand même"
        );
    }

    // La taille annoncée ment sur les échantillons trafiqués : elle ne sert
    // qu'à raccourcir le parcours, jamais à l'allonger.
    let announced = u32_at(data, 4).unwrap_or(0) as usize;
    let end = if (CHUNK_HEADER..=data.len()).contains(&announced) {
        announced
    } else {
        data.len()
    };
    let header_size = u16_at(data, 2).unwrap_or(0) as usize;
    let mut off = if (CHUNK_HEADER..=end).contains(&header_size) {
        header_size
    } else {
        CHUNK_HEADER
    };

    let mut pool = StringPool::default();
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut namespaces: Vec<(String, String)> =
        vec![(ANDROID_NS.to_string(), "android".to_string())];
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut ignored = 0usize;

    while off + CHUNK_HEADER <= end {
        let typ = u16_at(data, off).unwrap_or(0);
        let hsize = u16_at(data, off + 2).unwrap_or(0) as usize;
        let csize = u32_at(data, off + 4).unwrap_or(0) as usize;

        let step = if csize >= CHUNK_HEADER && off + csize <= end {
            csize
        } else if hsize >= CHUNK_HEADER && off + hsize <= end {
            // Taille de chunk nulle ou débordante : l'en-tête reste le seul
            // champ crédible pour retrouver le chunk suivant.
            hsize
        } else {
            tracing::debug!(
                offset = off,
                "taille de chunk inexploitable, parcours interrompu"
            );
            break;
        };
        let chunk = &data[off..off + step];

        match typ {
            RES_STRING_POOL => {
                if pool.is_empty() {
                    pool = StringPool::parse(chunk);
                }
            }
            RES_XML_RESOURCE_MAP => resource_ids = parse_resource_map(chunk, hsize),
            RES_XML_START_NAMESPACE => {
                let prefix = u32_at(chunk, NODE_HEADER).and_then(|i| pool.get(i));
                let uri = u32_at(chunk, NODE_HEADER + 4).and_then(|i| pool.get(i));
                if let (Some(prefix), Some(uri)) = (prefix, uri) {
                    namespaces.push((uri.to_string(), prefix.to_string()));
                }
            }
            RES_XML_START_ELEMENT => stack.push(parse_start_element(
                chunk,
                hsize,
                &pool,
                &resource_ids,
                &namespaces,
            )),
            RES_XML_END_ELEMENT => {
                if let Some(done) = stack.pop() {
                    close(&mut stack, &mut root, done);
                }
            }
            _ => ignored += 1,
        }
        off += step;
    }

    // Éléments jamais refermés : le flux s'arrête au milieu de l'arbre plutôt
    // que d'être invalide. On les referme dans l'ordre.
    while let Some(done) = stack.pop() {
        close(&mut stack, &mut root, done);
    }

    let mut root = root.ok_or_else(|| anyhow!("aucun élément exploitable dans l'AXML"))?;
    if root.tag.is_empty() {
        root.tag = "manifest".to_string();
    }

    tracing::info!(
        chaines = pool.len(),
        illisibles = pool.unreadable(),
        chunks_ignores = ignored,
        tag = %root.tag,
        enfants = root.children.len(),
        "AXML décodé par le repli tolérant"
    );
    Ok(root)
}

/// Rattache un élément refermé à son parent, ou l'installe comme racine.
fn close(stack: &mut [Element], root: &mut Option<Element>, done: Element) {
    if stack.len() > MAX_DEPTH {
        return;
    }
    match stack.last_mut() {
        Some(parent) => parent.children.push(done),
        None => {
            root.get_or_insert(done);
        }
    }
}

fn parse_resource_map(chunk: &[u8], hsize: usize) -> Vec<u32> {
    let start = if (CHUNK_HEADER..=chunk.len()).contains(&hsize) {
        hsize
    } else {
        CHUNK_HEADER
    };
    chunk[start..]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect()
}

fn parse_start_element(
    chunk: &[u8],
    hsize: usize,
    pool: &StringPool,
    resource_ids: &[u32],
    namespaces: &[(String, String)],
) -> Element {
    let base = if hsize >= NODE_HEADER && hsize + ATTR_EXT <= chunk.len() {
        hsize
    } else {
        NODE_HEADER
    };
    let tag = u32_at(chunk, base + 4)
        .and_then(|i| pool.get(i))
        .unwrap_or_default()
        .to_string();

    let attr_start = u16_at(chunk, base + 8).unwrap_or(0) as usize;
    let attr_size = u16_at(chunk, base + 10).unwrap_or(0) as usize;
    let declared = u16_at(chunk, base + 12).unwrap_or(0) as usize;

    let attr_start = attr_start.max(ATTR_EXT);
    let attr_size = attr_size.max(ATTR_SIZE);
    let first = base + attr_start;
    let count = declared.min(chunk.len().saturating_sub(first) / attr_size);

    let mut attributes = Vec::with_capacity(count);
    for i in 0..count {
        let a = first + i * attr_size;
        let ns = u32_at(chunk, a).unwrap_or(u32::MAX);
        let name_idx = u32_at(chunk, a + 4).unwrap_or(u32::MAX);
        let raw = u32_at(chunk, a + 8).unwrap_or(u32::MAX);
        let data_type = chunk.get(a + 15).copied().unwrap_or(0);
        let data = u32_at(chunk, a + 16).unwrap_or(0);

        // Nom vide ou illisible : seul le resource id fait foi, comme dans le
        // chargeur d'Android.
        let name = match pool.get(name_idx).filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => match resource_ids
                .get(name_idx as usize)
                .and_then(|id| attr_name_from_resource_id(*id))
            {
                Some(s) => s.to_string(),
                None => continue,
            },
        };

        let key = match pool
            .get(ns)
            .and_then(|uri| namespaces.iter().find(|(u, _)| u == uri))
        {
            Some((_, prefix)) => format!("{prefix}:{name}"),
            None => name,
        };

        let value = match pool.get(raw).filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => typed_value(data_type, data, pool),
        };
        attributes.push((key, value));
    }

    Element {
        tag,
        attributes,
        children: Vec::new(),
    }
}

/// Valeur typée d'un attribut, dans la notation du manifest source quand elle
/// existe. Diverge d'`axmldecoder` sur deux points, tous deux sur le seul
/// chemin de repli : les entiers `TYPE_INT_DEC` sortent signés (c'est ce
/// qu'affiche `aapt dump`, et `android:priority` est souvent négatif) et
/// `TYPE_INT_HEX` sort en base 16.
fn typed_value(data_type: u8, data: u32, pool: &StringPool) -> String {
    match data_type {
        0x00 => String::new(),
        0x01 => format!("@{data:#010x}"),
        0x02 => format!("?{data:#010x}"),
        0x03 => pool.get(data).unwrap_or_default().to_string(),
        0x04 => f32::from_bits(data).to_string(),
        0x10 => (data as i32).to_string(),
        0x11 => format!("{data:#x}"),
        0x12 => {
            if data == 0 {
                "false".to_string()
            } else {
                "true".to_string()
            }
        }
        0x1c..=0x1f => format!("#{data:08x}"),
        _ => format!("{data:#010x}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// String pool
// ─────────────────────────────────────────────────────────────────────────────

/// Pool de chaînes borné : tout accès hors limites rend `None` au lieu de
/// paniquer. `None` couvre aussi bien l'index absent que la chaîne dont l'offset
/// ou la longueur sortait du pool.
///
/// Partagé avec [`super::arsc`] : `resources.arsc` porte exactement le même
/// chunk `RES_STRING_POOL_TYPE`, aux mêmes offsets et au même drapeau UTF-8.
#[derive(Default)]
pub(crate) struct StringPool {
    strings: Vec<Option<String>>,
}

impl StringPool {
    pub(crate) fn parse(chunk: &[u8]) -> Self {
        let header_size = u16_at(chunk, 2).unwrap_or(0) as usize;
        let declared = u32_at(chunk, 8).unwrap_or(0) as usize;
        let flags = u32_at(chunk, 16).unwrap_or(0);
        let strings_start = u32_at(chunk, 20).unwrap_or(0) as usize;

        let offsets_at = if (POOL_HEADER..=chunk.len()).contains(&header_size) {
            header_size
        } else {
            POOL_HEADER
        };
        if strings_start < offsets_at || strings_start >= chunk.len() {
            tracing::warn!(
                strings_start,
                taille = chunk.len(),
                "string pool : début des chaînes hors du chunk, pool abandonné"
            );
            return Self::default();
        }

        // Le compte annoncé déborde parfois sur les données : on le ramène à ce
        // que la table d'offsets peut réellement contenir.
        let room = (strings_start - offsets_at) / 4;
        if declared > room {
            tracing::warn!(
                declared,
                room,
                "string pool : compte de chaînes ramené à la taille de la table d'offsets"
            );
        }
        let count = declared.min(room);
        let utf8 = flags & (1 << 8) != 0;
        let body = &chunk[strings_start..];

        let strings = (0..count)
            .map(|i| {
                let offset = u32_at(chunk, offsets_at + i * 4)? as usize;
                if utf8 {
                    decode_utf8(body, offset)
                } else {
                    decode_utf16(body, offset)
                }
            })
            .collect();
        Self { strings }
    }

    pub(crate) fn get(&self, index: u32) -> Option<&str> {
        if index == u32::MAX {
            return None;
        }
        self.strings.get(index as usize)?.as_deref()
    }

    pub(crate) fn len(&self) -> usize {
        self.strings.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    pub(crate) fn unreadable(&self) -> usize {
        self.strings.iter().filter(|s| s.is_none()).count()
    }
}

/// Longueur préfixée sur un ou deux octets (bit de poids fort = suite).
fn length_u8(d: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = *d.get(off)?;
    if first & 0x80 == 0 {
        return Some((first as usize, off + 1));
    }
    let second = *d.get(off + 1)?;
    Some(((((first & 0x7f) as usize) << 8) | second as usize, off + 2))
}

/// Longueur préfixée sur un ou deux mots de 16 bits.
fn length_u16(d: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = u16_at(d, off)?;
    if first & 0x8000 == 0 {
        return Some((first as usize, off + 2));
    }
    let second = u16_at(d, off + 2)?;
    Some((
        (((first & 0x7fff) as usize) << 16) | second as usize,
        off + 4,
    ))
}

fn decode_utf8(d: &[u8], off: usize) -> Option<String> {
    let (_utf16_len, p) = length_u8(d, off)?;
    let (len, p) = length_u8(d, p)?;
    let end = p.saturating_add(len).min(d.len());
    Some(String::from_utf8_lossy(d.get(p..end)?).into_owned())
}

fn decode_utf16(d: &[u8], off: usize) -> Option<String> {
    let (len, p) = length_u16(d, off)?;
    let end = p.saturating_add(len.saturating_mul(2)).min(d.len());
    let units: Vec<u16> = d
        .get(p..end)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource ids
// ─────────────────────────────────────────────────────────────────────────────

/// Identifiants `android.R.attr` des attributs lus par les consommateurs du
/// manifest. Relevés dans `android.jar` (android-36.1), pas transcrits de
/// mémoire. Ne servent que lorsque le pool ne rend pas le nom de l'attribut.
///
/// `compileSdkVersion` et `compileSdkVersionCodename` sont absents : ce ne sont
/// pas des attributs publics, ils n'ont pas d'entrée dans `android.R.attr` et
/// AAPT écrit toujours leur nom dans le pool.
const ATTR_RESOURCE_IDS: &[(u32, &str)] = &[
    (0x0101_0000, "theme"),
    (0x0101_0001, "label"),
    (0x0101_0002, "icon"),
    (0x0101_0003, "name"),
    (0x0101_0006, "permission"),
    (0x0101_0007, "readPermission"),
    (0x0101_0008, "writePermission"),
    (0x0101_0009, "protectionLevel"),
    (0x0101_000a, "permissionGroup"),
    (0x0101_000b, "sharedUserId"),
    (0x0101_000c, "hasCode"),
    (0x0101_000d, "persistent"),
    (0x0101_000e, "enabled"),
    (0x0101_000f, "debuggable"),
    (0x0101_0010, "exported"),
    (0x0101_0011, "process"),
    (0x0101_0012, "taskAffinity"),
    (0x0101_0013, "multiprocess"),
    (0x0101_0018, "authorities"),
    (0x0101_001b, "grantUriPermissions"),
    (0x0101_001c, "priority"),
    (0x0101_001d, "launchMode"),
    (0x0101_001f, "configChanges"),
    (0x0101_0024, "value"),
    (0x0101_0025, "resource"),
    (0x0101_0026, "mimeType"),
    (0x0101_0027, "scheme"),
    (0x0101_0028, "host"),
    (0x0101_0029, "port"),
    (0x0101_002a, "path"),
    (0x0101_002b, "pathPrefix"),
    (0x0101_002c, "pathPattern"),
    (0x0101_0202, "targetActivity"),
    (0x0101_020c, "minSdkVersion"),
    (0x0101_021b, "versionCode"),
    (0x0101_021c, "versionName"),
    (0x0101_0270, "targetSdkVersion"),
    (0x0101_0271, "maxSdkVersion"),
    (0x0101_0280, "allowBackup"),
    (0x0101_0281, "glEsVersion"),
    (0x0101_028e, "required"),
    (0x0101_02b7, "installLocation"),
    (0x0101_035a, "largeHeap"),
    (0x0101_04ea, "extractNativeLibs"),
    (0x0101_04ec, "usesCleartextTraffic"),
    (0x0101_0505, "directBootAware"),
    (0x0101_0527, "networkSecurityConfig"),
    (0x0101_057a, "appComponentFactory"),
];

fn attr_name_from_resource_id(id: u32) -> Option<&'static str> {
    ATTR_RESOURCE_IDS
        .iter()
        .find(|(k, _)| *k == id)
        .map(|(_, n)| *n)
}

// ─────────────────────────────────────────────────────────────────────────────
// Lectures bornées
// ─────────────────────────────────────────────────────────────────────────────

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let b: [u8; 2] = d.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(b))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let b: [u8; 4] = d.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16b(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }

    fn u32b(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// Chunk de string pool UTF-8. `announced` gonfle le compte déclaré,
    /// `corrupt` remplace l'offset de la chaîne d'index donné.
    fn string_pool(
        strings: &[&str],
        announced: Option<u32>,
        corrupt: Option<(usize, u32)>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(body.len() as u32);
            body.push(s.chars().count() as u8);
            body.push(s.len() as u8);
            body.extend_from_slice(s.as_bytes());
            body.push(0);
        }
        while body.len() % 4 != 0 {
            body.push(0);
        }
        if let Some((i, off)) = corrupt {
            offsets[i] = off;
        }

        let strings_start = POOL_HEADER + offsets.len() * 4;
        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_STRING_POOL));
        c.extend_from_slice(&u16b(POOL_HEADER as u16));
        c.extend_from_slice(&u32b((strings_start + body.len()) as u32));
        c.extend_from_slice(&u32b(announced.unwrap_or(strings.len() as u32)));
        c.extend_from_slice(&u32b(0));
        c.extend_from_slice(&u32b(1 << 8));
        c.extend_from_slice(&u32b(strings_start as u32));
        c.extend_from_slice(&u32b(0));
        for o in &offsets {
            c.extend_from_slice(&u32b(*o));
        }
        c.extend_from_slice(&body);
        c
    }

    fn resource_map(ids: &[u32]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_XML_RESOURCE_MAP));
        c.extend_from_slice(&u16b(CHUNK_HEADER as u16));
        c.extend_from_slice(&u32b((CHUNK_HEADER + ids.len() * 4) as u32));
        for id in ids {
            c.extend_from_slice(&u32b(*id));
        }
        c
    }

    /// Élément ouvrant. Chaque attribut : (index ns, index nom, index valeur).
    fn start(tag: u32, attrs: &[(u32, u32, u32)]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_XML_START_ELEMENT));
        c.extend_from_slice(&u16b(NODE_HEADER as u16));
        c.extend_from_slice(&u32b(
            (NODE_HEADER + ATTR_EXT + attrs.len() * ATTR_SIZE) as u32,
        ));
        c.extend_from_slice(&u32b(0));
        c.extend_from_slice(&u32b(u32::MAX));
        c.extend_from_slice(&u32b(u32::MAX));
        c.extend_from_slice(&u32b(tag));
        c.extend_from_slice(&u16b(ATTR_EXT as u16));
        c.extend_from_slice(&u16b(ATTR_SIZE as u16));
        c.extend_from_slice(&u16b(attrs.len() as u16));
        c.extend_from_slice(&u16b(0));
        c.extend_from_slice(&u16b(0));
        c.extend_from_slice(&u16b(0));
        for (ns, name, value) in attrs {
            c.extend_from_slice(&u32b(*ns));
            c.extend_from_slice(&u32b(*name));
            c.extend_from_slice(&u32b(*value));
            c.extend_from_slice(&u16b(8));
            c.push(0);
            c.push(0x03);
            c.extend_from_slice(&u32b(*value));
        }
        c
    }

    fn end(tag: u32) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_XML_END_ELEMENT));
        c.extend_from_slice(&u16b(NODE_HEADER as u16));
        c.extend_from_slice(&u32b((NODE_HEADER + 8) as u32));
        c.extend_from_slice(&u32b(0));
        c.extend_from_slice(&u32b(u32::MAX));
        c.extend_from_slice(&u32b(u32::MAX));
        c.extend_from_slice(&u32b(tag));
        c
    }

    /// Chunk de type `NullType` : ce que porte GodFather
    /// `49002e994539fa11eab6b7a273cf90272dda43aa3dd9784fde4c23bf3645fdcb`.
    fn null_chunk() -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&u16b(0x0000));
        c.extend_from_slice(&u16b(CHUNK_HEADER as u16));
        c.extend_from_slice(&u32b(CHUNK_HEADER as u32));
        c
    }

    fn document(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body = chunks.concat();
        let mut d = Vec::new();
        d.extend_from_slice(&u16b(RES_XML));
        d.extend_from_slice(&u16b(CHUNK_HEADER as u16));
        d.extend_from_slice(&u32b((CHUNK_HEADER + body.len()) as u32));
        d.extend_from_slice(&body);
        d
    }

    const STRINGS: &[&str] = &["manifest", "package", "com.example.app"];

    #[test]
    fn chemin_nominal_par_axmldecoder() {
        let doc = document(&[
            string_pool(STRINGS, None, None),
            resource_map(&[0]),
            start(0, &[(u32::MAX, 1, 2)]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert!(!d.tolerant);
        assert_eq!(d.root.get_tag(), "manifest");
        assert_eq!(d.root.attr("package").as_deref(), Some("com.example.app"));
    }

    #[test]
    fn chunk_de_type_inconnu_est_ignore() {
        let doc = document(&[
            string_pool(STRINGS, None, None),
            resource_map(&[0]),
            null_chunk(),
            start(0, &[(u32::MAX, 1, 2)]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert!(d.tolerant);
        assert_eq!(d.root.get_tag(), "manifest");
        assert_eq!(d.root.attr("package").as_deref(), Some("com.example.app"));
    }

    #[test]
    fn offset_de_chaine_hors_bornes_ne_perd_que_la_chaine() {
        let doc = document(&[
            string_pool(STRINGS, None, Some((2, 7_077_893))),
            resource_map(&[0]),
            start(0, &[(u32::MAX, 1, 2)]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert!(d.tolerant);
        assert_eq!(d.root.get_tag(), "manifest");
        assert_eq!(d.root.attr("package").as_deref(), Some(""));
    }

    #[test]
    fn compte_de_chaines_gonfle_est_ramene() {
        let doc = document(&[
            string_pool(STRINGS, Some(4096), None),
            resource_map(&[0]),
            start(0, &[(u32::MAX, 1, 2)]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert!(d.tolerant);
        assert_eq!(d.root.attr("package").as_deref(), Some("com.example.app"));
    }

    #[test]
    fn element_non_referme_est_rattache() {
        let doc = document(&[
            string_pool(&["manifest", "uses-sdk"], None, None),
            resource_map(&[0, 0]),
            start(0, &[]),
            start(1, &[]),
        ]);
        let d = decode(&doc).unwrap();
        assert!(d.tolerant);
        assert_eq!(d.root.get_tag(), "manifest");
        assert_eq!(d.root.get_children().len(), 1);
        assert_eq!(d.root.get_children()[0].get_tag(), "uses-sdk");
    }

    #[test]
    fn attribut_sans_nom_est_resolu_par_le_resource_map() {
        let doc = document(&[
            string_pool(&["service", "", "com.example.Svc"], None, None),
            resource_map(&[0, 0x0101_0003, 0]),
            null_chunk(),
            start(0, &[(u32::MAX, 1, 2)]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert!(d.tolerant);
        assert_eq!(d.root.get_tag(), "service");
        assert_eq!(d.root.attr("name").as_deref(), Some("com.example.Svc"));
    }

    #[test]
    fn racine_au_tag_illisible_est_nommee_manifest() {
        let doc = document(&[
            string_pool(&["manifest"], None, Some((0, 9_999_999))),
            resource_map(&[0]),
            start(0, &[]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert!(d.tolerant);
        assert_eq!(d.root.get_tag(), "manifest");
    }

    #[test]
    fn attributs_typiques() {
        let doc = document(&[
            string_pool(&["a", "exported", "true", "minSdk", "0x1a"], None, None),
            resource_map(&[0]),
            null_chunk(),
            start(0, &[(u32::MAX, 1, 2), (u32::MAX, 3, 4)]),
            end(0),
        ]);
        let d = decode(&doc).unwrap();
        assert_eq!(d.root.attr_bool("exported"), Some(true));
        assert_eq!(d.root.attr_u32("minSdk"), Some(26));
    }
}
