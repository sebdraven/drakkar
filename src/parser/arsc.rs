//! Lecture de `resources.arsc` : identifiant -> nom -> valeur.
//!
//! # Pourquoi
//!
//! Une chaîne d'interface se voit aujourd'hui sous deux formes — son nom dans
//! `R.string` (`please_find_more_details_in_mlite`) et son identifiant dans le
//! code (`0x7f110228`) — mais jamais avec sa valeur. Il fallait sortir de
//! l'outil (`aapt2 dump strings`, `apktool d`), ce qui interdit tout balayage
//! sur un corpus. Ce module ferme le trou sans dépendance externe.
//!
//! # Format
//!
//! Conteneur de chunks typés, identique à celui de l'AXML (`ResChunk_header` :
//! type u16, headerSize u16, size u32), d'où la réutilisation de
//! [`super::axml::StringPool`] — c'est le MÊME chunk `RES_STRING_POOL_TYPE`.
//!
//! ```text
//! RES_TABLE_TYPE (0x0002)            en-tête global, packageCount
//!   RES_STRING_POOL_TYPE (0x0001)    pool global : les VALEURS des chaînes
//!   RES_TABLE_PACKAGE_TYPE (0x0200)  un package, son id (0x7f pour l'app)
//!     RES_STRING_POOL_TYPE           noms de types (string, layout, xml…)
//!     RES_STRING_POOL_TYPE           noms d'entrées (les clés de R.*)
//!     RES_TABLE_TYPE_SPEC_TYPE (0x0202)
//!     RES_TABLE_TYPE_TYPE (0x0201)   entrées d'un type pour UNE configuration
//! ```
//!
//! Un identifiant se décompose en `0xPPTTEEEE` : package, type (1-indexé, c'est
//! l'index dans le pool des noms de types), index d'entrée.
//!
//! # Périmètre
//!
//! Les VALEURS retenues sont celles de la configuration **par défaut** (tous les
//! octets de `ResTable_config` à zéro : pas de locale, pas de densité, pas de
//! version d'API). Les autres configurations sont parcourues quand même, mais
//! n'alimentent que le compteur [`ResourceEntry::configs`] — une entrée qui
//! n'existe qu'en `fr` ou qu'en `hdpi` sort donc avec son nom, son identifiant,
//! et une valeur vide plutôt que d'être absente de l'inventaire.
//!
//! Les bags (styles, tableaux, pluriels — `FLAG_COMPLEX`) n'ont pas de valeur
//! scalaire : ils sortent avec [`ValueKind::Bag`]. Leur contenu n'est pas déplié.
//!
//! # Tolérance
//!
//! Même principe que [`super::axml`] : tout accès est borné, un chunk
//! inexploitable est sauté et non fatal, et rien ne panique sur un fichier
//! tronqué ou trafiqué. Un `resources.arsc` absent ou illisible donne un message
//! nommant la cause.
//!
//! Référence de format : AOSP `frameworks/base/libs/androidfw/ResourceTypes.h`.
//!
//! Toutes les étiquettes produites sont définies dans [`legend`].

use super::axml::StringPool;
use anyhow::{bail, Context, Result};
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

/// Nom de l'entrée d'archive qui porte la table.
pub const ARSC_ENTRY: &str = "resources.arsc";

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;

const CHUNK_HEADER: usize = 8;
const TABLE_HEADER: usize = 12;

/// Décalages dans `ResTable_package`. Le nom du package occupe 128 unités
/// UTF-16 entre [`PKG_NAME`] et [`PKG_TYPE_STRINGS`].
const PKG_ID: usize = 8;
const PKG_NAME: usize = 12;
const PKG_NAME_UNITS: usize = 128;
const PKG_TYPE_STRINGS: usize = 268;
const PKG_KEY_STRINGS: usize = 276;

/// Décalages dans `ResTable_type`, avant `ResTable_config`.
const TYPE_ID: usize = 8;
const TYPE_FLAGS: usize = 9;
const TYPE_ENTRY_COUNT: usize = 12;
const TYPE_ENTRIES_START: usize = 16;
const TYPE_CONFIG: usize = 20;

/// Table d'offsets creuse : paires (index d'entrée, offset/4) au lieu d'un
/// tableau dense.
const FLAG_SPARSE: u8 = 0x01;
/// Offsets sur 16 bits, exprimés en mots de 4 octets.
const FLAG_OFFSET16: u8 = 0x02;

/// L'entrée est un bag (style, tableau, pluriel) : pas de valeur scalaire.
const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
/// Entrée compacte (aapt2 récent) : 8 octets au lieu de 16, la clé prend la
/// place du champ `size` et la valeur celle du champ `key`.
const ENTRY_FLAG_COMPACT: u16 = 0x0008;

const NO_ENTRY: u32 = 0xFFFF_FFFF;
const NO_ENTRY_16: u16 = 0xFFFF;

/// Plafond d'entrées par chunk de type. Un `entryCount` trafiqué annoncerait
/// des millions d'entrées sur un fichier de quelques kilo-octets.
const MAX_ENTRIES_PER_TYPE: usize = 65_536;

// ─────────────────────────────────────────────────────────────────────────────
// Modèle
// ─────────────────────────────────────────────────────────────────────────────

/// Nature de la valeur d'une entrée, en configuration par défaut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueKind {
    Null,
    String,
    Reference,
    Attribute,
    Float,
    Dimension,
    Fraction,
    Int,
    Hex,
    Bool,
    Color,
    /// Style, tableau ou pluriel : l'entrée existe mais n'a pas de valeur
    /// scalaire.
    Bag,
    /// L'entrée n'est définie dans AUCUNE configuration par défaut — elle
    /// n'existe qu'en locale, densité ou version d'API particulière.
    Absent,
    /// Type de données hors de ceux que le module rend.
    Unknown,
}

impl ValueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::String => "string",
            Self::Reference => "reference",
            Self::Attribute => "attribute",
            Self::Float => "float",
            Self::Dimension => "dimension",
            Self::Fraction => "fraction",
            Self::Int => "int",
            Self::Hex => "hex",
            Self::Bool => "bool",
            Self::Color => "color",
            Self::Bag => "bag",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

/// Une ressource : son identifiant, son type, son nom, sa valeur par défaut.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceEntry {
    /// `0xPPTTEEEE`. Sérialisé en hexadécimal : c'est la forme sous laquelle il
    /// apparaît dans `R.java`, dans le code et dans les rapports.
    #[serde(serialize_with = "as_hex")]
    pub id: u32,
    pub package_id: u32,
    pub package: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub name: String,
    /// Valeur en configuration par défaut. `None` pour un bag comme pour une
    /// entrée définie seulement ailleurs — [`ResourceEntry::value_kind`] les
    /// distingue.
    pub value: Option<String>,
    pub value_kind: ValueKind,
    /// Nombre de configurations qui définissent l'entrée, défaut comprise.
    pub configs: usize,
}

impl ResourceEntry {
    pub fn id_hex(&self) -> String {
        format!("{:#010x}", self.id)
    }

    /// Valeur prête pour une colonne TSV : jamais de tabulation ni de saut de
    /// ligne, absence rendue par la chaîne vide.
    pub fn value_tsv(&self) -> String {
        match &self.value {
            Some(v) => v.replace(['\n', '\r', '\t'], " "),
            None => String::new(),
        }
    }
}

pub(crate) fn as_hex<S: Serializer>(v: &u32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:#010x}"))
}

/// Un package de la table.
#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    #[serde(serialize_with = "as_hex")]
    pub id: u32,
    pub name: String,
    pub entries: usize,
}

/// La table entière, indexée pour les trois interrogations utiles :
/// par identifiant, par nom, par type.
#[derive(Debug, Default, Serialize)]
pub struct ResourceTable {
    pub packages: Vec<PackageInfo>,
    pub entries: Vec<ResourceEntry>,
    /// Chaînes lues dans le pool global (les valeurs). Situe la table sans la
    /// rendre.
    pub global_strings: usize,
    /// Ce qui a été sauté ou ramené, jamais en silence.
    pub anomalies: Vec<String>,
    #[serde(skip)]
    by_id: HashMap<u32, usize>,
    #[serde(skip)]
    by_name: HashMap<String, Vec<usize>>,
}

impl ResourceTable {
    pub fn by_id(&self, id: u32) -> Option<&ResourceEntry> {
        self.by_id.get(&id).map(|i| &self.entries[*i])
    }

    /// Toutes les entrées portant ce nom. Les noms ne sont uniques QUE par
    /// type : `app_name` peut être à la fois une `string` et un `id`.
    pub fn by_name(&self, name: &str) -> Vec<&ResourceEntry> {
        self.by_name
            .get(name)
            .map(|v| v.iter().map(|i| &self.entries[*i]).collect())
            .unwrap_or_default()
    }

    pub fn by_type<'a>(&'a self, type_name: &'a str) -> impl Iterator<Item = &'a ResourceEntry> {
        self.entries
            .iter()
            .filter(move |e| e.type_name == type_name)
    }

    pub fn contains(&self, id: u32) -> bool {
        self.by_id.contains_key(&id)
    }

    /// Identifiants de package réellement présents dans la table. C'est ce qui
    /// définit la plage de candidats du balayage DEX : un entier `0x01…`
    /// (ressource du framework) n'est pas candidat si la table n'a pas de
    /// package `0x01`.
    pub fn package_ids(&self) -> Vec<u32> {
        self.packages.iter().map(|p| p.id).collect()
    }

    /// Vrai si l'octet de poids fort correspond à un package de la table.
    /// Condition NÉCESSAIRE, pas suffisante : [`contains`](Self::contains) fait
    /// seule le filtrage.
    pub fn in_package_range(&self, value: u32) -> bool {
        let pkg = value >> 24;
        pkg != 0 && self.packages.iter().any(|p| p.id == pkg)
    }

    /// Types présents, triés, dédoublonnés.
    pub fn type_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries.iter().map(|e| e.type_name.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    fn index(&mut self) {
        self.by_id.clear();
        self.by_name.clear();
        for (i, e) in self.entries.iter().enumerate() {
            self.by_id.insert(e.id, i);
            self.by_name.entry(e.name.clone()).or_default().push(i);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entrée depuis l'APK
// ─────────────────────────────────────────────────────────────────────────────

/// Lit et parse le `resources.arsc` d'un APK.
pub fn extract(apk: &Path) -> Result<ResourceTable> {
    let raw = read_arsc_bytes(apk)?;
    parse(&raw).with_context(|| format!("{} : resources.arsc illisible", apk.display()))
}

/// Extrait les octets de l'entrée `resources.arsc`.
///
/// Même repli que [`super::manifest`] : le crate `zip` ne contrôle le drapeau de
/// chiffrement et la méthode de compression qu'à la LECTURE de l'entrée. Sur les
/// archives trafiquées du corpus, l'ouverture passe et c'est `by_name` ou
/// `read_to_end` qui échoue.
fn read_arsc_bytes(apk: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(apk).with_context(|| format!("open {}", apk.display()))?;

    let nominal = (|| -> Result<Vec<u8>> {
        let mut zip = zip::ZipArchive::new(file).context("lecture de l'APK en zip")?;
        let mut entry = zip.by_name(ARSC_ENTRY).context("entrée absente")?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        Ok(buf)
    })();

    let err = match nominal {
        Ok(buf) => return Ok(buf),
        Err(e) => e,
    };
    tracing::warn!(
        apk = %apk.display(),
        error = %err,
        "resources.arsc illisible par le crate zip, repli sur le lecteur tolérant"
    );

    let zip = super::apkzip::TolerantZip::open(apk)?;
    if !zip.entries().iter().any(|e| e.name == ARSC_ENTRY) {
        bail!(
            "{} ne contient pas resources.arsc — APK sans ressources compilées, \
             ou entrée renommée (voir --list-entries)",
            apk.display()
        );
    }
    zip.read_by_name(ARSC_ENTRY)
        .context("resources.arsc illisible, y compris par le lecteur tolérant")
}

// ─────────────────────────────────────────────────────────────────────────────
// Parseur
// ─────────────────────────────────────────────────────────────────────────────

/// Parse une table de ressources depuis ses octets.
pub fn parse(data: &[u8]) -> Result<ResourceTable> {
    if data.len() < TABLE_HEADER {
        bail!("resources.arsc trop court : {} octets", data.len());
    }
    let typ = u16_at(data, 0).unwrap_or(0);
    if typ != RES_TABLE_TYPE {
        bail!(
            "resources.arsc : chunk de tête de type {typ:#06x}, attendu \
             RES_TABLE_TYPE (0x0002) — ce n'est pas une table de ressources"
        );
    }

    let end = announced_end(data, 0, data.len());
    let header_size = u16_at(data, 2).unwrap_or(0) as usize;
    let start = if (TABLE_HEADER..=end).contains(&header_size) {
        header_size
    } else {
        TABLE_HEADER
    };
    let declared_packages = u32_at(data, 8).unwrap_or(0) as usize;

    let mut table = ResourceTable::default();
    let mut global = StringPool::default();

    for (typ, off, size) in chunks(data, start, end) {
        let chunk = &data[off..off + size];
        match typ {
            RES_STRING_POOL_TYPE => {
                if global.is_empty() {
                    global = StringPool::parse(chunk);
                    table.global_strings = global.len();
                    if global.unreadable() > 0 {
                        table.anomalies.push(format!(
                            "{} chaîne(s) du pool global illisible(s) (offset ou longueur hors pool)",
                            global.unreadable()
                        ));
                    }
                }
            }
            RES_TABLE_PACKAGE_TYPE => parse_package(chunk, &global, &mut table),
            other => table
                .anomalies
                .push(format!("chunk de type {other:#06x} ignoré au niveau table")),
        }
    }

    if table.packages.len() != declared_packages {
        table.anomalies.push(format!(
            "{} package(s) lu(s) pour {declared_packages} annoncé(s)",
            table.packages.len()
        ));
    }
    if table.entries.is_empty() {
        bail!(
            "resources.arsc parsé mais vide : {} package(s), pool global de {} chaîne(s)",
            table.packages.len(),
            table.global_strings
        );
    }

    table.entries.sort_by_key(|e| e.id);
    table.index();

    tracing::info!(
        packages = table.packages.len(),
        entries = table.entries.len(),
        strings = table.global_strings,
        anomalies = table.anomalies.len(),
        "resources.arsc parsé"
    );
    Ok(table)
}

fn parse_package(chunk: &[u8], global: &StringPool, table: &mut ResourceTable) {
    let id = u32_at(chunk, PKG_ID).unwrap_or(0);
    let name = utf16_name(chunk, PKG_NAME, PKG_NAME_UNITS);

    let type_pool = pool_at(chunk, u32_at(chunk, PKG_TYPE_STRINGS).unwrap_or(0) as usize);
    let key_pool = pool_at(chunk, u32_at(chunk, PKG_KEY_STRINGS).unwrap_or(0) as usize);
    if type_pool.is_empty() || key_pool.is_empty() {
        table.anomalies.push(format!(
            "package {id:#04x} : pool de types ({} chaînes) ou de clés ({} chaînes) vide, \
             entrées non nommables",
            type_pool.len(),
            key_pool.len()
        ));
        return;
    }

    let end = announced_end(chunk, 0, chunk.len());
    let header_size = u16_at(chunk, 2).unwrap_or(0) as usize;
    let start = if (CHUNK_HEADER..=end).contains(&header_size) {
        header_size
    } else {
        CHUNK_HEADER
    };

    // Une entrée par identifiant : la première configuration par défaut
    // rencontrée fixe la valeur, les suivantes n'incrémentent que le compteur.
    let mut acc: HashMap<u32, ResourceEntry> = HashMap::new();

    for (typ, off, size) in chunks(chunk, start, end) {
        let inner = &chunk[off..off + size];
        match typ {
            RES_TABLE_TYPE_TYPE => parse_type(
                inner,
                id,
                &name,
                &type_pool,
                &key_pool,
                global,
                &mut acc,
                &mut table.anomalies,
            ),
            // Le pool de types et celui des clés sont atteints par leurs offsets
            // déclarés, pas par ce parcours ; le typeSpec ne porte que des
            // drapeaux de configuration, dont on ne fait rien.
            RES_STRING_POOL_TYPE | RES_TABLE_TYPE_SPEC_TYPE => {}
            other => table.anomalies.push(format!(
                "chunk de type {other:#06x} ignoré dans le package {id:#04x}"
            )),
        }
    }

    table.packages.push(PackageInfo {
        id,
        name,
        entries: acc.len(),
    });
    table.entries.extend(acc.into_values());
}

#[allow(clippy::too_many_arguments)]
fn parse_type(
    chunk: &[u8],
    package_id: u32,
    package_name: &str,
    type_pool: &StringPool,
    key_pool: &StringPool,
    global: &StringPool,
    acc: &mut HashMap<u32, ResourceEntry>,
    anomalies: &mut Vec<String>,
) {
    let type_id = match chunk.get(TYPE_ID) {
        Some(0) | None => return,
        Some(v) => *v as u32,
    };
    let flags = chunk.get(TYPE_FLAGS).copied().unwrap_or(0);
    let declared = u32_at(chunk, TYPE_ENTRY_COUNT).unwrap_or(0) as usize;
    let entries_start = u32_at(chunk, TYPE_ENTRIES_START).unwrap_or(0) as usize;
    let header_size = u16_at(chunk, 2).unwrap_or(0) as usize;
    if header_size < TYPE_CONFIG || header_size > chunk.len() {
        anomalies.push(format!(
            "type {type_id:#04x} : headerSize {header_size} incohérent, chunk sauté"
        ));
        return;
    }

    // Le nom du type est l'entrée `type_id - 1` du pool : les identifiants de
    // type sont 1-indexés.
    let type_name = match type_pool.get(type_id - 1) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => format!("type{type_id:#04x}"),
    };

    let is_default = config_is_default(chunk, TYPE_CONFIG, header_size);
    let sparse = flags & FLAG_SPARSE != 0;
    let offset16 = flags & FLAG_OFFSET16 != 0;

    let count = declared.min(MAX_ENTRIES_PER_TYPE);
    if count < declared {
        anomalies.push(format!(
            "type {type_name} : entryCount {declared} ramené à {count}"
        ));
    }

    for i in 0..count {
        // Table d'offsets : dense (u32, ou u16 en mots de 4 octets) ou creuse
        // (paires index/offset, l'offset en mots de 4 octets).
        let (index, rel) = if sparse {
            let at = header_size + i * 4;
            match (u16_at(chunk, at), u16_at(chunk, at + 2)) {
                (Some(idx), Some(off)) => (idx as usize, off as usize * 4),
                _ => break,
            }
        } else if offset16 {
            match u16_at(chunk, header_size + i * 2) {
                Some(NO_ENTRY_16) => continue,
                Some(off) => (i, off as usize * 4),
                None => break,
            }
        } else {
            match u32_at(chunk, header_size + i * 4) {
                Some(NO_ENTRY) => continue,
                Some(off) => (i, off as usize),
                None => break,
            }
        };

        let at = match entries_start.checked_add(rel) {
            Some(v) => v,
            None => continue,
        };
        let Some((key_index, value)) = parse_entry(chunk, at) else {
            continue;
        };
        let name = match key_pool.get(key_index) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };

        let id = (package_id << 24) | (type_id << 16) | (index as u32 & 0xFFFF);
        let slot = acc.entry(id).or_insert_with(|| ResourceEntry {
            id,
            package_id,
            package: package_name.to_string(),
            type_name: type_name.clone(),
            name,
            value: None,
            value_kind: ValueKind::Absent,
            configs: 0,
        });
        slot.configs += 1;

        // Seule la configuration par défaut donne une valeur. Un bag y est
        // signalé comme tel, sans être déplié.
        if is_default && slot.value_kind == ValueKind::Absent {
            match value {
                Some((data_type, data)) => {
                    let (rendered, kind) = render_value(data_type, data, global);
                    slot.value = Some(rendered);
                    slot.value_kind = kind;
                }
                None => slot.value_kind = ValueKind::Bag,
            }
        }
    }
}

/// Lit un `ResTable_entry` et rend (index de clé, valeur scalaire éventuelle).
///
/// Trois formes : compacte (8 octets, aapt2 récent — la clé occupe le champ
/// `size` et la valeur le champ `key`), bag (`FLAG_COMPLEX`, pas de valeur
/// scalaire), simple (en-tête puis `Res_value`).
fn parse_entry(chunk: &[u8], at: usize) -> Option<(u32, Option<(u8, u32)>)> {
    let first = u16_at(chunk, at)?;
    let flags = u16_at(chunk, at + 2)?;

    if flags & ENTRY_FLAG_COMPACT != 0 {
        let data = u32_at(chunk, at + 4)?;
        return Some((first as u32, Some(((flags >> 8) as u8, data))));
    }

    let key = u32_at(chunk, at + 4)?;
    if flags & ENTRY_FLAG_COMPLEX != 0 {
        return Some((key, None));
    }

    // `first` est la taille de l'en-tête d'entrée : la `Res_value` la suit.
    let size = if first as usize >= 8 {
        first as usize
    } else {
        8
    };
    let value_at = at.checked_add(size)?;
    let data_type = *chunk.get(value_at + 3)?;
    let data = u32_at(chunk, value_at + 4)?;
    Some((key, Some((data_type, data))))
}

/// Rend une `Res_value` en texte, avec la nature qui va avec.
fn render_value(data_type: u8, data: u32, global: &StringPool) -> (String, ValueKind) {
    match data_type {
        0x00 => (String::new(), ValueKind::Null),
        0x01 => (format!("@{data:#010x}"), ValueKind::Reference),
        0x02 => (format!("?{data:#010x}"), ValueKind::Attribute),
        0x03 => (
            global.get(data).unwrap_or_default().to_string(),
            ValueKind::String,
        ),
        0x04 => (f32::from_bits(data).to_string(), ValueKind::Float),
        0x05 => (complex(data, DIMENSION_UNITS), ValueKind::Dimension),
        0x06 => (complex(data, FRACTION_UNITS), ValueKind::Fraction),
        0x10 => ((data as i32).to_string(), ValueKind::Int),
        0x11 => (format!("{data:#x}"), ValueKind::Hex),
        0x12 => ((data != 0).to_string(), ValueKind::Bool),
        0x1c..=0x1f => (format!("#{data:08x}"), ValueKind::Color),
        _ => (format!("{data:#010x}"), ValueKind::Unknown),
    }
}

const DIMENSION_UNITS: &[&str] = &["px", "dip", "sp", "pt", "in", "mm"];
const FRACTION_UNITS: &[&str] = &["%", "%p"];

/// Décode un `TYPE_DIMENSION` / `TYPE_FRACTION` : mantisse de 24 bits signée,
/// radix sur deux bits, unité sur quatre.
fn complex(data: u32, units: &[&str]) -> String {
    const MANTISSA_MULT: f32 = 1.0 / (1 << 8) as f32;
    let radix = [
        MANTISSA_MULT,
        MANTISSA_MULT / (1 << 7) as f32,
        MANTISSA_MULT / (1 << 15) as f32,
        MANTISSA_MULT / (1 << 23) as f32,
    ];
    let value = ((data & 0xFFFF_FF00) as i32) as f32 * radix[((data >> 4) & 3) as usize];
    let unit = units.get((data & 0x0F) as usize).copied().unwrap_or("");
    format!("{value}{unit}")
}

/// Vrai si toute la `ResTable_config` est à zéro : ni locale, ni densité, ni
/// version d'API, ni orientation. C'est la définition de « configuration par
/// défaut » — la seule dont ce module retient les valeurs.
fn config_is_default(chunk: &[u8], at: usize, header_size: usize) -> bool {
    let size = u32_at(chunk, at).unwrap_or(0) as usize;
    let end = at.saturating_add(size).min(header_size).min(chunk.len());
    let body = at + 4;
    if body >= end {
        // Config réduite à son seul champ de taille : rien n'est qualifié.
        return true;
    }
    chunk[body..end].iter().all(|b| *b == 0)
}

/// Parse le string pool situé à `off` dans `chunk`, en contrôlant que c'en est
/// bien un. Rend un pool vide plutôt que d'échouer.
fn pool_at(chunk: &[u8], off: usize) -> StringPool {
    if off < CHUNK_HEADER || off + CHUNK_HEADER > chunk.len() {
        return StringPool::default();
    }
    if u16_at(chunk, off).unwrap_or(0) != RES_STRING_POOL_TYPE {
        return StringPool::default();
    }
    let size = u32_at(chunk, off + 4).unwrap_or(0) as usize;
    let end = if size >= CHUNK_HEADER && off + size <= chunk.len() {
        off + size
    } else {
        chunk.len()
    };
    StringPool::parse(&chunk[off..end])
}

/// Parcourt les chunks de `data` entre `from` et `end`, en se fiant à `size`
/// puis à `headerSize` — exactement la discipline du décodeur AXML tolérant.
fn chunks(data: &[u8], from: usize, end: usize) -> Vec<(u16, usize, usize)> {
    let mut out = Vec::new();
    let mut off = from;
    while off + CHUNK_HEADER <= end {
        let typ = u16_at(data, off).unwrap_or(0);
        let hsize = u16_at(data, off + 2).unwrap_or(0) as usize;
        let csize = u32_at(data, off + 4).unwrap_or(0) as usize;

        let step = if csize >= CHUNK_HEADER && off + csize <= end {
            csize
        } else if hsize >= CHUNK_HEADER && off + hsize <= end {
            hsize
        } else {
            break;
        };
        out.push((typ, off, step));
        off += step;
    }
    out
}

/// Fin exploitable d'un chunk : la taille annoncée ne sert qu'à RACCOURCIR le
/// parcours, jamais à l'allonger.
fn announced_end(data: &[u8], off: usize, cap: usize) -> usize {
    let announced = u32_at(data, off + 4).unwrap_or(0) as usize;
    let end = off.saturating_add(announced);
    if (off + CHUNK_HEADER..=cap).contains(&end) {
        end
    } else {
        cap
    }
}

/// Nom de package : UTF-16 terminé par un zéro, sur `units` unités au plus.
fn utf16_name(chunk: &[u8], at: usize, units: usize) -> String {
    let mut out = Vec::with_capacity(units);
    for i in 0..units {
        match u16_at(chunk, at + i * 2) {
            Some(0) | None => break,
            Some(u) => out.push(u),
        }
    }
    String::from_utf16_lossy(&out)
}

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

// ─────────────────────────────────────────────────────────────────────────────
// Identifiants
// ─────────────────────────────────────────────────────────────────────────────

/// Interprétations possibles d'un identifiant donné en argument, dans l'ordre
/// de préférence : `0x…` est hexadécimal ; une suite de chiffres décimaux est
/// lue en décimal PUIS en hexadécimal ; tout le reste en hexadécimal.
///
/// La double lecture existe parce que `2131886120` et `7f110228` désignent la
/// même ressource et que les deux formes circulent — `R.java` donne la seconde,
/// un dump de constantes DEX la première. L'appelant retient celle qui résout.
pub fn parse_id_candidates(s: &str) -> Vec<u32> {
    let t = s.trim().trim_start_matches(['@', '#']);
    let mut out = Vec::new();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if let Ok(v) = u32::from_str_radix(hex, 16) {
            out.push(v);
        }
        return out;
    }
    if t.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(v) = t.parse::<u32>() {
            out.push(v);
        }
    }
    if let Ok(v) = u32::from_str_radix(t, 16) {
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Légende
// ─────────────────────────────────────────────────────────────────────────────

pub fn legend() -> &'static str {
    "\
Table de ressources (resources.arsc)

Sortie TSV : sample, type, nom, id, valeur — une ligne par ressource, en-tête compris.

sample               Nom de base du fichier d'entrée, sans extension. Présent aussi en mode
                     single : c'est l'axe du croisement sur un corpus nommé par SHA-256.
id                   Identifiant 0xPPTTEEEE : PP = package (0x7f pour l'application), TT = type
                     (1-indexé, index dans le pool des noms de types), EEEE = index d'entrée.
                     Toujours rendu en hexadécimal sur 8 chiffres, comme dans R.java.
type                 Nom du type tel que stocké dans la table : string, layout, drawable, id,
                     xml, style, array… Ce n'est pas une catégorie inventée ici.
nom                  Nom d'entrée, c'est-à-dire la clé de R.<type>.<nom>. Unique PAR TYPE
                     seulement : le même nom peut exister en string et en id.
valeur               Valeur en configuration PAR DÉFAUT, rendue selon son type de données :
                       string      la chaîne, depuis le pool global
                       reference   @0xPPTTEEEE — NON résolue (repasser l'id à --resource-id)
                       attribute   ?0xPPTTEEEE
                       int / hex   entier signé / notation 0x
                       bool        true / false
                       color       #aarrggbb
                       dimension   valeur + unité (px, dip, sp, pt, in, mm)
                       fraction    valeur + % ou %p
                       float       valeur
                     Une valeur VIDE n'est pas une valeur nulle : voir value_kind.
value_kind           (JSON) Nature de la valeur. Deux cas font une colonne valeur vide :
                       bag       style, tableau ou pluriel : l'entrée n'a pas de valeur scalaire.
                                 Son contenu n'est pas déplié par ce module.
                       absent    l'entrée n'est définie dans AUCUNE configuration par défaut —
                                 elle n'existe qu'en locale, densité ou version d'API
                                 particulière. Son nom et son id restent exacts.
configs              (JSON) Nombre de configurations qui définissent l'entrée, défaut comprise.
                     > 1 = l'entrée est traduite ou déclinée ; seule la valeur par défaut est
                     rendue ici.
package              Nom du package de ressources, et son id.
anomalies            Ce qui a été sauté ou ramené pendant le parsing : chunk de type inconnu,
                     compteur incohérent, pool illisible. Jamais d'omission silencieuse.

Périmètre assumé : seule la configuration par défaut porte des valeurs (ResTable_config
entièrement à zéro : pas de locale, pas de densité, pas de version d'API). Les autres
configurations sont parcourues — elles alimentent `configs` — mais leurs valeurs ne sont pas
rendues. Une traduction française n'est donc PAS visible ici.

Formes d'identifiant acceptées par --resource-id : 0x7f110228, 7f110228, 2131886120. Une suite
de chiffres décimaux est essayée en décimal puis en hexadécimal, et la lecture qui résout est
retenue.

Lecture de l'archive : chemin nominal par le crate zip, repli sur src/parser/apkzip.rs quand il
refuse l'entrée. Un APK sans resources.arsc, ou dont la table est illisible, sort en [FAIL] avec
la cause — jamais une panique, jamais un inventaire vide silencieux."
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

    /// Chunk de string pool UTF-8, même construction que les tests d'axml.
    fn string_pool(strings: &[&str]) -> Vec<u8> {
        const POOL_HEADER: usize = 28;
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
        let strings_start = POOL_HEADER + offsets.len() * 4;
        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_STRING_POOL_TYPE));
        c.extend_from_slice(&u16b(POOL_HEADER as u16));
        c.extend_from_slice(&u32b((strings_start + body.len()) as u32));
        c.extend_from_slice(&u32b(strings.len() as u32));
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

    /// Chunk `ResTable_type` dense, une entrée par index, valeurs `(clé, type, data)`.
    /// `locale` non vide qualifie la configuration, qui n'est alors plus la
    /// configuration par défaut.
    fn type_chunk(type_id: u8, entries: &[Option<(u32, u8, u32)>], locale: &[u8; 2]) -> Vec<u8> {
        const HEADER: usize = 84;
        const CONFIG_SIZE: usize = 64;

        let mut offsets = Vec::new();
        let mut body = Vec::new();
        for e in entries {
            match e {
                None => offsets.push(NO_ENTRY),
                Some((key, dt, data)) => {
                    offsets.push(body.len() as u32);
                    body.extend_from_slice(&u16b(8));
                    body.extend_from_slice(&u16b(0));
                    body.extend_from_slice(&u32b(*key));
                    body.extend_from_slice(&u16b(8));
                    body.push(0);
                    body.push(*dt);
                    body.extend_from_slice(&u32b(*data));
                }
            }
        }
        let entries_start = HEADER + offsets.len() * 4;

        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_TABLE_TYPE_TYPE));
        c.extend_from_slice(&u16b(HEADER as u16));
        c.extend_from_slice(&u32b((entries_start + body.len()) as u32));
        c.push(type_id);
        c.push(0);
        c.extend_from_slice(&u16b(0));
        c.extend_from_slice(&u32b(entries.len() as u32));
        c.extend_from_slice(&u32b(entries_start as u32));
        // ResTable_config : taille, imsi, puis la locale à l'offset 8.
        let mut config = vec![0u8; CONFIG_SIZE];
        config[0..4].copy_from_slice(&u32b(CONFIG_SIZE as u32));
        config[8] = locale[0];
        config[9] = locale[1];
        c.extend_from_slice(&config);
        for o in &offsets {
            c.extend_from_slice(&u32b(*o));
        }
        c.extend_from_slice(&body);
        c
    }

    fn package(id: u32, types: &[&str], keys: &[&str], chunks: &[Vec<u8>]) -> Vec<u8> {
        const HEADER: usize = 288;
        let type_pool = string_pool(types);
        let key_pool = string_pool(keys);
        let type_off = HEADER;
        let key_off = type_off + type_pool.len();
        let body = chunks.concat();

        let mut c = Vec::new();
        c.extend_from_slice(&u16b(RES_TABLE_PACKAGE_TYPE));
        c.extend_from_slice(&u16b(HEADER as u16));
        c.extend_from_slice(&u32b(
            (HEADER + type_pool.len() + key_pool.len() + body.len()) as u32,
        ));
        c.extend_from_slice(&u32b(id));
        c.extend_from_slice(&vec![0u8; PKG_NAME_UNITS * 2]);
        c.extend_from_slice(&u32b(type_off as u32));
        c.extend_from_slice(&u32b(0));
        c.extend_from_slice(&u32b(key_off as u32));
        c.extend_from_slice(&u32b(0));
        // typeIdOffset, présent dans les paquets récents.
        c.extend_from_slice(&u32b(0));
        assert_eq!(c.len(), HEADER);
        c.extend_from_slice(&type_pool);
        c.extend_from_slice(&key_pool);
        c.extend_from_slice(&body);
        c
    }

    fn table(global: &[&str], packages: &[Vec<u8>]) -> Vec<u8> {
        let pool = string_pool(global);
        let body = packages.concat();
        let mut d = Vec::new();
        d.extend_from_slice(&u16b(RES_TABLE_TYPE));
        d.extend_from_slice(&u16b(TABLE_HEADER as u16));
        d.extend_from_slice(&u32b((TABLE_HEADER + pool.len() + body.len()) as u32));
        d.extend_from_slice(&u32b(packages.len() as u32));
        d.extend_from_slice(&pool);
        d.extend_from_slice(&body);
        d
    }

    /// Le cas de référence : type 0x11, entrée 0x0228 -> 0x7f110228.
    fn reference_table() -> Vec<u8> {
        let mut entries: Vec<Option<(u32, u8, u32)>> = vec![None; 0x229];
        entries[0x228] = Some((0, 0x03, 0));
        let types: Vec<String> = (1..=0x11).map(|i| format!("t{i}")).collect();
        let mut names: Vec<&str> = types.iter().map(|s| s.as_str()).collect();
        names[0x10] = "string";
        table(
            &["Please, find more details in mLite"],
            &[package(
                0x7f,
                &names,
                &["please_find_more_details_in_mlite"],
                &[type_chunk(0x11, &entries, b"\0\0")],
            )],
        )
    }

    #[test]
    fn resout_le_cas_de_reference() {
        let t = parse(&reference_table()).unwrap();
        let e = t.by_id(0x7f11_0228).expect("entrée 0x7f110228");
        assert_eq!(e.type_name, "string");
        assert_eq!(e.name, "please_find_more_details_in_mlite");
        assert_eq!(
            e.value.as_deref(),
            Some("Please, find more details in mLite")
        );
        assert_eq!(e.value_kind, ValueKind::String);
        assert_eq!(t.by_name("please_find_more_details_in_mlite").len(), 1);
    }

    #[test]
    fn plage_de_package_limitee_aux_packages_presents() {
        let t = parse(&reference_table()).unwrap();
        assert!(t.in_package_range(0x7f11_0228));
        assert!(!t.in_package_range(0x0104_0000));
        assert!(t.contains(0x7f11_0228));
        assert!(!t.contains(0x7f11_0229));
    }

    #[test]
    fn configuration_non_defaut_nomme_sans_valeur() {
        let entries = vec![Some((0u32, 0x03u8, 0u32))];
        let d = table(
            &["bonjour"],
            &[package(
                0x7f,
                &["string"],
                &["hello"],
                &[type_chunk(1, &entries, b"fr")],
            )],
        );
        let t = parse(&d).unwrap();
        let e = t.by_id(0x7f01_0000).unwrap();
        assert_eq!(e.name, "hello");
        assert_eq!(e.value, None);
        assert_eq!(e.value_kind, ValueKind::Absent);
        assert_eq!(e.configs, 1);
    }

    #[test]
    fn defaut_prime_et_compte_les_configurations() {
        let entries = vec![Some((0u32, 0x03u8, 0u32))];
        let d = table(
            &["hello", "bonjour"],
            &[package(
                0x7f,
                &["string"],
                &["hello"],
                &[
                    type_chunk(1, &entries, b"\0\0"),
                    type_chunk(1, &[Some((0, 0x03, 1))], b"fr"),
                ],
            )],
        );
        let t = parse(&d).unwrap();
        let e = t.by_id(0x7f01_0000).unwrap();
        assert_eq!(e.value.as_deref(), Some("hello"));
        assert_eq!(e.configs, 2);
    }

    #[test]
    fn refuse_ce_qui_n_est_pas_une_table() {
        assert!(parse(b"PK\x03\x04").is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn tronque_ne_panique_pas() {
        let full = reference_table();
        for cut in [13, 40, 120, 300, 512] {
            if cut < full.len() {
                let _ = parse(&full[..cut]);
            }
        }
    }

    #[test]
    fn identifiants_acceptes() {
        assert_eq!(parse_id_candidates("0x7f110228"), vec![0x7f11_0228]);
        assert_eq!(parse_id_candidates("7f110228"), vec![0x7f11_0228]);
        assert_eq!(parse_id_candidates("@0x7f110228"), vec![0x7f11_0228]);
        // Suite de chiffres : décimal d'abord. Ici la lecture hexadécimale
        // déborderait d'un u32, elle n'est donc pas proposée.
        assert_eq!(parse_id_candidates("2131886120"), vec![2_131_886_120]);
        assert_eq!(parse_id_candidates("7f110228"), vec![0x7f11_0228]);
        assert_eq!(
            parse_id_candidates("12345678"),
            vec![12_345_678, 0x1234_5678]
        );
    }

    #[test]
    fn rendu_des_valeurs() {
        let pool = StringPool::default();
        assert_eq!(render_value(0x12, 1, &pool).0, "true");
        assert_eq!(render_value(0x11, 0x1a, &pool).0, "0x1a");
        assert_eq!(render_value(0x10, u32::MAX, &pool).0, "-1");
        assert_eq!(render_value(0x1c, 0xff00_00ff, &pool).0, "#ff0000ff");
        assert_eq!(render_value(0x01, 0x7f11_0228, &pool).0, "@0x7f110228");
        assert_eq!(render_value(0x05, (16 << 8) | 1, &pool).0, "16dip");
    }
}
