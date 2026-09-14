//! Inventaire et export des entrées `assets/` d'un APK.
//!
//! # Pourquoi un module à part
//!
//! `assets/` est le dépotoir des packers et des droppers : DEX chiffré de
//! 360 Jiagu, second étage d'un dropper sous un nom anodin, APK de plugin, blob
//! de configuration C2. [`super::entry_extract`] sait déjà sortir une entrée
//! nommée, mais il faut connaître son chemin ; ici on prend **tout `assets/`**
//! et on rend un inventaire mesuré (taille, méthode déclarée, SHA-256, type
//! reniflé, entropie) qui se lit à plat.
//!
//! # Ce que le module ne fait pas
//!
//! Il ne **déballe pas récursivement**. Un asset qui est lui-même un ZIP, un APK
//! ou un DEX est typé et écrit tel quel : le déballage reste une opération
//! explicite de l'utilisateur (repasser le fichier produit à `drakkar`). Sinon
//! l'inventaire mélangerait deux niveaux d'archive et les SHA-256 ne
//! désigneraient plus ce que l'APK contient réellement.
//!
//! # Lecture de l'archive
//!
//! Chemin nominal via le crate `zip`, repli sur [`super::apkzip`] dès que
//! celui-ci refuse quoi que ce soit — l'archive à l'ouverture comme une entrée à
//! la lecture. Le corpus contient des archives trafiquées (bit 0 des GP flags,
//! extra field `$JADXBLOCK`, méthode `0x64b4`, horodatages 2030, noms très
//! longs) qui font tomber apktool, JADX et androguard ; sans ce repli, ces APK
//! ressortiraient avec un `assets/` vide, ce qui est un faux négatif
//! indiscernable d'un APK réellement sans assets. Le champ [`AssetsReport::reader`]
//! dit lequel des deux lecteurs a produit l'inventaire.
//!
//! # Sémantique du SHA-256
//!
//! Le `sha256` d'un asset porte sur le **contenu DÉCOMPRESSÉ**, jamais sur les
//! octets stockés dans l'archive. Deux raisons, aucune cosmétique :
//!
//! * c'est la seule forme requêtable — VirusTotal, MalwareBazaar et Koodous
//!   indexent le fichier déballé ; un hash d'octets compressés ne se croise avec
//!   rien ;
//! * « les octets stockés » n'est même pas une notion stable ici. Sur les
//!   archives trafiquées, la méthode déclarée est fausse et [`super::apkzip`]
//!   essaie deflate puis stored : le même asset donnerait deux hashes selon le
//!   chemin de lecture emprunté. Le contenu déballé, lui, est identique par les
//!   deux lecteurs.
//!
//! Corollaire : un asset `stored` et le même contenu `deflate` ont le même
//! `sha256`. Le SHA-256 de l'APK conteneur, lui, porte sur le fichier entier
//! ([`AssetsReport::apk_sha256`]).
//!
//! # Écriture
//!
//! [`write_all`] n'écrit **jamais** hors du répertoire demandé : chemins
//! normalisés, `..`, chemins absolus et séparateurs Windows refusés, collisions
//! de noms suffixées, composants trop longs tronqués pour le système de
//! fichiers. Le chemin ORIGINAL de l'archive reste dans le JSON — c'est lui qui
//! sert au rapprochement, pas le nom écrit.
//!
//! # Filtrage par hash connu
//!
//! [`HashFilter`] restreint les assets retenus à un ensemble de sha256 connus
//! ([`HashMode::Keep`], pivot sur une charge) ou le retire ([`HashMode::Exclude`],
//! soustraction du déjà-qualifié). Deux invariants :
//!
//! * il s'applique APRÈS le calcul de l'empreinte d'ensemble, qui porte toujours
//!   sur la totalité des assets — une empreinte filtrée aurait l'apparence d'une
//!   empreinte valide tout en étant incomparable d'un échantillon à l'autre ;
//! * une entrée non évaluée n'a pas de hash, donc n'est jamais testée. C'est ce
//!   que compte [`AssetsReport::not_evaluated`] : sans lui, une absence de
//!   correspondance se lirait comme l'absence de l'asset.
//!
//! Toutes les étiquettes produites sont définies dans [`legend`].

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Préfixe d'archive retenu. La comparaison est insensible à la casse : les
/// archives trafiquées mélangent les conventions et rater `Assets/` serait un
/// faux négatif silencieux.
const ASSETS_PREFIX: &str = "assets/";

/// Longueur max d'un composant de chemin à l'écriture. 255 octets est la limite
/// commune d'ext4 et d'APFS ; au-delà le nom est tronqué et l'original consigné.
const MAX_COMPONENT: usize = 255;

/// Valeur portée par `sha256` et `kind` quand l'entrée n'a pas été lue, donc pas
/// hachée. Délibérément NON hexadécimale : un consommateur en aval qui la
/// prendrait pour un hash échouera bruyamment au lieu de croire à une identité.
pub const NOT_EVALUATED: &str = "NON-EVALUE";

/// Statuts possibles de l'empreinte d'ensemble. Constantes et non littéraux
/// épars : la valeur est comparée en aval, et une faute de frappe dans une des
/// copies ferait passer une empreinte incomplète pour utilisable.
pub const FP_COMPLETE: &str = "complet";
pub const FP_NO_ASSETS: &str = "aucun-asset";
pub const FP_INCOMPLETE: &str = "incomplet";

/// Options de filtrage d'une passe.
#[derive(Debug, Clone, Default)]
pub struct AssetsOptions {
    /// Sous-chaînes à retenir sur le chemin d'entrée (insensible à la casse).
    /// Vide = tout `assets/`.
    pub include: Vec<String>,
    /// Plafond de taille décompressée. Au-delà, l'entrée n'est pas lue : elle
    /// reste dans `entries` avec `evaluated: false` et un `sha256` à
    /// [`NOT_EVALUATED`].
    pub max_size: Option<u64>,
    /// Filtre par hash connu, appliqué APRÈS le calcul de l'empreinte
    /// d'ensemble — voir [`HashFilter`].
    pub hash_filter: Option<HashFilter>,
}

impl AssetsOptions {
    fn retains(&self, entry: &str) -> bool {
        if self.include.is_empty() {
            return true;
        }
        let lower = entry.to_ascii_lowercase();
        self.include
            .iter()
            .any(|p| lower.contains(&p.to_ascii_lowercase()))
    }
}

/// Sens d'application d'un ensemble de sha256 connus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashMode {
    /// Ne garder que les assets dont le sha256 est dans l'ensemble : pivot sur
    /// une charge connue (« quels binaires du corpus portent cet asset ? »).
    Keep,
    /// Retirer les assets dont le sha256 est dans l'ensemble : soustraction du
    /// déjà-qualifié (polices, libs de SDK) pour ne laisser que le reliquat.
    Exclude,
}

/// Ensemble de sha256 connus et sens d'application.
///
/// N'intervient JAMAIS dans le calcul de l'empreinte d'ensemble : une empreinte
/// filtrée serait incomparable d'un échantillon à l'autre tout en gardant
/// l'apparence d'une empreinte valide.
#[derive(Debug, Clone)]
pub struct HashFilter {
    pub mode: HashMode,
    /// Hashes normalisés en minuscules, 64 caractères hexadécimaux.
    pub hashes: HashSet<String>,
}

impl HashFilter {
    /// L'asymétrie sur les entrées non évaluées est délibérée : sans hash, une
    /// entrée ne peut pas être reconnue comme connue. Elle ne satisfait donc
    /// jamais un `Keep`, mais elle survit à un `Exclude` — n'étant pas
    /// qualifiée, elle appartient au reliquat.
    fn retains(&self, e: &AssetEntry) -> bool {
        match self.mode {
            HashMode::Keep => e.evaluated && self.hashes.contains(&e.sha256),
            HashMode::Exclude => !e.evaluated || !self.hashes.contains(&e.sha256),
        }
    }
}

/// Normalise et valide un sha256. `origin` nomme la source dans le message
/// d'erreur (option ou `fichier:ligne`).
///
/// Refuse tout ce qui n'est pas 64 caractères hexadécimaux. Pas de
/// correspondance par préfixe, pas de troncature, dans aucun sens : un préfixe
/// n'établit pas une identité.
pub fn normalize_hash(raw: &str, origin: &str) -> Result<String> {
    let h = raw.trim();
    let n = h.chars().count();
    if n != 64 {
        bail!(
            "{origin} : « {h} » fait {n} caractère(s) ; un SHA-256 en compte 64 — \
             un préfixe n'établit pas une identité et n'est pas accepté"
        );
    }
    if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "{origin} : « {h} » contient des caractères non hexadécimaux ; un SHA-256 \
             s'écrit avec 64 chiffres hexadécimaux"
        );
    }
    Ok(h.to_ascii_lowercase())
}

/// Lit un fichier de hashes : un par ligne, `#` introduit un commentaire, les
/// lignes vides sont ignorées, la casse est indifférente. La ligne fautive est
/// nommée.
pub fn read_hash_file(path: &Path) -> Result<Vec<String>> {
    let body =
        std::fs::read_to_string(path).with_context(|| format!("lecture {}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in body.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        out.push(normalize_hash(line, &format!("{}:{}", path.display(), n + 1))?);
    }
    Ok(out)
}

fn gather_hashes(values: &[String], file: Option<&Path>, opt: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (i, v) in values.iter().enumerate() {
        out.push(normalize_hash(v, &format!("{opt} #{}", i + 1))?);
    }
    if let Some(p) = file {
        out.extend(read_hash_file(p)?);
    }
    Ok(out)
}

/// Construit le filtre à partir des quatre sources possibles. Les deux sens sont
/// mutuellement exclusifs. `Ok(None)` si aucune source n'est fournie.
pub fn build_hash_filter(
    keep: &[String],
    keep_file: Option<&Path>,
    exclude: &[String],
    exclude_file: Option<&Path>,
) -> Result<Option<HashFilter>> {
    let keeps = gather_hashes(keep, keep_file, "--assets-hash")?;
    let excludes = gather_hashes(exclude, exclude_file, "--assets-hash-exclude")?;

    match (keeps.is_empty(), excludes.is_empty()) {
        (true, true) => Ok(None),
        (false, true) => Ok(Some(HashFilter {
            mode: HashMode::Keep,
            hashes: keeps.into_iter().collect(),
        })),
        (true, false) => Ok(Some(HashFilter {
            mode: HashMode::Exclude,
            hashes: excludes.into_iter().collect(),
        })),
        (false, false) => bail!(
            "--assets-hash / --assets-hash-file et --assets-hash-exclude / \
             --assets-hash-exclude-file sont mutuellement exclusifs"
        ),
    }
}

/// Lecteur ayant produit l'inventaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reader {
    /// Crate `zip`, chemin nominal.
    Nominal,
    /// [`super::apkzip`], archive trafiquée.
    Tolerant,
}

impl Reader {
    pub fn as_str(self) -> &'static str {
        match self {
            Reader::Nominal => "nominal",
            Reader::Tolerant => "tolerant",
        }
    }
}

/// Un asset inventorié.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEntry {
    /// Chemin ORIGINAL dans l'archive, jamais normalisé : `assets/payload.bin`.
    pub entry: String,
    /// Nom de fichier seul, tel que porté par l'archive.
    pub file: String,
    /// Taille stockée dans l'archive (après compression), déclarée.
    pub compressed_size: u64,
    /// Taille décompressée réelle, MESURÉE sur les octets lus — pas la valeur
    /// déclarée, qui ment sur les archives trafiquées.
    ///
    /// Exception : si `evaluated` est faux, rien n'a été lu et ce champ porte la
    /// valeur DÉCLARÉE, donc justement celle que ces archives falsifient. `note`
    /// le dit explicitement pour que la colonne ne se lise pas comme les autres.
    pub size: u64,
    /// Méthode de compression DÉCLARÉE, valeur brute. 0 = stored, 8 = deflate ;
    /// toute autre valeur est un marqueur de trafiquage (ex. `0x64b4`), la
    /// décompression n'en tient pas compte.
    pub method: u16,
    /// Forme lisible de `method` : `stored(0)`, `deflate(8)`, `0x64b4`.
    pub method_label: String,
    /// SHA-256 COMPLET du contenu DÉCOMPRESSÉ (64 caractères, jamais tronqué) —
    /// jamais des octets stockés dans l'archive, qui ne se croisent avec aucune
    /// base publique. Vaut [`NOT_EVALUATED`] si `evaluated` est faux.
    pub sha256: String,
    /// Type déduit des octets de tête, jamais de l'extension. Vaut
    /// [`NOT_EVALUATED`] si `evaluated` est faux.
    pub kind: String,
    /// Entropie de Shannon en bits par octet, arrondie à 2 décimales pour que
    /// console et JSON portent exactement la même valeur. 0.0 si `evaluated`
    /// est faux.
    pub entropy: f64,
    /// Faux quand l'entrée a été vue mais pas lue (plafond `--assets-max-size`).
    /// La ligne existe quand même : sur un échantillon packé, la plus grosse
    /// entrée d'`assets/` est souvent celle qui porte la charge, et une omission
    /// silencieuse y serait exactement au mauvais endroit. `size` porte alors la
    /// taille DÉCLARÉE, faute de mesure.
    pub evaluated: bool,
    /// Chemin réellement écrit sur disque, renseigné par [`write_all`].
    /// `None` en inventaire seul, ou si l'écriture a été refusée.
    pub written: Option<String>,
    /// Trace d'une divergence à l'écriture : refus (traversée de chemin),
    /// troncature de nom, suffixe de collision, erreur d'E/S.
    pub note: Option<String>,
    /// Octets complets, en mémoire. Exclus de la sérialisation (binaire).
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

/// Une entrée `assets/` vue mais non retenue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedAsset {
    pub entry: String,
    pub reason: String,
}

/// Inventaire des assets d'un APK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetsReport {
    /// Chemin de l'APK analysé.
    pub apk: String,
    /// SHA-256 complet de l'APK lui-même.
    pub apk_sha256: String,
    /// Lecteur ayant produit l'inventaire.
    pub reader: Reader,
    /// Nombre total d'entrées de l'archive (dénominateur du filtrage).
    pub scanned: usize,
    /// Entrées sous `assets/` avant application des filtres.
    pub assets_seen: usize,
    /// Assets retenus après filtrage par hash, dans l'ordre de l'archive. Les
    /// entrées non évaluées y figurent aussi (voir [`AssetEntry::evaluated`]).
    pub entries: Vec<AssetEntry>,
    /// Assets vus mais ILLISIBLES — le lecteur tolérant n'a rien pu en tirer.
    /// Distinct des non-évalués, qui restent dans `entries`.
    pub skipped: Vec<SkippedAsset>,
    /// Empreinte d'ensemble — axe de regroupement. `None` dès que l'ensemble des
    /// assets n'est pas intégralement connu : `fingerprint_status` dit pourquoi.
    pub fingerprint: Option<String>,
    /// `complet`, `aucun-asset`, ou `incomplet : <causes>`. Une empreinte
    /// calculée sur un sous-ensemble aurait l'apparence d'une empreinte valide
    /// tout en étant incomparable — d'où l'absence plutôt qu'une valeur.
    pub fingerprint_status: String,
    /// Entrées vues mais non hachées (plafond `--assets-max-size`), AVANT
    /// filtrage par hash. Un filtre par hash ne les teste jamais : sans ce
    /// compteur, l'absence de correspondance se lirait comme une absence
    /// de l'asset.
    pub not_evaluated: usize,
    /// Sens du filtre par hash appliqué à `entries`, s'il y en a un.
    pub hash_filter: Option<HashMode>,
    /// Taille de l'ensemble de hashes de référence.
    pub hash_filter_size: usize,
    /// Filtres appliqués, tels que fournis.
    pub include: Vec<String>,
    pub max_size: Option<u64>,
}

impl AssetsReport {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Empreinte utilisable comme axe de regroupement, ou `None`.
    ///
    /// À préférer à la lecture directe du champ : ne rend une valeur que si le
    /// statut la déclare complète, donc comparable à celle d'un autre
    /// échantillon. Une empreinte calculée sur un jeu tronqué ne peut pas
    /// ressortir par ici, même si les deux champs venaient à diverger.
    pub fn grouping_key(&self) -> Option<&str> {
        if self.fingerprint_status == FP_COMPLETE {
            self.fingerprint.as_deref()
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Inventaire
// ---------------------------------------------------------------------------

/// Inventorie les assets d'un APK. Rien n'est écrit sur disque : les octets
/// restent en mémoire, l'écriture est un appel séparé ([`write_all`]).
pub fn collect(apk: &Path, opts: &AssetsOptions) -> Result<AssetsReport> {
    let apk_sha256 = file_sha256(apk)?;

    let (reader, scanned, assets_seen, mut entries, skipped) = match collect_nominal(apk, opts) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                apk = %apk.display(),
                error = %e,
                "crate zip en échec sur les assets, repli sur le lecteur tolérant"
            );
            collect_tolerant(apk, opts)?
        }
    };

    // L'empreinte est calculée AVANT le filtrage par hash et sur l'ensemble
    // complet : filtrée, elle resterait d'apparence valide tout en devenant
    // incomparable d'un échantillon à l'autre.
    let (fingerprint, fingerprint_status) = fingerprint(&entries, assets_seen, opts, &skipped);

    // Une empreinte hexadécimale sous un statut autre que « complet » est la
    // seule combinaison qui classerait le corpus de travers en gardant l'air
    // correcte. `fingerprint` ne peut pas la produire ; ceci le garde vrai si
    // quelqu'un touche aux deux champs séparément plus tard.
    debug_assert_eq!(
        fingerprint.is_some(),
        fingerprint_status == FP_COMPLETE,
        "empreinte et statut désaccordés : {fingerprint:?} / {fingerprint_status}"
    );

    let not_evaluated = entries.iter().filter(|e| !e.evaluated).count();

    if let Some(f) = &opts.hash_filter {
        entries.retain(|e| f.retains(e));
    }

    Ok(AssetsReport {
        apk: apk.display().to_string(),
        apk_sha256,
        reader,
        scanned,
        assets_seen,
        entries,
        skipped,
        fingerprint,
        fingerprint_status,
        not_evaluated,
        hash_filter: opts.hash_filter.as_ref().map(|f| f.mode),
        hash_filter_size: opts.hash_filter.as_ref().map_or(0, |f| f.hashes.len()),
        include: opts.include.clone(),
        max_size: opts.max_size,
    })
}

type Collected = (Reader, usize, usize, Vec<AssetEntry>, Vec<SkippedAsset>);

/// Chemin nominal. Toute erreur — ouverture, entrée refusée, lecture — remonte
/// et déclenche le repli complet : un inventaire partiel serait pire qu'un
/// inventaire tolérant, parce qu'il se lit comme un inventaire complet.
fn collect_nominal(apk: &Path, opts: &AssetsOptions) -> Result<Collected> {
    let file = std::fs::File::open(apk).with_context(|| format!("ouverture {}", apk.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("lecture APK (zip)")?;

    let scanned = archive.len();
    let mut assets_seen = 0usize;
    let mut entries = Vec::new();

    // Toujours vide ici : dans le chemin nominal, une entrée illisible fait
    // basculer toute la passe sur le lecteur tolérant au lieu d'être consignée.
    let skipped = Vec::new();

    for i in 0..scanned {
        let mut zf = archive
            .by_index(i)
            .with_context(|| format!("entrée zip #{i}"))?;
        let name = zf.name().to_string();
        if !is_asset(&name) {
            continue;
        }
        assets_seen += 1;
        if !opts.retains(&name) {
            continue;
        }

        let declared_size = zf.size();
        let method = method_code(zf.compression());
        let compressed_size = zf.compressed_size();

        if let Some(cap) = opts.max_size.filter(|c| declared_size > *c) {
            entries.push(not_evaluated_entry(
                name,
                method,
                compressed_size,
                declared_size,
                format!("taille déclarée {declared_size} o > --assets-max-size {cap} o"),
            ));
            continue;
        }

        // La capacité suit la taille DÉCLARÉE, plafonnée : une archive trafiquée
        // annonce n'importe quoi, et `read_to_end` agrandira si besoin.
        let mut bytes = Vec::with_capacity(declared_size.min(16 * 1024 * 1024) as usize);

        // Le plafond borne la LECTURE, pas seulement le filtrage : sans cela une
        // entrée qui sous-déclare sa taille se déballerait entièrement en RAM
        // avant d'être écartée. On lit un octet de plus que le plafond pour que
        // le contrôle sur la taille réelle, dans `push_entry`, puisse déclencher.
        let read = match opts.max_size {
            Some(limit) => zf.by_ref().take(limit.saturating_add(1)).read_to_end(&mut bytes),
            None => zf.read_to_end(&mut bytes),
        };
        read.with_context(|| format!("lecture {name}"))?;

        push_entry(
            &mut entries,
            opts,
            name,
            method,
            compressed_size,
            declared_size,
            bytes,
        );
    }

    Ok((Reader::Nominal, scanned, assets_seen, entries, skipped))
}

/// Repli tolérant. Ici, contrairement au chemin nominal, une entrée illisible
/// est consignée et le parcours continue : c'est tout l'intérêt du lecteur, et
/// il n'y a plus de troisième niveau de repli derrière.
fn collect_tolerant(apk: &Path, opts: &AssetsOptions) -> Result<Collected> {
    let zip = super::apkzip::TolerantZip::open(apk)
        .with_context(|| format!("lecteur tolérant sur {}", apk.display()))?;
    tracing::warn!(
        entries = zip.len(),
        tampered = zip.tampered_count(),
        "lecteur tolérant actif sur les assets"
    );

    let scanned = zip.len();
    let mut assets_seen = 0usize;
    let mut entries = Vec::new();
    let mut skipped = Vec::new();

    for (i, e) in zip.entries().iter().enumerate() {
        let name = e.name.clone();
        if !is_asset(&name) {
            continue;
        }
        assets_seen += 1;
        if !opts.retains(&name) {
            continue;
        }
        if let Some(cap) = opts.max_size.filter(|c| e.uncomp_size > *c) {
            entries.push(not_evaluated_entry(
                name,
                e.method,
                e.comp_size,
                e.uncomp_size,
                format!(
                    "taille déclarée {} o > --assets-max-size {cap} o",
                    e.uncomp_size
                ),
            ));
            continue;
        }

        let bytes = match zip.read(i) {
            Ok(b) => b,
            Err(err) => {
                skipped.push(SkippedAsset {
                    entry: name,
                    reason: format!("illisible : {err:#}"),
                });
                continue;
            }
        };

        push_entry(
            &mut entries,
            opts,
            name,
            e.method,
            e.comp_size,
            e.uncomp_size,
            bytes,
        );
    }

    Ok((Reader::Tolerant, scanned, assets_seen, entries, skipped))
}

/// Mesure et range une entrée lue. Le plafond est revérifié sur la taille
/// RÉELLE : le central directory d'une archive trafiquée sous-déclare.
fn push_entry(
    entries: &mut Vec<AssetEntry>,
    opts: &AssetsOptions,
    name: String,
    method: u16,
    compressed_size: u64,
    declared_size: u64,
    bytes: Vec<u8>,
) {
    let size = bytes.len() as u64;
    // La lecture ayant été bornée à cap+1, `size` ne mesure pas le contenu : on
    // sait seulement qu'il dépasse. Le dire ainsi, pas comme une mesure.
    if let Some(cap) = opts.max_size.filter(|c| size > *c) {
        entries.push(not_evaluated_entry(
            name,
            method,
            compressed_size,
            declared_size,
            format!("contenu réel au-delà de --assets-max-size {cap} o (lecture bornée)"),
        ));
        return;
    }
    let file = name.rsplit('/').next().unwrap_or(&name).to_string();
    entries.push(AssetEntry {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        kind: sniff(&bytes).to_string(),
        entropy: entropy(&bytes),
        file,
        entry: name,
        compressed_size,
        size,
        method,
        method_label: method_label(method),
        evaluated: true,
        written: None,
        note: None,
        bytes,
    });
}

/// Entrée vue mais non lue, donc non hachée. La ligne existe : sur un
/// échantillon packé, la plus grosse entrée d'`assets/` est très souvent celle
/// qui porte la charge, et l'omettre serait une perte exactement au mauvais
/// endroit. `size` porte la taille DÉCLARÉE, faute de mesure.
fn not_evaluated_entry(
    name: String,
    method: u16,
    compressed_size: u64,
    declared_size: u64,
    cause: String,
) -> AssetEntry {
    let file = name.rsplit('/').next().unwrap_or(&name).to_string();
    AssetEntry {
        file,
        entry: name,
        compressed_size,
        size: declared_size,
        method,
        method_label: method_label(method),
        sha256: NOT_EVALUATED.to_string(),
        kind: NOT_EVALUATED.to_string(),
        entropy: 0.0,
        evaluated: false,
        written: None,
        // La taille affichée vient du central directory, qui est précisément ce
        // que falsifient les archives trafiquées — les mêmes qui patchent la
        // méthode de compression et les horodatages. Sans cette mention, la
        // colonne se lirait comme les lignes voisines, où elle est mesurée.
        note: Some(format!(
            "non hachée : {cause} ; taille_decompressee est la valeur DÉCLARÉE par \
             l'archive, NON mesurée"
        )),
        bytes: Vec::new(),
    }
}

fn is_asset(name: &str) -> bool {
    !name.ends_with('/') && name.to_ascii_lowercase().starts_with(ASSETS_PREFIX)
}

/// Code de méthode déclaré, valeur brute. `to_u16` est déprécié au profit des
/// constantes, mais c'est précisément la valeur non constante (`0x64b4`) qui
/// nous intéresse ici.
#[allow(deprecated)]
fn method_code(m: zip::CompressionMethod) -> u16 {
    m.to_u16()
}

fn method_label(method: u16) -> String {
    match method {
        0 => "stored(0)".to_string(),
        8 => "deflate(8)".to_string(),
        other => format!("{other:#06x}"),
    }
}

/// Type de contenu déduit des octets de tête. L'extension n'est jamais
/// consultée : dans `assets/`, le second étage d'un dropper s'appelle
/// `config.dat` et le DEX chiffré d'un packer n'a pas d'extension du tout.
fn sniff(bytes: &[u8]) -> &'static str {
    match bytes {
        [] => "unknown",
        [0x64, 0x65, 0x78, 0x0A, ..] => "dex",
        [0x50, 0x4B, 0x03, 0x04, ..] => "apk/zip",
        [0x7F, 0x45, 0x4C, 0x46, ..] => "elf",
        [0x03, 0x00, 0x08, 0x00, ..] => "axml",
        [0x02, 0x00, 0x0C, 0x00, ..] => "arsc",
        [0x89, 0x50, 0x4E, 0x47, ..] => "png",
        [0xFF, 0xD8, 0xFF, ..] => "jpeg",
        _ if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") => "gif",
        [0x1F, 0x8B, ..] => "gzip",
        _ if is_utf8_text(bytes) => "texte-utf8",
        _ => "unknown",
    }
}

/// UTF-8 valide et sans octet de contrôle hors `\t\n\r`. Le second critère
/// écarte les binaires que `from_utf8` accepte par hasard.
fn is_utf8_text(bytes: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return false;
    };
    !s.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

/// Entropie de Shannon sur la distribution des octets, en bits par octet,
/// arrondie à 2 décimales. > 7,9 = chiffré ou déjà compressé — c'est ce qui
/// fait ressortir les charges de packer déposées dans `assets/`.
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let h = -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>();
    (h * 100.0).round() / 100.0
}

/// Empreinte d'ensemble : SHA-256 de la liste TRIÉE des lignes
/// `chemin\tsha256`, chacune terminée par `\n`.
///
/// Elle n'est émise QUE si elle porte sur la totalité des assets de l'archive.
/// Deux absences distinctes, toutes deux explicites :
///
/// * `aucun-asset` — l'APK n'a rien sous `assets/`. Sortir l'empreinte de la
///   chaîne vide agglomérerait tous ces APK en un cluster qui ne veut rien dire.
/// * `incomplet : …` — le jeu d'assets est tronqué (`--assets-include`) ou
///   partiellement non évalué (`--assets-max-size`, entrée illisible). Une
///   empreinte calculée là-dessus aurait l'apparence d'une empreinte valide tout
///   en étant incomparable à celle d'un autre échantillon : c'est le genre de
///   piège qui ne se voit qu'une fois le corpus classé de travers.
///
/// Les filtres par hash (`--assets-hash*`), eux, sont sans effet ici : ils
/// s'appliquent après, et l'appelant passe l'ensemble non filtré.
fn fingerprint(
    entries: &[AssetEntry],
    assets_seen: usize,
    opts: &AssetsOptions,
    skipped: &[SkippedAsset],
) -> (Option<String>, String) {
    if assets_seen == 0 {
        return (None, FP_NO_ASSETS.to_string());
    }

    let mut causes: Vec<String> = Vec::new();
    if !opts.include.is_empty() {
        causes.push("jeu tronqué par --assets-include".to_string());
    }
    let unevaluated = entries.iter().filter(|e| !e.evaluated).count();
    if unevaluated > 0 {
        causes.push(format!(
            "{unevaluated} entrée(s) non évaluée(s) (--assets-max-size)"
        ));
    }
    if !skipped.is_empty() {
        causes.push(format!("{} entrée(s) illisible(s)", skipped.len()));
    }
    if !causes.is_empty() {
        return (None, format!("{FP_INCOMPLETE} : {}", causes.join(", ")));
    }

    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| format!("{}\t{}", e.entry, e.sha256))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    for l in &lines {
        h.update(l.as_bytes());
        h.update(b"\n");
    }
    (Some(format!("{:x}", h.finalize())), FP_COMPLETE.to_string())
}

/// SHA-256 du fichier entier, lu par blocs pour ne pas charger l'APK en mémoire.
fn file_sha256(path: &Path) -> Result<String> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

// ---------------------------------------------------------------------------
// Écriture
// ---------------------------------------------------------------------------

/// Écrit les assets retenus sous `dir`, en reproduisant l'arborescence de
/// l'archive, puis y dépose `assets.json` (le rapport sérialisé).
///
/// Chaque entrée est annotée : [`AssetEntry::written`] porte le chemin
/// réellement écrit, [`AssetEntry::note`] la raison d'un refus ou la trace
/// d'un renommage. Une entrée en échec n'interrompt pas les autres.
pub fn write_all(report: &mut AssetsReport, dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("création {}", dir.display()))?;
    let root = dir
        .canonicalize()
        .with_context(|| format!("résolution {}", dir.display()))?;

    let mut used: HashSet<PathBuf> = HashSet::new();

    for e in &mut report.entries {
        if !e.evaluated {
            // Rien à écrire : l'entrée n'a jamais été lue. `note` porte déjà la
            // raison, `written` reste None.
            continue;
        }
        let (rel, mut note) = match sanitize(&e.entry) {
            Ok(v) => v,
            Err(why) => {
                e.note = Some(format!("non écrit : {why}"));
                tracing::warn!(entry = %e.entry, reason = %why, "asset refusé à l'écriture");
                continue;
            }
        };

        let mut dest = root.join(&rel);
        // Ultime garde-fou : même construit à partir de composants assainis, le
        // chemin doit rester sous la racine.
        if !dest.starts_with(&root) {
            e.note = Some("non écrit : chemin résolu hors du répertoire de sortie".to_string());
            continue;
        }

        if let Some(unique) = deduplicate(&dest, &used) {
            note = Some(match note {
                Some(n) => format!("{n} ; collision de nom suffixée"),
                None => "collision de nom suffixée".to_string(),
            });
            dest = unique;
        }

        if let Some(parent) = dest.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                // Typiquement un `assets/a` fichier et un `assets/a/b` fichier
                // dans la même archive : le parent existe déjà comme fichier.
                e.note = Some(format!("non écrit : création de {} — {err}", parent.display()));
                continue;
            }
        }

        // Le résultat est lié avant le match : l'emprunt de `e.bytes` se termine
        // ici, les bras peuvent annoter `e`.
        let written = std::fs::write(&dest, &e.bytes);
        match written {
            Ok(()) => {
                used.insert(dest.clone());
                e.written = Some(dest.display().to_string());
                e.note = note;
            }
            Err(err) => e.note = Some(format!("non écrit : {err}")),
        }
    }

    let json_path = root.join("assets.json");
    let body = serde_json::to_string_pretty(report).context("sérialisation assets.json")?;
    std::fs::write(&json_path, body)
        .with_context(|| format!("écriture {}", json_path.display()))?;
    Ok(json_path)
}

/// Normalise un chemin d'archive en chemin relatif sûr.
///
/// Rend `Err(raison)` sur `..`, chemin absolu, séparateur Windows ou préfixe de
/// lecteur — aucune écriture hors du répertoire de sortie, jamais. Rend aussi
/// une note quand un composant a dû être tronqué pour le système de fichiers :
/// le nom ORIGINAL reste dans `entry`, seul le nom écrit est raccourci.
fn sanitize(entry: &str) -> std::result::Result<(PathBuf, Option<String>), String> {
    if entry.contains('\\') {
        return Err("séparateur Windows dans le chemin".to_string());
    }
    if entry.starts_with('/') {
        return Err("chemin absolu".to_string());
    }

    let mut parts: Vec<String> = Vec::new();
    let mut truncated = false;
    for c in entry.split('/') {
        match c {
            "" | "." => continue,
            ".." => return Err("traversée de répertoire (..)".to_string()),
            _ => {}
        }
        if c.len() >= 2 && c.as_bytes()[1] == b':' && c.as_bytes()[0].is_ascii_alphabetic() {
            return Err("préfixe de lecteur Windows".to_string());
        }
        if c.len() > MAX_COMPONENT {
            truncated = true;
            parts.push(truncate_bytes(c, MAX_COMPONENT).to_string());
        } else {
            parts.push(c.to_string());
        }
    }

    if parts.is_empty() {
        return Err("chemin vide après normalisation".to_string());
    }
    let note = truncated.then(|| "nom tronqué pour le système de fichiers".to_string());
    Ok((parts.iter().collect(), note))
}

/// Tronque à `max` octets sans couper un caractère UTF-8 en deux.
fn truncate_bytes(s: &str, max: usize) -> &str {
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Rend un chemin libre quand `dest` est déjà pris, en insérant `-1`, `-2`, …
/// avant l'extension. `None` si `dest` était libre.
fn deduplicate(dest: &Path, used: &HashSet<PathBuf>) -> Option<PathBuf> {
    if !used.contains(dest) && !dest.exists() {
        return None;
    }
    let parent = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "asset".to_string());
    let ext = dest.extension().map(|s| s.to_string_lossy().into_owned());

    for n in 1u32.. {
        let name = match &ext {
            Some(e) => format!("{stem}-{n}.{e}"),
            None => format!("{stem}-{n}"),
        };
        let cand = parent.join(truncate_bytes(&name, MAX_COMPONENT));
        if !used.contains(&cand) && !cand.exists() {
            return Some(cand);
        }
    }
    unreachable!("l'itérateur 1.. ne s'épuise pas")
}

// ---------------------------------------------------------------------------
// Index de lot
// ---------------------------------------------------------------------------

/// Une ligne de l'index global d'un lot. Le détail par asset reste dans le
/// `assets.json` de chaque échantillon ; l'index ne porte que les clés de
/// regroupement, pour rester lisible sur un corpus entier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkSample {
    pub sample: String,
    pub path: String,
    pub apk_sha256: String,
    pub reader: Reader,
    pub assets: usize,
    pub skipped: usize,
    /// Entrées vues mais non hachées (plafond de taille).
    pub not_evaluated: usize,
    pub fingerprint: Option<String>,
    /// Pourquoi l'empreinte est présente ou non — voir `AssetsReport`.
    pub fingerprint_status: String,
    /// Sous-répertoire d'extraction, `None` en inventaire seul.
    pub out_dir: Option<String>,
}

/// Un échantillon qui n'a pas pu être inventorié. Nommé plutôt qu'absent : sur
/// un corpus nommé par hachage, une disparition muette est indiscernable d'une
/// absence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedSample {
    pub sample: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BulkIndex {
    pub samples: Vec<BulkSample>,
    pub failed: Vec<FailedSample>,
}

impl BulkIndex {
    /// Écrit `assets_index.json` à la racine de `dir`.
    pub fn write(&self, dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(dir).with_context(|| format!("création {}", dir.display()))?;
        let path = dir.join("assets_index.json");
        let body = serde_json::to_string_pretty(self).context("sérialisation assets_index.json")?;
        std::fs::write(&path, body).with_context(|| format!("écriture {}", path.display()))?;
        Ok(path)
    }
}

// ---------------------------------------------------------------------------
// Rendu TSV
// ---------------------------------------------------------------------------

/// Forme de la sortie TSV. L'en-tête décrit toujours exactement les colonnes
/// émises, quelle que soit la combinaison.
#[derive(Debug, Clone, Copy, Default)]
pub struct TsvShape {
    /// Colonne `sample` en tête (mode bulk, ou pivot par hash).
    pub sample: bool,
    /// Colonne `chemin_ecrit` en queue (`--extract-assets`).
    pub written: bool,
    /// Forme étroite `chemin | sha256` du pivot par hash : seule l'identité
    /// compte quand on cherche qui porte une charge connue.
    pub narrow: bool,
}

/// En-tête TSV correspondant à `shape`.
pub fn tsv_header(shape: TsvShape) -> String {
    let mut cols: Vec<&str> = Vec::with_capacity(9);
    if shape.sample {
        cols.push("sample");
    }
    if shape.narrow {
        cols.extend(["chemin", "sha256"]);
    } else {
        cols.extend([
            "chemin",
            "taille_compressee",
            "taille_decompressee",
            "methode",
            "sha256",
            "type",
            "entropie",
        ]);
    }
    if shape.written {
        cols.push("chemin_ecrit");
    }
    cols.join("\t")
}

/// Une ligne TSV pour un asset. Le SHA-256 y est toujours complet, ou le
/// marqueur [`NOT_EVALUATED`] — jamais un préfixe, jamais une colonne vide.
pub fn tsv_row(e: &AssetEntry, sample: Option<&str>, shape: TsvShape) -> String {
    let mut cols: Vec<String> = Vec::with_capacity(9);
    if let Some(s) = sample {
        cols.push(s.to_string());
    }
    let path = e.entry.replace(['\n', '\r', '\t'], " ");
    if shape.narrow {
        cols.extend([path, e.sha256.clone()]);
    } else {
        cols.extend([
            path,
            e.compressed_size.to_string(),
            e.size.to_string(),
            e.method_label.clone(),
            e.sha256.clone(),
            e.kind.clone(),
            format!("{:.2}", e.entropy),
        ]);
    }
    if shape.written {
        cols.push(match (&e.written, &e.note) {
            (Some(p), _) => p.clone(),
            (None, Some(n)) => format!("-  ({n})"),
            (None, None) => "-".to_string(),
        });
    }
    cols.join("\t")
}

/// Marqueur porté par la colonne `empreinte` quand il n'y en a pas. Non
/// hexadécimal, comme [`NOT_EVALUATED`] : la colonne ne doit jamais pouvoir
/// passer pour une empreinte.
pub const NO_FINGERPRINT: &str = "ABSENTE";

/// En-tête TSV du mode empreinte seule (`--assets-fingerprint`).
///
/// `statut` et `non_evalues` ne sont pas décoratifs : une empreinte absente et
/// une empreinte incomparable se ressemblent dans un tableur, et c'est la
/// combinaison des trois colonnes qui permet de savoir laquelle on regarde.
pub fn fingerprint_tsv_header() -> &'static str {
    "sample\tempreinte\tstatut\tassets\tnon_evalues"
}

/// Une ligne du mode empreinte seule.
pub fn fingerprint_tsv_row(sample: &str, r: &AssetsReport) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}",
        sample,
        r.fingerprint.as_deref().unwrap_or(NO_FINGERPRINT),
        r.fingerprint_status,
        r.count(),
        r.not_evaluated
    )
}

/// Légende autonome des étiquettes produites par ce module.
pub fn legend() -> &'static str {
    "\
chemin               Chemin ORIGINAL de l'entrée dans l'APK (assets/…). Jamais normalisé : c'est
                     lui qui sert au rapprochement, pas le nom écrit sur disque.
taille_compressee    Taille stockée dans l'archive, telle que DÉCLARÉE par le central directory.
taille_decompressee  Taille RÉELLE des octets obtenus, MESURÉE. Sur une archive trafiquée elle
                     diffère de la valeur déclarée — c'est la mesure qui fait foi.
                     EXCEPTION : sur une entrée NON-EVALUE, rien n'a été lu et la colonne porte
                     la valeur DÉCLARÉE par le central directory — c'est-à-dire exactement le
                     champ que falsifient les archives trafiquées, les mêmes qui patchent la
                     méthode de compression et les horodatages. À ne PAS lire comme les lignes
                     voisines : note le rappelle sur chaque entrée concernée.
apk_sha256           (JSON) SHA-256 complet de l'APK conteneur, présent dans assets.json comme
                     dans chaque échantillon d'assets_index.json.
methode              Méthode de compression DÉCLARÉE : stored(0), deflate(8). Toute autre valeur
                     (ex. 0x64b4) est un marqueur de trafiquage ; la lecture n'en tient pas compte.
sha256               SHA-256 COMPLET (64 caractères hexadécimaux) du contenu DÉCOMPRESSÉ —
                     JAMAIS des octets stockés dans l'archive. C'est la seule forme requêtable
                     sur VirusTotal, MalwareBazaar ou Koodous ; un hash d'octets compressés ne
                     se croise avec rien. Et « les octets stockés » n'est pas une notion stable
                     ici : sur une archive trafiquée la méthode déclarée est fausse et le lecteur
                     tolérant essaie deflate puis stored, donc le même asset donnerait deux
                     valeurs selon le chemin de lecture. Corollaire : un asset stored et le même
                     contenu deflate ont le même sha256. Jamais tronqué, jamais un préfixe.
                     Vaut NON-EVALUE — valeur volontairement NON hexadécimale — quand l'entrée
                     n'a pas été lue (voir taille_decompressee et chemin_ecrit).
type                 Type déduit des OCTETS DE TÊTE, jamais de l'extension : dex, apk/zip, elf,
                     axml, arsc, png, jpeg, gif, gzip, texte-utf8, unknown. NON-EVALUE si
                     l'entrée n'a pas été lue.
entropie             Entropie de Shannon en bits par octet (0.00-8.00), 2 décimales. > 7.90 =
                     chiffré ou déjà compressé : c'est ce qui fait ressortir les charges de packer
                     déposées dans assets/. Un texte est vers 4-5, un DEX en clair vers 6.
chemin_ecrit         (--extract-assets) Chemin réellement écrit. \"-\" suivi d'une raison si
                     l'entrée a été refusée (traversée de chemin) ou si l'écriture a échoué.

fingerprint          SHA-256 de la liste TRIÉE des lignes \"chemin<TAB>sha256\", chacune terminée
                     par un saut de ligne. Axe de regroupement : deux APK de la même famille
                     déposent le même jeu d'assets. N'est émise QUE si elle porte sur la TOTALITÉ
                     des assets — sinon elle est ABSENTE, jamais approchée. fingerprint_status
                     dit laquelle des trois situations :
                       complet      empreinte calculée sur tous les assets, comparable.
                       aucun-asset  l'APK n'a rien sous assets/. L'empreinte de la chaîne vide
                                    agglomérerait tous ces APK en un faux cluster.
                       incomplet    jeu tronqué (--assets-include) ou partiellement non évalué
                                    (--assets-max-size, entrée illisible). Une empreinte calculée
                                    là-dessus aurait l'apparence d'une empreinte valide tout en
                                    étant incomparable à celle d'un autre échantillon.
                     Les filtres par hash (--assets-hash*) n'ont AUCUN effet sur l'empreinte :
                     ils s'appliquent après son calcul, sur l'ensemble complet.
not_evaluated        Entrées vues mais non hachées (plafond de taille), comptées AVANT le filtrage
                     par hash. Un filtre par hash ne peut pas les tester : sans ce compteur,
                     l'absence de correspondance se lirait à tort comme l'absence de l'asset.
reader               Lecteur ayant produit l'inventaire : \"nominal\" (crate zip) ou \"tolerant\"
                     (src/parser/apkzip.rs, archive trafiquée). Un APK \"tolerant\" serait vu vide
                     par apktool, JADX ou androguard.
scanned              Nombre total d'entrées de l'archive.
assets_seen          Entrées sous assets/ avant filtres (dénominateur de --assets-include).
skipped              Entrées assets/ vues mais écartées, avec la raison (plafond de taille,
                     entrée illisible). Jamais d'omission silencieuse.

Filtres :
  --assets-include <MOTIF>   Répétable. SOUS-CHAÎNE sur le chemin d'entrée, insensible à la casse.
  --assets-max-size <N>      Plafond en octets sur la taille décompressée. Contrôlé sur la taille
                             déclarée AVANT lecture, puis sur la taille réelle après. En lecteur
                             \"nominal\" il borne aussi la lecture elle-même (une entrée qui
                             sous-déclare sa taille ne se déballe pas en RAM avant d'être écartée) ;
                             en lecteur \"tolerant\" le contrôle reste postérieur à la lecture, que
                             borne alors la limite d'archive en mémoire d'apkzip (512 Mio).

Mode empreinte seule (--assets-fingerprint) :
  Sortie TSV sample | empreinte | statut | assets | non_evalues. Rien n'est écrit.
  --assets-include et --assets-max-size y sont acceptés — c'est même le seul moyen d'observer
  un statut \"incomplet\" sur un lot — mais ils rendent l'empreinte ABSENTE dès qu'ils tronquent
  effectivement le jeu. La colonne empreinte vaut alors ABSENTE, valeur volontairement non
  hexadécimale, et statut dit pourquoi.
  Les filtres par hash y sont REFUSÉS, pas ignorés : l'empreinte ne les honore pas, et les
  accepter en silence laisserait croire qu'elle porte sur le sous-ensemble filtré.

Filtrage par hash connu (mutuellement exclusifs) :
  --assets-hash <SHA256>             Répétable. Ne garde que les assets dont le sha256 est dans
  --assets-hash-file <FICHIER>       l'ensemble. Pivot : \"quels binaires du corpus portent cet
                                     asset ?\". Sortie TSV étroite sample | chemin | sha256 ;
                                     un échantillon sans correspondance ne produit aucune ligne.
  --assets-hash-exclude <SHA256>     Répétable. Sens inverse : retire le déjà-qualifié (polices,
  --assets-hash-exclude-file <FIC.>  libs de SDK, ressources tierces) pour ne laisser que le
                                     reliquat.
Format de fichier : un hash par ligne, \"#\" introduit un commentaire, lignes vides ignorées,
casse indifférente. Toute valeur qui n'est pas 64 caractères hexadécimaux est REFUSÉE en nommant
la ligne fautive : pas de correspondance par préfixe, pas de troncature, dans aucun sens — un
préfixe n'établit pas une identité.
Une entrée NON-EVALUE n'a pas de hash : elle ne satisfait jamais --assets-hash, mais elle SURVIT
à --assets-hash-exclude (n'étant pas qualifiée, elle appartient au reliquat).
Rien n'est écrit sous un filtre par hash, sauf si --extract-assets est aussi passé — auquel cas
seuls les assets retenus le sont.

Le module ne déballe PAS récursivement : un asset qui est lui-même un ZIP, un APK ou un DEX est
typé et écrit tel quel. Le déballage reste une opération explicite (repasser le fichier à drakkar).

Sécurité d'écriture (zip-slip) : \"..\", chemin absolu, séparateur Windows et préfixe de lecteur
sont REFUSÉS ; les composants de plus de 255 octets sont tronqués et les collisions suffixées
(-1, -2, …), l'entrée conservant son chemin d'origine dans le JSON. Rien n'est écrit hors du
répertoire de sortie."
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

    fn on_disk(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sample.apk");
        std::fs::write(&p, bytes).unwrap();
        (dir, p)
    }

    /// Une signature d'en-tête peut apparaître par hasard dans un flux deflate.
    /// On n'accepte un en-tête que si le nom qui le suit est de l'UTF-8
    /// plausible, ce qui écarte les collisions fortuites.
    fn header_name_plausible(z: &[u8], name_at: usize, len_at: usize) -> bool {
        let len = u16::from_le_bytes([z[len_at], z[len_at + 1]]) as usize;
        (1..=512).contains(&len)
            && name_at + len <= z.len()
            && match std::str::from_utf8(&z[name_at..name_at + len]) {
                Ok(n) => n.chars().all(|c| !c.is_control()),
                Err(_) => false,
            }
    }

    /// Trafique l'archive comme le corpus : bit 0 des GP flags (faux
    /// chiffrement) et méthode de compression inexistante, dans le central
    /// directory ET le local file header. Le crate `zip` refuse, Android non.
    fn tamper(mut z: Vec<u8>) -> Vec<u8> {
        // Une signature peut apparaître par hasard dans un flux deflate : on
        // n'accepte un en-tête que si le nom qui le suit est de l'UTF-8
        // plausible, ce qui écarte les collisions fortuites.
        let mut i = 0;
        while i + 46 <= z.len() {
            let sig = u32::from_le_bytes([z[i], z[i + 1], z[i + 2], z[i + 3]]);
            if sig == 0x0403_4b50 && header_name_plausible(&z, i + 30, i + 26) {
                z[i + 6] |= 1; // GP flags : faux chiffrement
                z[i + 8..i + 10].copy_from_slice(&0x64b4u16.to_le_bytes());
            } else if sig == 0x0201_4b50 && header_name_plausible(&z, i + 46, i + 28) {
                z[i + 8] |= 1;
                z[i + 10..i + 12].copy_from_slice(&0x64b4u16.to_le_bytes());
            }
            i += 1;
        }
        z
    }

    #[test]
    fn inventories_only_assets() {
        let (_d, apk) = on_disk(&make_apk(&[
            ("classes.dex", b"dex\n035\0host".to_vec()),
            ("assets/payload.bin", vec![0u8; 32]),
            ("assets/sub/config.json", b"{\"c2\":\"x\"}".to_vec()),
            ("res/raw/plugin", b"PK\x03\x04...".to_vec()),
        ]));

        let r = collect(&apk, &AssetsOptions::default()).unwrap();
        assert_eq!(r.reader, Reader::Nominal);
        assert_eq!(r.scanned, 4);
        assert_eq!(r.assets_seen, 2);
        assert_eq!(r.count(), 2);
        assert!(r.entries.iter().all(|e| e.entry.starts_with("assets/")));
        assert_eq!(r.apk_sha256.len(), 64);
    }

    #[test]
    fn types_by_content_not_extension() {
        let (_d, apk) = on_disk(&make_apk(&[
            ("assets/a.txt", b"dex\n035\0payload".to_vec()),
            ("assets/b.png", b"\x7FELF\x02\x01\x01\0".to_vec()),
            ("assets/c.dex", b"PK\x03\x04\0\0".to_vec()),
            ("assets/d.bin", b"hello monde\n".to_vec()),
            ("assets/e", b"\x03\x00\x08\x00\0\0\0\0".to_vec()),
        ]));
        let r = collect(&apk, &AssetsOptions::default()).unwrap();
        let kind = |n: &str| {
            r.entries
                .iter()
                .find(|e| e.entry == n)
                .unwrap()
                .kind
                .as_str()
        };
        assert_eq!(kind("assets/a.txt"), "dex");
        assert_eq!(kind("assets/b.png"), "elf");
        assert_eq!(kind("assets/c.dex"), "apk/zip");
        assert_eq!(kind("assets/d.bin"), "texte-utf8");
        assert_eq!(kind("assets/e"), "axml");
    }

    #[test]
    fn falls_back_to_tolerant_reader_on_tampered_archive() {
        let clean = make_apk(&[
            ("classes.dex", b"dex\n035\0host".to_vec()),
            ("assets/payload.bin", vec![7u8; 4096]),
        ]);
        let (_d, apk) = on_disk(&tamper(clean));

        let r = collect(&apk, &AssetsOptions::default()).unwrap();
        assert_eq!(r.reader, Reader::Tolerant);
        assert_eq!(r.count(), 1, "sans repli, cet APK ressortirait sans assets");

        let e = &r.entries[0];
        assert_eq!(e.entry, "assets/payload.bin");
        assert_eq!(e.size, 4096);
        assert_eq!(e.method, 0x64b4, "la méthode trafiquée est consignée");
        assert_eq!(e.method_label, "0x64b4");
        assert_eq!(e.sha256, format!("{:x}", Sha256::digest(vec![7u8; 4096])));
    }

    #[test]
    fn include_filters_on_substring() {
        let (_d, apk) = on_disk(&make_apk(&[
            ("assets/libjiagu.so", b"\x7FELF".to_vec()),
            ("assets/www/index.html", b"<html>".to_vec()),
            ("assets/data.bin", vec![1u8; 8]),
        ]));
        let opts = AssetsOptions {
            include: vec!["JIAGU".into(), "www/".into()],
            ..Default::default()
        };
        let r = collect(&apk, &opts).unwrap();
        assert_eq!(r.assets_seen, 3);
        assert_eq!(r.count(), 2);
        assert!(r.skipped.is_empty(), "un non-retenu par filtre n'est pas un skip");

        // B5 : jeu tronqué par --assets-include -> pas d'empreinte.
        assert!(r.fingerprint.is_none());
        assert!(r.fingerprint_status.contains("assets-include"));
    }

    /// A3 : l'entrée au-delà du plafond reste une LIGNE, avec un marqueur non
    /// hexadécimal dans sha256 et la raison dans note.
    #[test]
    fn max_size_yields_a_non_evaluated_row_never_an_omission() {
        let (_d, apk) = on_disk(&make_apk(&[
            ("assets/small.bin", vec![1u8; 16]),
            ("assets/big.bin", vec![2u8; 4096]),
        ]));
        let opts = AssetsOptions {
            max_size: Some(1024),
            ..Default::default()
        };
        let r = collect(&apk, &opts).unwrap();

        assert_eq!(r.count(), 2, "l'entrée écartée doit rester visible");
        assert_eq!(r.not_evaluated, 1);
        assert!(r.skipped.is_empty(), "non évalué != illisible");

        let big = r.entries.iter().find(|e| e.entry == "assets/big.bin").unwrap();
        assert!(!big.evaluated);
        assert_eq!(big.sha256, NOT_EVALUATED);
        assert_eq!(big.kind, NOT_EVALUATED);
        assert!(!big.sha256.bytes().all(|b| b.is_ascii_hexdigit()));
        let note = big.note.as_ref().unwrap();
        assert!(note.contains("assets-max-size"));
        assert!(
            note.contains("DÉCLARÉE") && note.contains("NON mesurée"),
            "la colonne de taille ne doit pas se lire comme une mesure : {note}"
        );
        assert_eq!(big.size, 4096, "taille déclarée, faute de mesure");

        let small = r.entries.iter().find(|e| e.entry == "assets/small.bin").unwrap();
        assert!(small.evaluated);
        assert_eq!(small.sha256.len(), 64);

        // B5 : le jeu est partiel, donc pas d'empreinte.
        assert!(r.fingerprint.is_none());
        assert!(r.fingerprint_status.starts_with("incomplet"));
    }

    #[test]
    fn fingerprint_is_none_without_assets_and_stable_otherwise() {
        let (_d1, bare) = on_disk(&make_apk(&[("classes.dex", b"dex\n".to_vec())]));
        let r = collect(&bare, &AssetsOptions::default()).unwrap();
        assert!(r.fingerprint.is_none());
        assert_eq!(r.fingerprint_status, "aucun-asset");

        // Même jeu d'assets, ordre d'archive inverse -> même empreinte.
        let a = make_apk(&[
            ("assets/a.bin", vec![1u8; 8]),
            ("assets/b.bin", vec![2u8; 8]),
        ]);
        let b = make_apk(&[
            ("assets/b.bin", vec![2u8; 8]),
            ("assets/a.bin", vec![1u8; 8]),
        ]);
        let (_d2, pa) = on_disk(&a);
        let (_d3, pb) = on_disk(&b);
        let ra = collect(&pa, &AssetsOptions::default()).unwrap();
        let fa = ra.fingerprint.clone();
        let fb = collect(&pb, &AssetsOptions::default()).unwrap().fingerprint;
        assert_eq!(ra.fingerprint_status, "complet");
        assert_eq!(fa, fb);
        assert_eq!(fa.unwrap().len(), 64);

        // Un contenu différent change l'empreinte.
        let (_d4, pc) = on_disk(&make_apk(&[
            ("assets/a.bin", vec![1u8; 8]),
            ("assets/b.bin", vec![9u8; 8]),
        ]));
        assert_ne!(
            collect(&pc, &AssetsOptions::default()).unwrap().fingerprint,
            fb
        );
    }

    #[test]
    fn sanitize_refuses_traversal_absolute_and_windows() {
        assert!(sanitize("assets/../../etc/passwd").is_err());
        assert!(sanitize("/etc/passwd").is_err());
        assert!(sanitize("assets\\win\\payload.bin").is_err());
        assert!(sanitize("C:/windows/system32/x").is_err());
        assert!(sanitize("assets/./ok.bin").is_ok());
    }

    #[test]
    fn sanitize_truncates_long_component_and_notes_it() {
        let long = "a".repeat(400);
        let (rel, note) = sanitize(&format!("assets/{long}")).unwrap();
        assert!(note.is_some());
        let last = rel.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(last.len(), MAX_COMPONENT);
    }

    #[test]
    fn write_all_stays_inside_dir_and_emits_json() {
        let (_d, apk) = on_disk(&make_apk(&[
            ("assets/sub/payload.bin", vec![3u8; 64]),
            ("assets/notes.txt", b"hello".to_vec()),
        ]));
        let mut r = collect(&apk, &AssetsOptions::default()).unwrap();

        let out = tempfile::tempdir().unwrap();
        let json = write_all(&mut r, out.path()).unwrap();
        assert!(json.exists());

        let root = out.path().canonicalize().unwrap();
        for e in &r.entries {
            let w = PathBuf::from(e.written.as_ref().unwrap());
            assert!(w.starts_with(&root), "{} sort du répertoire", w.display());
            assert!(w.exists());
        }
        assert!(root.join("assets/sub/payload.bin").exists());

        // Le JSON porte le chemin d'archive ET le chemin écrit, hash complet.
        let body = std::fs::read_to_string(&json).unwrap();
        let back: AssetsReport = serde_json::from_str(&body).unwrap();
        assert_eq!(back.count(), 2);
        assert_eq!(back.apk_sha256, r.apk_sha256);
        assert!(back.entries.iter().all(|e| e.sha256.len() == 64));
        assert!(back.entries.iter().all(|e| e.written.is_some()));
        assert!(back.fingerprint.is_some());
    }

    #[test]
    fn write_all_refuses_traversal_entry_without_aborting_the_rest() {
        // Le ZipWriter refuse un nom en "..", on passe donc par le repli
        // tolérant : l'archive est bricolée à la main côté noms.
        let mut r = AssetsReport {
            apk: "x.apk".into(),
            apk_sha256: "0".repeat(64),
            reader: Reader::Tolerant,
            scanned: 2,
            assets_seen: 2,
            entries: vec![
                AssetEntry {
                    entry: "assets/../../../tmp/evil".into(),
                    file: "evil".into(),
                    compressed_size: 3,
                    size: 3,
                    method: 0,
                    method_label: "stored(0)".into(),
                    sha256: "0".repeat(64),
                    kind: "unknown".into(),
                    entropy: 0.0,
                    evaluated: true,
                    written: None,
                    note: None,
                    bytes: b"bad".to_vec(),
                },
                AssetEntry {
                    entry: "assets/good.bin".into(),
                    file: "good.bin".into(),
                    compressed_size: 4,
                    size: 4,
                    method: 0,
                    method_label: "stored(0)".into(),
                    sha256: "1".repeat(64),
                    kind: "unknown".into(),
                    entropy: 0.0,
                    evaluated: true,
                    written: None,
                    note: None,
                    bytes: b"good".to_vec(),
                },
            ],
            skipped: vec![],
            fingerprint: None,
            fingerprint_status: "aucun-asset".into(),
            not_evaluated: 0,
            hash_filter: None,
            hash_filter_size: 0,
            include: vec![],
            max_size: None,
        };

        let out = tempfile::tempdir().unwrap();
        write_all(&mut r, out.path()).unwrap();

        assert!(r.entries[0].written.is_none());
        assert!(r.entries[0].note.as_ref().unwrap().contains("traversée"));
        assert!(r.entries[1].written.is_some());
        assert!(out.path().join("assets/good.bin").exists());
    }

    /// A1, démonstration directe : le même contenu rangé une fois `stored` et
    /// une fois `deflate` donne le MÊME sha256. Ce ne serait pas le cas si le
    /// hash portait sur les octets stockés.
    #[test]
    fn sha256_is_over_decompressed_content_not_stored_bytes() {
        use zip::CompressionMethod;

        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();

        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            zw.start_file(
                "assets/stored.bin",
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
            )
            .unwrap();
            zw.write_all(&payload).unwrap();
            zw.start_file(
                "assets/deflated.bin",
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            )
            .unwrap();
            zw.write_all(&payload).unwrap();
            zw.finish().unwrap();
        }
        let (_d, apk) = on_disk(&buf);

        let r = collect(&apk, &AssetsOptions::default()).unwrap();
        let get = |n: &str| r.entries.iter().find(|e| e.entry == n).unwrap();
        let stored = get("assets/stored.bin");
        let deflated = get("assets/deflated.bin");

        let expected = format!("{:x}", Sha256::digest(&payload));
        assert_eq!(stored.sha256, expected);
        assert_eq!(deflated.sha256, expected);
        assert_eq!(stored.method, 0);
        assert_eq!(deflated.method, 8);
        assert_ne!(
            stored.compressed_size, deflated.compressed_size,
            "les octets stockés diffèrent bien, seul le contenu déballé coïncide"
        );
    }

    /// A1 sur l'autre chemin de lecture : le repli tolérant essaie deflate puis
    /// stored, et doit rendre exactement le même hash que le chemin nominal.
    #[test]
    fn both_readers_agree_on_the_hash() {
        let payload: Vec<u8> = (0..2048u32).map(|i| (i % 253) as u8).collect();
        let clean = make_apk(&[("assets/payload.bin", payload.clone())]);

        let (_d1, nominal) = on_disk(&clean);
        let (_d2, tampered) = on_disk(&tamper(clean.clone()));

        let a = collect(&nominal, &AssetsOptions::default()).unwrap();
        let b = collect(&tampered, &AssetsOptions::default()).unwrap();
        assert_eq!(a.reader, Reader::Nominal);
        assert_eq!(b.reader, Reader::Tolerant);
        assert_eq!(a.entries[0].sha256, format!("{:x}", Sha256::digest(&payload)));
        assert_eq!(a.entries[0].sha256, b.entries[0].sha256);
        assert_eq!(a.fingerprint, b.fingerprint);
    }

    /// A2 : le sha256 de l'APK conteneur est dans le rapport, donc dans
    /// assets.json, et vaut bien le hash du fichier entier.
    #[test]
    fn container_sha256_is_the_hash_of_the_apk_file() {
        let bytes = make_apk(&[("assets/x.bin", vec![1u8; 8])]);
        let (_d, apk) = on_disk(&bytes);
        let r = collect(&apk, &AssetsOptions::default()).unwrap();
        assert_eq!(r.apk_sha256, format!("{:x}", Sha256::digest(&bytes)));
    }

    // ── B : filtrage par hash connu ──

    fn hash_of(b: &[u8]) -> String {
        format!("{:x}", Sha256::digest(b))
    }

    fn three_asset_apk() -> (tempfile::TempDir, PathBuf, String, String) {
        let a = vec![1u8; 64];
        let b = vec![2u8; 64];
        let apk = make_apk(&[
            ("assets/a.bin", a.clone()),
            ("assets/b.bin", b.clone()),
            ("assets/c.bin", vec![3u8; 64]),
        ]);
        let (d, p) = on_disk(&apk);
        (d, p, hash_of(&a), hash_of(&b))
    }

    #[test]
    fn hash_filter_keep_retains_only_matches() {
        let (_d, apk, ha, _hb) = three_asset_apk();
        let opts = AssetsOptions {
            hash_filter: build_hash_filter(&[ha.to_uppercase()], None, &[], None).unwrap(),
            ..Default::default()
        };
        let r = collect(&apk, &opts).unwrap();
        assert_eq!(r.count(), 1);
        assert_eq!(r.entries[0].entry, "assets/a.bin");
        assert_eq!(r.entries[0].sha256, ha, "la casse d'entrée est indifférente");
        assert_eq!(r.hash_filter, Some(HashMode::Keep));
    }

    #[test]
    fn hash_filter_exclude_leaves_the_remainder() {
        let (_d, apk, ha, hb) = three_asset_apk();
        let opts = AssetsOptions {
            hash_filter: build_hash_filter(&[], None, &[ha, hb], None).unwrap(),
            ..Default::default()
        };
        let r = collect(&apk, &opts).unwrap();
        assert_eq!(r.count(), 1);
        assert_eq!(r.entries[0].entry, "assets/c.bin");
        assert_eq!(r.hash_filter, Some(HashMode::Exclude));
    }

    /// B5 : les filtres par hash ne touchent pas l'empreinte, qui porte sur
    /// l'ensemble complet — sans quoi le corpus se classerait de travers.
    #[test]
    fn hash_filters_leave_the_fingerprint_untouched() {
        let (_d, apk, ha, _hb) = three_asset_apk();
        let unfiltered = collect(&apk, &AssetsOptions::default()).unwrap();

        let kept = collect(
            &apk,
            &AssetsOptions {
                hash_filter: build_hash_filter(&[ha.clone()], None, &[], None).unwrap(),
                ..Default::default()
            },
        )
        .unwrap();
        let excluded = collect(
            &apk,
            &AssetsOptions {
                hash_filter: build_hash_filter(&[], None, &[ha], None).unwrap(),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(unfiltered.fingerprint_status, "complet");
        assert_eq!(kept.fingerprint, unfiltered.fingerprint);
        assert_eq!(excluded.fingerprint, unfiltered.fingerprint);
        assert_eq!(kept.fingerprint_status, "complet");
        assert_ne!(kept.count(), unfiltered.count());
    }

    /// B1 + A3 : une entrée non évaluée n'a pas de hash, donc ne satisfait pas
    /// un Keep — mais elle survit à un Exclude, n'étant pas qualifiée.
    #[test]
    fn non_evaluated_entry_never_matches_keep_but_survives_exclude() {
        let small = vec![1u8; 16];
        let (_d, apk) = on_disk(&make_apk(&[
            ("assets/small.bin", small.clone()),
            ("assets/big.bin", vec![2u8; 4096]),
        ]));
        let other = hash_of(b"quelque chose d'autre");

        let keep = collect(
            &apk,
            &AssetsOptions {
                max_size: Some(1024),
                hash_filter: build_hash_filter(&[other.clone()], None, &[], None).unwrap(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(keep.count(), 0);
        assert_eq!(keep.not_evaluated, 1, "compté malgré le filtrage");

        let exclude = collect(
            &apk,
            &AssetsOptions {
                max_size: Some(1024),
                hash_filter: build_hash_filter(&[], None, &[hash_of(&small)], None).unwrap(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(exclude.count(), 1);
        assert_eq!(exclude.entries[0].entry, "assets/big.bin");
        assert!(!exclude.entries[0].evaluated);
        assert_eq!(exclude.not_evaluated, 1);
    }

    /// B3 : ni préfixe, ni longueur approchante, ni caractère non hexadécimal.
    #[test]
    fn hash_validation_refuses_anything_but_64_hex() {
        let good = "a".repeat(64);
        assert_eq!(normalize_hash(&good.to_uppercase(), "t").unwrap(), good);
        assert_eq!(normalize_hash(&format!("  {good}  "), "t").unwrap(), good);

        for bad in [
            "a".repeat(63),
            "a".repeat(65),
            "z".repeat(64),
            "deadbeef".to_string(),
            String::new(),
        ] {
            let err = normalize_hash(&bad, "--assets-hash #1").unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("--assets-hash #1"), "la source doit être nommée : {msg}");
            assert!(msg.contains("64"), "{msg}");
        }
    }

    #[test]
    fn hash_file_parses_comments_and_names_the_offending_line() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("connus.txt");
        std::fs::write(
            &good,
            format!(
                "# charges connues\n{}\n\n   {}   # avec commentaire en fin de ligne\n",
                "a".repeat(64),
                "B".repeat(64)
            ),
        )
        .unwrap();
        let parsed = read_hash_file(&good).unwrap();
        assert_eq!(parsed, vec!["a".repeat(64), "b".repeat(64)]);

        let bad = dir.path().join("casse.txt");
        std::fs::write(&bad, format!("{}\ndeadbeef\n", "a".repeat(64))).unwrap();
        let msg = format!("{:#}", read_hash_file(&bad).unwrap_err());
        assert!(msg.contains("casse.txt:2"), "ligne fautive non nommée : {msg}");
    }

    /// B2 : les deux sens sont mutuellement exclusifs.
    #[test]
    fn keep_and_exclude_are_mutually_exclusive() {
        let h = "a".repeat(64);
        let err = build_hash_filter(&[h.clone()], None, &[h], None).unwrap_err();
        assert!(format!("{err:#}").contains("mutuellement exclusifs"));

        assert!(build_hash_filter(&[], None, &[], None).unwrap().is_none());
    }

    /// B1 : sous filtre, seuls les assets retenus sont écrits.
    #[test]
    fn extraction_under_a_keep_filter_writes_only_matches() {
        let (_d, apk, ha, _hb) = three_asset_apk();
        let mut r = collect(
            &apk,
            &AssetsOptions {
                hash_filter: build_hash_filter(&[ha], None, &[], None).unwrap(),
                ..Default::default()
            },
        )
        .unwrap();

        let out = tempfile::tempdir().unwrap();
        write_all(&mut r, out.path()).unwrap();
        assert!(out.path().join("assets/a.bin").exists());
        assert!(!out.path().join("assets/b.bin").exists());
        assert!(!out.path().join("assets/c.bin").exists());
    }

    /// Une entrée non lue ne produit pas un fichier vide trompeur.
    #[test]
    fn non_evaluated_entry_is_not_written() {
        let (_d, apk) = on_disk(&make_apk(&[("assets/big.bin", vec![2u8; 4096])]));
        let mut r = collect(
            &apk,
            &AssetsOptions {
                max_size: Some(16),
                ..Default::default()
            },
        )
        .unwrap();

        let out = tempfile::tempdir().unwrap();
        let json = write_all(&mut r, out.path()).unwrap();
        assert!(!out.path().join("assets/big.bin").exists());
        assert!(r.entries[0].written.is_none());

        let back: AssetsReport =
            serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        assert_eq!(back.entries[0].sha256, NOT_EVALUATED);
        assert!(back.entries[0].note.is_some());
    }

    /// La note distingue les deux causes : taille déclarée hors plafond (rien
    /// n'a été lu) et contenu réel au-delà (lecture bornée). Sur une archive
    /// trafiquée, la déclaration ment — les deux ne disent pas la même chose.
    #[test]
    fn not_evaluated_note_distinguishes_declared_from_measured_overflow() {
        // Déclaration honnête au-delà du plafond.
        let (_d1, a) = on_disk(&make_apk(&[("assets/big.bin", vec![2u8; 4096])]));
        let ra = collect(
            &a,
            &AssetsOptions { max_size: Some(64), ..Default::default() },
        )
        .unwrap();
        let na = ra.entries[0].note.as_ref().unwrap();
        assert!(na.contains("taille déclarée"), "{na}");
        assert!(na.contains("DÉCLARÉE"), "{na}");

        // Déclaration falsifiée : uncomp_size mis à 1 dans le central directory
        // ET le local header, contenu réel bien plus gros. Le plafond n'est donc
        // franchi qu'à la lecture.
        let mut z = make_apk(&[("assets/menteur.bin", vec![3u8; 4096])]);
        let mut i = 0;
        while i + 46 <= z.len() {
            let sig = u32::from_le_bytes([z[i], z[i + 1], z[i + 2], z[i + 3]]);
            if sig == 0x0403_4b50 && header_name_plausible(&z, i + 30, i + 26) {
                z[i + 22..i + 26].copy_from_slice(&1u32.to_le_bytes());
            } else if sig == 0x0201_4b50 && header_name_plausible(&z, i + 46, i + 28) {
                z[i + 24..i + 28].copy_from_slice(&1u32.to_le_bytes());
            }
            i += 1;
        }
        let (_d2, b) = on_disk(&z);
        let rb = collect(
            &b,
            &AssetsOptions { max_size: Some(64), ..Default::default() },
        )
        .unwrap();
        let e = &rb.entries[0];
        assert!(!e.evaluated);
        assert_eq!(e.sha256, NOT_EVALUATED);
        let nb = e.note.as_ref().unwrap();
        assert!(nb.contains("contenu réel au-delà"), "{nb}");
        assert!(nb.contains("DÉCLARÉE"), "{nb}");
        assert_eq!(e.size, 1, "la taille affichée est bien la déclaration, mensongère");
    }

    /// B5, l'invariant central : une empreinte HEXADÉCIMALE ne peut jamais
    /// coexister avec un statut autre que « complet ». C'est la seule
    /// combinaison qui rendrait le classement faux en gardant l'air correct.
    ///
    /// Le point subtil que garantit le retour anticipé de `fingerprint` : une
    /// entrée non évaluée porte la chaîne `NON-EVALUE` dans `sha256`, et cette
    /// chaîne entre dans le condensat comme n'importe quelle autre. Sans la
    /// sortie avant la boucle, un jeu tronqué produirait une empreinte de
    /// 64 caractères hexadécimaux parfaitement crédible, avec un marqueur cuit
    /// dedans — indétectable en aval.
    #[test]
    fn a_hex_fingerprint_never_coexists_with_a_non_complete_status() {
        let apk_bytes = make_apk(&[
            ("classes.dex", b"dex\n035\0host".to_vec()),
            ("assets/a.bin", vec![1u8; 2048]),
            ("assets/b.bin", vec![2u8; 16]),
            ("assets/www/index.html", b"<html></html>".to_vec()),
        ]);
        let (_d, apk) = on_disk(&apk_bytes);
        let (_d2, bare) = on_disk(&make_apk(&[("classes.dex", b"dex\n".to_vec())]));
        let ha = format!("{:x}", Sha256::digest(vec![1u8; 2048]));

        let cases: Vec<(&str, &PathBuf, AssetsOptions)> = vec![
            ("jeu complet", &apk, AssetsOptions::default()),
            (
                "tronqué par include",
                &apk,
                AssetsOptions { include: vec!["www".into()], ..Default::default() },
            ),
            (
                "tronqué par max-size",
                &apk,
                AssetsOptions { max_size: Some(1024), ..Default::default() },
            ),
            (
                "include ET max-size",
                &apk,
                AssetsOptions {
                    include: vec!["bin".into()],
                    max_size: Some(1024),
                    ..Default::default()
                },
            ),
            (
                "plafond jamais atteint",
                &apk,
                AssetsOptions { max_size: Some(1 << 20), ..Default::default() },
            ),
            (
                "filtre par hash (sans effet sur l'empreinte)",
                &apk,
                AssetsOptions {
                    hash_filter: build_hash_filter(&[ha.clone()], None, &[], None).unwrap(),
                    ..Default::default()
                },
            ),
            (
                "exclusion par hash (sans effet sur l'empreinte)",
                &apk,
                AssetsOptions {
                    hash_filter: build_hash_filter(&[], None, &[ha], None).unwrap(),
                    ..Default::default()
                },
            ),
            ("aucun asset", &bare, AssetsOptions::default()),
        ];

        for (label, path, opts) in cases {
            let r = collect(path, &opts).unwrap();

            // Le biconditionnel, dans les deux sens.
            assert_eq!(
                r.fingerprint.is_some(),
                r.fingerprint_status == FP_COMPLETE,
                "{label} : empreinte {:?} sous statut « {} »",
                r.fingerprint,
                r.fingerprint_status
            );

            match &r.fingerprint {
                Some(f) => {
                    assert_eq!(f.len(), 64, "{label}");
                    assert!(f.bytes().all(|b| b.is_ascii_hexdigit()), "{label}");
                    assert_eq!(r.fingerprint_status, FP_COMPLETE, "{label}");
                    assert_eq!(r.grouping_key(), Some(f.as_str()), "{label}");
                    assert_eq!(r.not_evaluated, 0, "{label} : un jeu complet n'a pas de non-évaluée");
                }
                None => {
                    assert!(
                        r.fingerprint_status == FP_NO_ASSETS
                            || r.fingerprint_status.starts_with(FP_INCOMPLETE),
                        "{label} : statut inattendu « {} »",
                        r.fingerprint_status
                    );
                    assert_eq!(r.grouping_key(), None, "{label}");
                    // La colonne TSV ne peut pas passer pour une empreinte.
                    let row = fingerprint_tsv_row("ech", &r);
                    let col = row.split('\t').nth(1).unwrap();
                    assert_eq!(col, NO_FINGERPRINT, "{label}");
                    assert!(!col.bytes().all(|b| b.is_ascii_hexdigit()), "{label}");
                }
            }
        }
    }

    /// Corollaire : le marqueur NON-EVALUE ne doit jamais avoir été mêlé au
    /// condensat. Un jeu partiel et le même jeu complet ne peuvent pas rendre
    /// deux empreintes — le partiel n'en rend aucune.
    #[test]
    fn a_truncated_set_never_bakes_the_marker_into_a_digest() {
        let (_d, apk) = on_disk(&make_apk(&[
            ("assets/small.bin", vec![1u8; 16]),
            ("assets/big.bin", vec![2u8; 4096]),
        ]));

        let full = collect(&apk, &AssetsOptions::default()).unwrap();
        let partial = collect(
            &apk,
            &AssetsOptions { max_size: Some(1024), ..Default::default() },
        )
        .unwrap();

        assert!(full.fingerprint.is_some());
        assert_eq!(partial.not_evaluated, 1);
        assert!(
            partial.fingerprint.is_none(),
            "le condensat aurait absorbé le marqueur NON-EVALUE"
        );
        assert!(partial.entries.iter().any(|e| e.sha256 == NOT_EVALUATED));
    }

    /// Le mode empreinte seule ne peut jamais rendre une colonne qui passerait
    /// pour une empreinte alors qu'elle n'en est pas une.
    #[test]
    fn fingerprint_row_never_passes_off_an_absence_as_a_hash() {
        assert_eq!(
            fingerprint_tsv_header().split('\t').count(),
            5,
            "en-tête et ligne doivent s'accorder"
        );

        // Jeu complet : empreinte hexadécimale de 64 caractères.
        let (_d1, full) = on_disk(&make_apk(&[("assets/a.bin", vec![1u8; 32])]));
        let complete = collect(&full, &AssetsOptions::default()).unwrap();
        let row = fingerprint_tsv_row("ech", &complete);
        let cols: Vec<&str> = row.split('\t').collect();
        assert_eq!(cols.len(), 5);
        assert_eq!(cols[0], "ech");
        assert_eq!(cols[1].len(), 64);
        assert!(cols[1].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(cols[2], "complet");

        // Jeu tronqué : la colonne porte un marqueur NON hexadécimal.
        let (_d2, capped) = on_disk(&make_apk(&[("assets/big.bin", vec![2u8; 4096])]));
        let partial = collect(
            &capped,
            &AssetsOptions { max_size: Some(16), ..Default::default() },
        )
        .unwrap();
        let row = fingerprint_tsv_row("ech", &partial);
        let cols: Vec<&str> = row.split('\t').collect();
        assert_eq!(cols[1], NO_FINGERPRINT);
        assert!(!cols[1].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(cols[2].starts_with("incomplet"));
        assert_eq!(cols[4], "1", "les non évaluées sont comptées dans la ligne");

        // Aucun asset : distinct de l'incomplet, et toujours pas d'empreinte.
        let (_d3, bare) = on_disk(&make_apk(&[("classes.dex", b"dex\n".to_vec())]));
        let r = collect(&bare, &AssetsOptions::default()).unwrap();
        let row = fingerprint_tsv_row("ech", &r);
        assert!(row.contains(NO_FINGERPRINT));
        assert!(row.contains("aucun-asset"));
    }

    #[test]
    fn entropy_separates_plain_from_encrypted_payload() {
        assert!(entropy(&vec![b'A'; 4096]) < 0.1);

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
    fn tsv_header_matches_emitted_columns() {
        let e = AssetEntry {
            entry: "assets/p.bin".into(),
            file: "p.bin".into(),
            compressed_size: 10,
            size: 20,
            method: 8,
            method_label: "deflate(8)".into(),
            sha256: "a".repeat(64),
            kind: "unknown".into(),
            entropy: 7.996,
            evaluated: true,
            written: None,
            note: None,
            bytes: vec![],
        };
        for sample in [false, true] {
            for written in [false, true] {
                for narrow in [false, true] {
                    let shape = TsvShape { sample, written, narrow };
                    let who = sample.then_some("s");
                    assert_eq!(
                        tsv_header(shape).split('\t').count(),
                        tsv_row(&e, who, shape).split('\t').count(),
                        "en-tête et ligne désaccordés : {shape:?}"
                    );
                }
            }
        }

        let wide = TsvShape::default();
        assert!(tsv_row(&e, None, wide).contains(&"a".repeat(64)));
        assert!(tsv_row(&e, None, wide).ends_with("8.00"));

        // Forme étroite du pivot : chemin puis sha256 COMPLET, rien d'autre.
        let narrow = TsvShape { narrow: true, ..Default::default() };
        assert_eq!(tsv_header(narrow), "chemin\tsha256");
        assert_eq!(tsv_row(&e, None, narrow), format!("assets/p.bin\t{}", "a".repeat(64)));
    }
}
