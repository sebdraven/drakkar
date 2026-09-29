//! Inventaire de la **signature** d'un APK : schémas employés (v1 JAR, v2, v3,
//! v3.1) et détail des certificats X.509 associés.
//!
//! Trois sources sont couvertes :
//!   - **v1 (JAR signing)** — `META-INF/*.{RSA,DSA,EC}` : structure PKCS#7
//!     `SignedData` dont on extrait les certificats ;
//!   - **v2 / v3 / v3.1** — *APK Signing Block* inséré entre le contenu zip et
//!     le *central directory*, indexé par identifiants 32 bits.
//!
//! Aucune vérification cryptographique n'est effectuée : on ne *valide* pas la
//! signature, on **décrit** les certificats. L'objectif est le pivot CTI —
//! l'empreinte SHA-256 du certificat est stable sur toutes les versions d'une
//! même famille et regroupe les APK d'un même éditeur.
//!
//! Toutes les étiquettes produites sont définies dans [`legend`].

use anyhow::{Context, Result};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use x509_cert::Certificate;

// ─────────────────────────────────────────────────────────────────────────────
// Constantes du format
// ─────────────────────────────────────────────────────────────────────────────

/// Magie de fin de l'APK Signing Block (16 octets, juste avant le central dir).
const SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Signature de l'*End Of Central Directory* zip.
const EOCD_SIG: u32 = 0x0605_4b50;

/// Taille max d'un commentaire zip (65535) + en-tête EOCD (22).
const EOCD_MAX_SEARCH: u64 = 65_557;

/// Identifiants de blocs connus dans l'APK Signing Block.
const ID_V2: u32 = 0x7109_871a;
const ID_V3: u32 = 0xf053_68c0;
const ID_V31: u32 = 0x1b93_ad61;
const ID_VERITY_PADDING: u32 = 0x4272_6577;
const ID_SOURCE_STAMP_V1: u32 = 0x2b09_189e;
const ID_SOURCE_STAMP_V2: u32 = 0x6dff_800d;
const ID_DEPENDENCY_INFO: u32 = 0x504b_4453;

// ─────────────────────────────────────────────────────────────────────────────
// Modèle
// ─────────────────────────────────────────────────────────────────────────────

/// Rapport de signature complet d'un APK.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigningReport {
    pub schemes: Schemes,
    /// Entrées `META-INF/*.{RSA,DSA,EC}` trouvées dans l'archive.
    pub v1_signature_files: Vec<String>,
    /// Identifiants présents dans l'APK Signing Block, en hexadécimal.
    pub signing_block_ids: Vec<String>,
    /// Certificats dédoublonnés par empreinte SHA-256.
    pub certificates: Vec<CertInfo>,
    pub anomalies: Vec<String>,
}

/// Schémas de signature détectés.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Schemes {
    /// v1 — signature JAR historique (`META-INF/`), vérifiée par entrée.
    pub v1: bool,
    /// v2 — signature de l'archive entière (API 24+).
    pub v2: bool,
    /// v3 — v2 + rotation de clé (API 28+).
    pub v3: bool,
    /// v3.1 — rotation ciblée par niveau d'API (API 33+).
    pub v3_1: bool,
}

impl Schemes {
    pub fn labels(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.v1 {
            v.push("v1");
        }
        if self.v2 {
            v.push("v2");
        }
        if self.v3 {
            v.push("v3");
        }
        if self.v3_1 {
            v.push("v3.1");
        }
        v
    }
}

/// D'où provient un certificat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum CertSource {
    /// PKCS#7 d'un fichier `META-INF/<nom>.{RSA,DSA,EC}`.
    V1(String),
    /// Bloc v2 de l'APK Signing Block.
    V2,
    /// Bloc v3 de l'APK Signing Block.
    V3,
    /// Bloc v3.1 de l'APK Signing Block.
    V31,
}

impl CertSource {
    pub fn label(&self) -> String {
        match self {
            CertSource::V1(f) => format!("v1:{f}"),
            CertSource::V2 => "v2".into(),
            CertSource::V3 => "v3".into(),
            CertSource::V31 => "v3.1".into(),
        }
    }
}

/// Détail d'un certificat X.509 de signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Toutes les sources où ce certificat (même SHA-256) apparaît.
    pub sources: Vec<CertSource>,
    /// Version X.509 (1, 2 ou 3).
    pub version: u8,
    /// Numéro de série, hexadécimal.
    pub serial: String,
    /// Distinguished Name complet du sujet (format RFC 4514).
    pub subject: String,
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub subject_ou: Option<String>,
    pub subject_l: Option<String>,
    pub subject_st: Option<String>,
    pub subject_c: Option<String>,
    /// DN complet de l'émetteur.
    pub issuer: String,
    pub issuer_cn: Option<String>,
    /// `true` si sujet == émetteur (cas normal sur Android : auto-signé).
    pub self_signed: bool,
    /// Début de validité, UTC ISO-8601.
    pub not_before: String,
    /// Fin de validité, UTC ISO-8601.
    pub not_after: String,
    /// Durée de validité en années (365,25 j).
    pub validity_years: f64,
    /// Algorithme de signature du certificat.
    pub signature_algorithm: String,
    pub public_key: PublicKeyInfo,
    pub fingerprints: Fingerprints,
    /// SHA-256 du `SubjectPublicKeyInfo` DER — pivot indépendant du certificat
    /// (deux certificats différents peuvent porter la même clé).
    pub public_key_sha256: String,
}

/// Clé publique portée par le certificat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// RSA / DSA / EC / OID brut si inconnu.
    pub algorithm: String,
    /// Taille en bits (module RSA, ou taille de courbe pour EC).
    pub size_bits: Option<u32>,
    /// Courbe nommée pour EC (P-256, P-384…).
    pub curve: Option<String>,
}

/// Empreintes du certificat encodé DER.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprints {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Point d'entrée du module
// ─────────────────────────────────────────────────────────────────────────────

/// Analyse la signature d'un APK et produit le rapport complet.
pub fn extract(apk_path: &Path) -> Result<SigningReport> {
    let mut report = SigningReport::default();
    // (der, source) accumulés puis dédoublonnés par SHA-256.
    let mut raw_certs: Vec<(Vec<u8>, CertSource)> = Vec::new();

    // ── v1 : META-INF/*.{RSA,DSA,EC} ──
    collect_v1(apk_path, &mut report, &mut raw_certs)?;

    // ── v2 / v3 / v3.1 : APK Signing Block ──
    if let Err(e) = collect_signing_block(apk_path, &mut report, &mut raw_certs) {
        tracing::warn!(error = %e, "APK Signing Block illisible");
        report
            .anomalies
            .push(format!("APK Signing Block illisible : {e}"));
    }

    // ── Décodage X.509 + dédoublonnage ──
    for (der, source) in raw_certs {
        match build_cert_info(&der, source.clone()) {
            Ok(info) => {
                if let Some(existing) = report
                    .certificates
                    .iter_mut()
                    .find(|c| c.fingerprints.sha256 == info.fingerprints.sha256)
                {
                    if !existing.sources.contains(&source) {
                        existing.sources.push(source);
                    }
                } else {
                    report.certificates.push(info);
                }
            }
            Err(e) => {
                tracing::warn!(source = %source.label(), error = %e, "certificat illisible");
                report
                    .anomalies
                    .push(format!("certificat illisible ({}) : {e}", source.label()));
            }
        }
    }

    report.anomalies.extend(derive_anomalies(&report));

    tracing::info!(
        schemes = ?report.schemes.labels(),
        certs = report.certificates.len(),
        "signature extraite"
    );
    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// v1 — PKCS#7 dans META-INF/
// ─────────────────────────────────────────────────────────────────────────────

fn collect_v1(
    apk_path: &Path,
    report: &mut SigningReport,
    out: &mut Vec<(Vec<u8>, CertSource)>,
) -> Result<()> {
    let file = std::fs::File::open(apk_path)
        .with_context(|| format!("ouverture {}", apk_path.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("lecture de l'APK comme zip")?;

    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|e| e.name().to_string()))
        .filter(|n| is_v1_signature_file(n))
        .collect();

    for name in names {
        let mut buf = Vec::new();
        {
            let mut entry = match zip.by_name(&name) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(entry = %name, error = %e, "entrée illisible");
                    continue;
                }
            };
            if entry.read_to_end(&mut buf).is_err() {
                continue;
            }
        }
        report.schemes.v1 = true;
        report.v1_signature_files.push(name.clone());

        let certs = pkcs7_certificates(&buf);
        if certs.is_empty() {
            report
                .anomalies
                .push(format!("{name} : aucun certificat extrait du PKCS#7"));
        }
        for der in certs {
            out.push((der, CertSource::V1(name.clone())));
        }
    }
    Ok(())
}

/// `META-INF/FOO.RSA` / `.DSA` / `.EC` (comparaison insensible à la casse).
fn is_v1_signature_file(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("META-INF/")
        && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
}

/// Extrait les certificats DER d'un blob PKCS#7 `SignedData`.
///
/// Chemin nominal : décodage `ContentInfo` -> `SignedData` -> `certificates`.
/// Chemin de repli : balayage DER brut du blob (certains APK portent des
/// PKCS#7 malformés que les outils Android acceptent quand même).
fn pkcs7_certificates(blob: &[u8]) -> Vec<Vec<u8>> {
    if let Some(certs) = pkcs7_certificates_strict(blob) {
        if !certs.is_empty() {
            return certs;
        }
    }
    scan_der_certificates(blob)
}

fn pkcs7_certificates_strict(blob: &[u8]) -> Option<Vec<Vec<u8>>> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    let ci = ContentInfo::from_der(blob).ok()?;
    let sd: SignedData = ci.content.decode_as().ok()?;
    let set = sd.certificates?;

    let mut out = Vec::new();
    for choice in set.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = choice {
            if let Ok(der) = cert.to_der() {
                out.push(der);
            }
        }
    }
    Some(out)
}

/// Balaye un blob à la recherche de SEQUENCE DER décodables en certificat X.509.
///
/// On ne teste que les positions commençant par `30 82` (SEQUENCE, longueur sur
/// 2 octets) — cas de tous les certificats réels (entre 256 o et 64 Ko).
fn scan_der_certificates(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut i = 0usize;
    while i + 4 <= blob.len() {
        if blob[i] == 0x30 && blob[i + 1] == 0x82 {
            let len = u16::from_be_bytes([blob[i + 2], blob[i + 3]]) as usize;
            let end = i + 4 + len;
            if end <= blob.len() {
                let slice = &blob[i..end];
                if Certificate::from_der(slice).is_ok() && !out.iter().any(|c| c == slice) {
                    out.push(slice.to_vec());
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// v2 / v3 — APK Signing Block
// ─────────────────────────────────────────────────────────────────────────────

fn collect_signing_block(
    apk_path: &Path,
    report: &mut SigningReport,
    out: &mut Vec<(Vec<u8>, CertSource)>,
) -> Result<()> {
    let mut f = std::fs::File::open(apk_path)
        .with_context(|| format!("ouverture {}", apk_path.display()))?;
    let file_len = f.metadata()?.len();

    let Some(cd_offset) = central_directory_offset(&mut f, file_len)? else {
        anyhow::bail!("EOCD introuvable (archive tronquée ou ZIP64 non géré)");
    };
    if cd_offset < 32 {
        return Ok(()); // pas de place pour un signing block
    }

    // Pied du bloc : [u64 size][16 o magic] immédiatement avant le central dir.
    let mut footer = [0u8; 24];
    f.seek(SeekFrom::Start(cd_offset - 24))?;
    f.read_exact(&mut footer)?;
    if &footer[8..24] != SIG_BLOCK_MAGIC {
        return Ok(()); // APK signé v1 uniquement
    }

    let block_size = u64::from_le_bytes(footer[0..8].try_into().unwrap());
    // `block_size` exclut le champ de taille de tête (8 octets).
    let block_start = cd_offset
        .checked_sub(block_size + 8)
        .context("taille de signing block incohérente")?;

    let total = (cd_offset - block_start) as usize;
    if total > 64 * 1024 * 1024 {
        anyhow::bail!("signing block anormalement volumineux ({total} o)");
    }
    let mut block = vec![0u8; total];
    f.seek(SeekFrom::Start(block_start))?;
    f.read_exact(&mut block)?;

    // Contenu utile : entre l'en-tête de taille (8 o) et le pied (24 o).
    let payload = &block[8..total - 24];

    let mut cur = 0usize;
    while cur + 12 <= payload.len() {
        let pair_len = u64::from_le_bytes(payload[cur..cur + 8].try_into().unwrap()) as usize;
        if pair_len < 4 || cur + 8 + pair_len > payload.len() {
            report
                .anomalies
                .push("paire ID-value tronquée dans le signing block".into());
            break;
        }
        let id = u32::from_le_bytes(payload[cur + 8..cur + 12].try_into().unwrap());
        let value = &payload[cur + 12..cur + 8 + pair_len];
        cur += 8 + pair_len;

        report
            .signing_block_ids
            .push(format!("0x{id:08x} ({})", block_id_label(id)));

        let source = match id {
            ID_V2 => {
                report.schemes.v2 = true;
                Some(CertSource::V2)
            }
            ID_V3 => {
                report.schemes.v3 = true;
                Some(CertSource::V3)
            }
            ID_V31 => {
                report.schemes.v3_1 = true;
                Some(CertSource::V31)
            }
            _ => None,
        };

        if let Some(src) = source {
            for der in signer_block_certificates(value) {
                out.push((der, src.clone()));
            }
        }
    }

    Ok(())
}

/// Localise l'offset du *central directory* via l'EOCD.
fn central_directory_offset(f: &mut std::fs::File, file_len: u64) -> Result<Option<u64>> {
    let search = EOCD_MAX_SEARCH.min(file_len);
    let start = file_len - search;
    let mut tail = vec![0u8; search as usize];
    f.seek(SeekFrom::Start(start))?;
    f.read_exact(&mut tail)?;

    // Balayage arrière : on veut le dernier EOCD valide.
    let mut i = tail.len().saturating_sub(22);
    loop {
        if u32::from_le_bytes(tail[i..i + 4].try_into().unwrap()) == EOCD_SIG {
            let cd_offset = u32::from_le_bytes(tail[i + 16..i + 20].try_into().unwrap());
            if cd_offset == u32::MAX {
                anyhow::bail!("archive ZIP64 — offset de central directory non géré");
            }
            return Ok(Some(cd_offset as u64));
        }
        if i == 0 {
            return Ok(None);
        }
        i -= 1;
    }
}

/// Extrait les certificats DER d'un bloc de signataires v2 / v3 / v3.1.
///
/// Disposition (little-endian, longueurs sur u32) — identique pour les trois
/// schémas jusqu'au champ `certificates` :
/// ```text
/// signers            := len(u32) || signer*
///   signer           := len(u32) || signed_data || …
///     signed_data    := len(u32) || digests || certificates || …
///       digests      := len(u32) || …            (ignoré ici)
///       certificates := len(u32) || cert*
///         cert       := len(u32) || X.509 DER
/// ```
fn signer_block_certificates(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(signers) = len_prefixed(value, 0) else {
        return out;
    };

    let mut cur = 0usize;
    while let Some(signer) = len_prefixed(signers, cur) {
        cur += 4 + signer.len();

        if let Some(signed_data) = len_prefixed(signer, 0) {
            // digests -> ignoré, on saute le champ.
            if let Some(digests) = len_prefixed(signed_data, 0) {
                let after_digests = 4 + digests.len();
                if let Some(certs) = len_prefixed(signed_data, after_digests) {
                    let mut c = 0usize;
                    while let Some(der) = len_prefixed(certs, c) {
                        c += 4 + der.len();
                        if !der.is_empty() {
                            out.push(der.to_vec());
                        }
                    }
                }
            }
        }

        if cur >= signers.len() {
            break;
        }
    }
    out
}

/// Libellé des identifiants connus de l'APK Signing Block.
fn block_id_label(id: u32) -> &'static str {
    match id {
        ID_V2 => "signature v2",
        ID_V3 => "signature v3",
        ID_V31 => "signature v3.1",
        ID_VERITY_PADDING => "padding fs-verity",
        ID_SOURCE_STAMP_V1 => "source stamp v1",
        ID_SOURCE_STAMP_V2 => "source stamp v2",
        ID_DEPENDENCY_INFO => "métadonnées de dépendances (Play)",
        _ => "inconnu",
    }
}

/// Lit un champ préfixé par sa longueur (u32 LE) à `offset` et renvoie son contenu.
fn len_prefixed(buf: &[u8], offset: usize) -> Option<&[u8]> {
    if offset + 4 > buf.len() {
        return None;
    }
    let len = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?) as usize;
    let start = offset + 4;
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(&buf[start..end])
}

// ─────────────────────────────────────────────────────────────────────────────
// Décodage X.509
// ─────────────────────────────────────────────────────────────────────────────

fn build_cert_info(der: &[u8], source: CertSource) -> Result<CertInfo> {
    let cert = Certificate::from_der(der).context("décodage X.509")?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();

    let nb = tbs.validity.not_before.to_unix_duration().as_secs() as i64;
    let na = tbs.validity.not_after.to_unix_duration().as_secs() as i64;
    let validity_years = (na - nb) as f64 / (365.25 * 86_400.0);

    let spki = &tbs.subject_public_key_info;
    let spki_der = spki.to_der().unwrap_or_default();
    let pk_oid = spki.algorithm.oid.to_string();
    let pk_bits = spki.subject_public_key.raw_bytes();

    let (algorithm, size_bits, curve) = match pk_oid.as_str() {
        "1.2.840.113549.1.1.1" => ("RSA".to_string(), rsa_modulus_bits(pk_bits), None),
        "1.2.840.10040.4.1" => ("DSA".to_string(), None, None),
        "1.2.840.10045.2.1" => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                .map(|oid| curve_name(&oid.to_string()));
            let bits = curve.as_deref().and_then(curve_bits);
            ("EC".to_string(), bits, curve)
        }
        other => (format!("OID {other}"), None, None),
    };

    // `Version` est un enum `#[repr(u8)]` valant 0/1/2 pour X.509 v1/v2/v3.
    let version = tbs.version as u8 + 1;

    Ok(CertInfo {
        sources: vec![source],
        version,
        serial: hex_lower(tbs.serial_number.as_bytes()),
        subject_cn: dn_component(&subject, "CN"),
        subject_o: dn_component(&subject, "O"),
        subject_ou: dn_component(&subject, "OU"),
        subject_l: dn_component(&subject, "L"),
        subject_st: dn_component(&subject, "ST"),
        subject_c: dn_component(&subject, "C"),
        issuer_cn: dn_component(&issuer, "CN"),
        self_signed: subject == issuer,
        subject,
        issuer,
        not_before: fmt_unix_utc(nb),
        not_after: fmt_unix_utc(na),
        validity_years,
        signature_algorithm: sig_alg_name(&cert.signature_algorithm.oid.to_string()),
        public_key: PublicKeyInfo {
            algorithm,
            size_bits,
            curve,
        },
        fingerprints: Fingerprints {
            md5: hex_lower(&md5_digest(der)),
            sha1: hex_lower(&sha1_digest(der)),
            sha256: hex_lower(&sha256_digest(der)),
        },
        public_key_sha256: hex_lower(&sha256_digest(&spki_der)),
    })
}

/// Extrait un composant d'un DN RFC 4514 (`CN=x,O=y`), en gérant l'échappement.
fn dn_component(dn: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let bytes: Vec<char> = dn.chars().collect();
    let mut i = 0usize;
    let mut field_start = 0usize;

    while i <= bytes.len() {
        let at_sep = i == bytes.len() || (bytes[i] == ',' && (i == 0 || bytes[i - 1] != '\\'));
        if at_sep {
            let field: String = bytes[field_start..i].iter().collect();
            let field = field.trim();
            if let Some(rest) = field.strip_prefix(prefix.as_str()) {
                return Some(rest.replace("\\,", ",").replace("\\+", "+"));
            }
            field_start = i + 1;
        }
        i += 1;
    }
    None
}

/// Nombre de bits du module RSA, lu dans `RSAPublicKey ::= SEQUENCE { n, e }`.
fn rsa_modulus_bits(spki_key: &[u8]) -> Option<u32> {
    let (seq, _) = der_read_tlv(spki_key, 0)?;
    let (modulus, _) = der_read_tlv(seq, 0)?;
    let n: &[u8] = {
        let mut s = modulus;
        while !s.is_empty() && s[0] == 0 {
            s = &s[1..];
        }
        s
    };
    if n.is_empty() {
        return None;
    }
    let leading = n[0].leading_zeros();
    Some((n.len() as u32) * 8 - leading)
}

/// Lit un TLV DER à `offset` : renvoie (contenu, offset de fin).
/// Ne gère que les tags sur un octet — suffisant pour SEQUENCE / INTEGER.
fn der_read_tlv(buf: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset + 2 > buf.len() {
        return None;
    }
    let mut i = offset + 1; // saute le tag
    let first = buf[i];
    i += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || i + n > buf.len() {
            return None;
        }
        let mut v = 0usize;
        for b in &buf[i..i + n] {
            v = (v << 8) | (*b as usize);
        }
        i += n;
        v
    };
    let end = i.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some((&buf[i..end], end))
}

/// OID d'algorithme de signature -> libellé lisible.
fn sig_alg_name(oid: &str) -> String {
    let name = match oid {
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10040.4.3" => "dsaWithSHA1",
        "2.16.840.1.101.3.4.3.2" => "dsaWithSHA256",
        "1.2.840.10045.4.1" => "ecdsaWithSHA1",
        "1.2.840.10045.4.3.2" => "ecdsaWithSHA256",
        "1.2.840.10045.4.3.3" => "ecdsaWithSHA384",
        "1.2.840.10045.4.3.4" => "ecdsaWithSHA512",
        other => return format!("OID {other}"),
    };
    name.to_string()
}

fn curve_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.3.1.7" => "P-256".into(),
        "1.3.132.0.34" => "P-384".into(),
        "1.3.132.0.35" => "P-521".into(),
        "1.3.132.0.10" => "secp256k1".into(),
        other => format!("OID {other}"),
    }
}

fn curve_bits(curve: &str) -> Option<u32> {
    match curve {
        "P-256" | "secp256k1" => Some(256),
        "P-384" => Some(384),
        "P-521" => Some(521),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Anomalies
// ─────────────────────────────────────────────────────────────────────────────

fn derive_anomalies(r: &SigningReport) -> Vec<String> {
    let mut a = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if r.certificates.is_empty() {
        a.push("aucun certificat extrait — APK non signé ou signature illisible".into());
    }
    if !r.schemes.v1 && !r.schemes.v2 && !r.schemes.v3 && !r.schemes.v3_1 {
        a.push("aucun schéma de signature détecté".into());
    }
    if r.schemes.v1 && !r.schemes.v2 && !r.schemes.v3 {
        a.push("v1 seul — signature JAR historique, APK antérieur ou outillage ancien".into());
    }
    if r.certificates.len() > 1 {
        a.push(format!(
            "{} certificats distincts — rotation de clé ou signature multiple",
            r.certificates.len()
        ));
    }

    for c in &r.certificates {
        let who = c.subject_cn.clone().unwrap_or_else(|| c.subject.clone());

        if c.subject_cn.as_deref() == Some("Android Debug") {
            a.push(format!(
                "{who} : certificat de DÉBOGAGE Android (clé debug du SDK, non publiable)"
            ));
        }
        if c.validity_years > 50.0 {
            a.push(format!(
                "{who} : validité de {:.0} ans — clé auto-générée jetable typique",
                c.validity_years
            ));
        }
        if c.not_after.as_str() < fmt_unix_utc(now).as_str() {
            a.push(format!("{who} : certificat expiré ({})", c.not_after));
        }
        if c.signature_algorithm.contains("md5") || c.signature_algorithm.contains("md2") {
            a.push(format!(
                "{who} : signature {} — algorithme cassé",
                c.signature_algorithm
            ));
        }
        if c.signature_algorithm.contains("sha1") {
            a.push(format!(
                "{who} : signature {} — SHA-1 déprécié",
                c.signature_algorithm
            ));
        }
        if c.public_key.algorithm == "RSA" {
            if let Some(bits) = c.public_key.size_bits {
                if bits < 2048 {
                    a.push(format!(
                        "{who} : clé RSA de {bits} bits — sous le seuil de 2048"
                    ));
                }
            }
        }
        if !c.self_signed {
            a.push(format!(
                "{who} : certificat NON auto-signé — inhabituel pour un APK Android"
            ));
        }
    }

    a
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilitaires
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

fn sha1_digest(data: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    Sha1::digest(data).to_vec()
}

fn md5_digest(data: &[u8]) -> Vec<u8> {
    use md5::{Digest, Md5};
    Md5::digest(data).to_vec()
}

/// Hexadécimal minuscule, sans séparateur (grep-friendly).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Hexadécimal groupé par octet avec `:` — lisible en console.
pub fn hex_colons(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/// Timestamp Unix -> `YYYY-MM-DDTHH:MM:SSZ` (UTC, sans dépendance externe).
///
/// Conversion jours -> date civile : algorithme de Howard Hinnant
/// (`civil_from_days`), valide sur toute la plage proleptique grégorienne.
pub fn fmt_unix_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

// ─────────────────────────────────────────────────────────────────────────────
// Légende
// ─────────────────────────────────────────────────────────────────────────────

/// Légende autonome : définit chaque champ et chaque étiquette du rapport.
pub fn legend() -> String {
    let mut s = String::new();
    s.push_str("Légende — rapport de signature\n");
    s.push_str("  Schémas :\n");
    s.push_str("    v1    signature JAR (META-INF/*.SF + *.RSA|DSA|EC), par entrée zip\n");
    s.push_str("    v2    signature de l'archive entière, APK Signing Block (API 24+)\n");
    s.push_str("    v3    v2 + rotation de clé avec preuve de continuité (API 28+)\n");
    s.push_str("    v3.1  rotation ciblée par niveau d'API (API 33+)\n");
    s.push_str("  Champs certificat :\n");
    s.push_str("    subject/issuer     DN au format RFC 4514 ; sur Android le certificat\n");
    s.push_str("                       est normalement auto-signé (subject == issuer)\n");
    s.push_str("    fingerprints       empreintes du certificat encodé DER — SHA-256 est\n");
    s.push_str("                       le pivot de regroupement inter-échantillons\n");
    s.push_str("    public_key_sha256  empreinte du SubjectPublicKeyInfo — identifie la\n");
    s.push_str("                       CLÉ, stable même si le certificat est ré-émis\n");
    s.push_str("    validity_years     (notAfter - notBefore) / 365,25 j\n");
    s.push_str("  Note : aucune vérification cryptographique n'est faite ; la présence\n");
    s.push_str("  d'un certificat ne signifie pas que la signature est valide.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_epoch() {
        assert_eq!(fmt_unix_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn date_connue() {
        // 2001-09-09T01:46:40Z
        assert_eq!(fmt_unix_utc(1_000_000_000), "2001-09-09T01:46:40Z");
    }

    #[test]
    fn date_bissextile() {
        // 2020-02-29T00:00:00Z
        assert_eq!(fmt_unix_utc(1_582_934_400), "2020-02-29T00:00:00Z");
    }

    #[test]
    fn dn_extraction() {
        let dn = "CN=Android Debug,O=Android,C=US";
        assert_eq!(dn_component(dn, "CN").as_deref(), Some("Android Debug"));
        assert_eq!(dn_component(dn, "O").as_deref(), Some("Android"));
        assert_eq!(dn_component(dn, "C").as_deref(), Some("US"));
        assert_eq!(dn_component(dn, "OU"), None);
    }

    #[test]
    fn dn_virgule_echappee() {
        let dn = "CN=Foo\\, Inc.,O=Bar";
        assert_eq!(dn_component(dn, "CN").as_deref(), Some("Foo, Inc."));
        assert_eq!(dn_component(dn, "O").as_deref(), Some("Bar"));
    }

    #[test]
    fn champ_prefixe_longueur() {
        // [len=3]["abc"] suivi de bruit
        let buf = [3u8, 0, 0, 0, b'a', b'b', b'c', 0xff];
        assert_eq!(len_prefixed(&buf, 0), Some(&b"abc"[..]));
        assert_eq!(len_prefixed(&buf, 6), None); // longueur au-delà du tampon
    }

    #[test]
    fn bits_rsa_2048() {
        // SEQUENCE { INTEGER (2048 bits, préfixé 0x00), INTEGER 65537 }
        let mut modulus = vec![0x00u8];
        modulus.push(0xc0); // bit de poids fort à 1 -> 8 bits pleins
        modulus.extend(std::iter::repeat_n(0xab, 255));
        let mut inner = vec![0x02, 0x82, 0x01, 0x01];
        inner.extend_from_slice(&modulus);
        inner.extend_from_slice(&[0x02, 0x03, 0x01, 0x00, 0x01]);
        let mut seq = vec![0x30, 0x82];
        seq.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        seq.extend_from_slice(&inner);
        assert_eq!(rsa_modulus_bits(&seq), Some(2048));
    }

    #[test]
    fn hex_avec_deux_points() {
        assert_eq!(hex_colons("deadbeef"), "de:ad:be:ef");
    }
}
