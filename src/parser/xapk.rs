//! Conteneur **XAPK** (format APKPure) : un zip qui porte à sa racine le base
//! APK et ses splits (`config.<abi>.apk`, `config.<lang>.apk`…), plus des
//! annexes (`manifest.json`, icône, `.obb` sous `Android/obb/`).
//!
//! Le module résout un XAPK en son base APK **entièrement en mémoire** : les APK
//! internes sont lus en octets ([`Source::Bytes`]), rien n'est écrit sur disque.
//! Les annexes, `manifest.json` compris, ne sont pas lues : tout se décide sur
//! les APK eux-mêmes.
//!
//! # Détection
//!
//! Au contenu, jamais à l'extension : un zip sans `AndroidManifest.xml` à la
//! racine, dont au moins une entrée racine `*.apk` porte elle-même un
//! `AndroidManifest.xml`.
//!
//! # Base et splits
//!
//! Le base est l'APK interne dont le `<manifest>` binaire n'a pas d'attribut
//! `split` ; les splits en ont un, et sa valeur est leur id. Zéro ou plusieurs
//! bases : erreur nommée. Un split est ABI (`native`) s'il porte au moins une
//! entrée `lib/**.so`.
//!
//! Un APK interne illisible (entrée, archive ou manifeste) devient une anomalie
//! du bloc `container` et le reste est analysé ; seul le base ne peut manquer.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::apkzip::TolerantZip;
use super::source::{Reader, Source};

const ANDROID_MANIFEST: &str = "AndroidManifest.xml";

// ─────────────────────────────────────────────────────────────────────────────
// Modèle
// ─────────────────────────────────────────────────────────────────────────────

/// Nature du conteneur. Une seule pour l'instant ; l'énumération garde le champ
/// `kind` du JSON fermé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerKind {
    Xapk,
}

impl ContainerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ContainerKind::Xapk => "xapk",
        }
    }
}

/// Bloc `container` des rapports : absent pour un APK simple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub kind: ContainerKind,
    /// Chemin du fichier conteneur.
    pub path: String,
    /// SHA-256 du fichier conteneur.
    pub sha256: String,
    /// Nom de l'entrée du base APK dans le conteneur.
    pub base_entry: String,
    /// SHA-256 des octets du base APK, c'est-à-dire de l'APK analysé.
    pub base_sha256: String,
    pub splits: Vec<ContainerSplit>,
    /// APK internes écartés, avec leur raison.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<String>,
}

/// Un split tel qu'il figure dans le bloc `container`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSplit {
    pub entry: String,
    pub id: String,
    pub sha256: String,
    pub native: bool,
}

/// Un split, en mémoire.
#[derive(Debug, Clone)]
pub struct Split {
    /// Nom de l'entrée dans le conteneur.
    pub entry: String,
    /// Valeur de l'attribut `split` de son manifeste.
    pub id: String,
    pub sha256: String,
    /// Porte au moins une entrée `lib/**.so` : c'est un split ABI.
    pub native: bool,
    pub source: Source,
}

/// XAPK ouvert : base et splits en mémoire.
#[derive(Debug, Clone)]
pub struct Xapk {
    pub path: PathBuf,
    pub sha256: String,
    pub base_entry: String,
    pub base_sha256: String,
    pub base: Source,
    pub splits: Vec<Split>,
    pub anomalies: Vec<String>,
}

impl Xapk {
    pub fn container_info(&self) -> ContainerInfo {
        ContainerInfo {
            kind: ContainerKind::Xapk,
            path: self.path.display().to_string(),
            sha256: self.sha256.clone(),
            base_entry: self.base_entry.clone(),
            base_sha256: self.base_sha256.clone(),
            splits: self
                .splits
                .iter()
                .map(|s| ContainerSplit {
                    entry: s.entry.clone(),
                    id: s.id.clone(),
                    sha256: s.sha256.clone(),
                    native: s.native,
                })
                .collect(),
            anomalies: self.anomalies.clone(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Résolution
// ─────────────────────────────────────────────────────────────────────────────

/// Entrée d'analyse résolue : le fichier d'origine pour un APK (ou un DEX, un
/// ELF…), le base en mémoire pour un XAPK.
#[derive(Debug, Clone)]
pub struct Input {
    origin: PathBuf,
    source: Source,
    xapk: Option<Xapk>,
}

impl Input {
    /// Entrée prise telle quelle, sans détection.
    pub fn plain(path: &Path) -> Self {
        Input {
            origin: path.to_path_buf(),
            source: Source::from(path),
            xapk: None,
        }
    }

    /// Le fichier désigné par l'utilisateur ou collecté en bulk.
    pub fn origin(&self) -> &Path {
        &self.origin
    }

    /// Ce que reçoivent les analyses.
    pub fn source(&self) -> &Source {
        &self.source
    }

    pub fn xapk(&self) -> Option<&Xapk> {
        self.xapk.as_ref()
    }

    /// Splits du XAPK ; vide hors XAPK.
    pub fn splits(&self) -> &[Split] {
        self.xapk.as_ref().map_or(&[][..], |x| x.splits.as_slice())
    }

    /// Bloc `container` des rapports ; `None` hors XAPK.
    pub fn container(&self) -> Option<ContainerInfo> {
        self.xapk.as_ref().map(Xapk::container_info)
    }

    pub fn manifest_report(&self) -> Result<super::manifest_info::ManifestReport> {
        let mut r = super::manifest_info::extract(&self.source)?;
        r.container = self.container();
        Ok(r)
    }

    /// Rapport de signature du base ; pour un XAPK, plus les signataires des
    /// splits.
    pub fn cert_report(&self) -> Result<super::cert::SigningReport> {
        let mut r = super::cert::extract(&self.source)?;
        if let Some(x) = &self.xapk {
            super::cert::add_split_signers(&mut r, &x.splits);
            r.container = Some(x.container_info());
        }
        Ok(r)
    }

    pub fn dating_report(&self) -> Result<super::dating::DatingReport> {
        let mut r = super::dating::extract(&self.source)?;
        r.container = self.container();
        Ok(r)
    }
}

/// Point de normalisation unique : un XAPK est remplacé par son base en
/// mémoire, tout le reste passe inchangé.
pub fn resolve(path: &Path) -> Result<Input> {
    let mut input = Input::plain(path);
    if let Some(xapk) = open(path)? {
        input.source = xapk.base.clone();
        input.xapk = Some(xapk);
    }
    Ok(input)
}

/// Vrai si `path` est reconnu comme XAPK, y compris un XAPK dont la résolution
/// échouera (base absent ou ambigu) : il doit alors être compté en échec, pas
/// écarté.
pub fn is_xapk(path: &Path) -> bool {
    !matches!(open(path), Ok(None))
}

// ─────────────────────────────────────────────────────────────────────────────
// Détection et ouverture
// ─────────────────────────────────────────────────────────────────────────────

/// Entrée `*.apk` à la racine de l'archive.
fn is_root_apk(name: &str) -> bool {
    !name.contains('/') && name.len() > 4 && name.to_ascii_lowercase().ends_with(".apk")
}

/// Forme de conteneur : pas d'`AndroidManifest.xml` à la racine, au moins un
/// `*.apk` à la racine. Nécessaire, pas suffisant : il faut encore qu'un de ces
/// APK porte un manifeste (cf. `open`).
pub fn looks_like_container<'a>(names: impl IntoIterator<Item = &'a str>) -> bool {
    let (mut apk, mut android_manifest) = (false, false);
    for name in names {
        if name == ANDROID_MANIFEST {
            android_manifest = true;
        } else if is_root_apk(name) {
            apk = true;
        }
    }
    apk && !android_manifest
}

/// Un APK interne lisible jusqu'à son manifeste.
struct Inner {
    entry: String,
    sha256: String,
    source: Source,
    /// Attribut `split` du manifeste ; `None` pour le base.
    split: Option<String>,
    native: bool,
}

/// Ouvre `path` s'il est un XAPK ; `Ok(None)` s'il n'en est pas un. Une erreur
/// n'est rendue qu'une fois le XAPK reconnu.
fn open(path: &Path) -> Result<Option<Xapk>> {
    let container = Source::from(path);
    if container.sniff() != Some(super::dyn_entrypoints::InputKind::Apk) {
        return Ok(None);
    }
    let Ok(names) = super::entry_extract::list_entries(&container) else {
        return Ok(None);
    };
    if !looks_like_container(names.iter().map(String::as_str)) {
        return Ok(None);
    }
    let mut apks: Vec<String> = Vec::new();
    for name in names.into_iter().filter(|n| is_root_apk(n)) {
        if !apks.contains(&name) {
            apks.push(name);
        }
    }

    let mut inner = Vec::new();
    let mut anomalies = Vec::new();
    let mut with_manifest = 0usize;
    for (entry, bytes) in read_entries(&container, &apks) {
        let classified = match bytes {
            Ok(bytes) => classify(path, &entry, bytes),
            Err(e) => Classified::Broken {
                has_manifest: false,
                why: format!("entrée illisible ({e:#})"),
            },
        };
        match classified {
            Classified::Apk(apk) => {
                with_manifest += 1;
                inner.push(apk);
            }
            Classified::NoManifest => {
                anomalies.push(format!("APK interne {entry} : pas d'{ANDROID_MANIFEST}"));
            }
            Classified::Broken { has_manifest, why } => {
                with_manifest += usize::from(has_manifest);
                anomalies.push(format!("APK interne {entry} : {why}"));
            }
        }
    }
    if with_manifest == 0 {
        return Ok(None);
    }

    let (bases, splits): (Vec<Inner>, Vec<Inner>) =
        inner.into_iter().partition(|i| i.split.is_none());
    let base = match <[Inner; 1]>::try_from(bases) {
        Ok([base]) => base,
        Err(bases) if bases.is_empty() => bail!(
            "XAPK {} : aucun APK interne sans attribut split, base introuvable{}",
            path.display(),
            detail(&anomalies)
        ),
        Err(bases) => bail!(
            "XAPK {} : plusieurs APK internes sans attribut split, base ambigu ({})",
            path.display(),
            bases
                .iter()
                .map(|b| b.entry.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };

    for a in &anomalies {
        tracing::warn!(xapk = %path.display(), anomaly = %a, "XAPK");
    }
    tracing::info!(
        xapk = %path.display(),
        base = %base.entry,
        splits = splits.len(),
        native = splits.iter().filter(|s| s.native).count(),
        "XAPK : analyse du base APK en mémoire"
    );
    Ok(Some(Xapk {
        path: path.to_path_buf(),
        sha256: container.sha256()?,
        base_entry: base.entry,
        base_sha256: base.sha256,
        base: base.source,
        splits: splits
            .into_iter()
            .map(|s| Split {
                entry: s.entry,
                id: s.split.unwrap_or_default(),
                sha256: s.sha256,
                native: s.native,
                source: s.source,
            })
            .collect(),
        anomalies,
    }))
}

/// Verdict sur un APK interne.
enum Classified {
    Apk(Inner),
    NoManifest,
    /// Illisible ; `has_manifest` : il porte un `AndroidManifest.xml`, c'est donc
    /// bien un APK.
    Broken {
        has_manifest: bool,
        why: String,
    },
}

fn classify(container: &Path, entry: &str, bytes: Vec<u8>) -> Classified {
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let data: Arc<[u8]> = bytes.into();
    let source = Source::bytes(format!("{}!{entry}", container.display()), data);

    let names = match super::entry_extract::list_entries(&source) {
        Ok(names) => names,
        Err(e) => {
            let why = format!("archive illisible ({e:#})");
            return Classified::Broken {
                has_manifest: false,
                why,
            };
        }
    };
    if !names.iter().any(|n| n == ANDROID_MANIFEST) {
        return Classified::NoManifest;
    }
    let split = match split_attribute(&source) {
        Ok(split) => split,
        Err(e) => {
            let why = format!("manifeste illisible ({e:#})");
            return Classified::Broken {
                has_manifest: true,
                why,
            };
        }
    };
    let native = names
        .iter()
        .any(|n| n.starts_with("lib/") && n.ends_with(".so"));
    Classified::Apk(Inner {
        entry: entry.to_string(),
        sha256,
        source,
        split,
        native,
    })
}

/// Attribut `split` du `<manifest>` binaire, par le même décodeur AXML (repli
/// tolérant compris) que le reste du parser.
fn split_attribute(apk: &Source) -> Result<Option<String>> {
    let raw = super::manifest::read_manifest_bytes(apk)?
        .ok_or_else(|| anyhow!("{ANDROID_MANIFEST} illisible"))?;
    let decoded = super::axml::decode(&raw)?;
    if decoded.root.get_tag() != "manifest" {
        bail!("racine <{}> au lieu de <manifest>", decoded.root.get_tag());
    }
    Ok(decoded.root.attr("split"))
}

/// Octets des APK internes, par le crate `zip`, puis par le lecteur tolérant
/// pour toute entrée qu'il refuse — ouverture, `by_name` ou lecture.
fn read_entries(container: &Source, apks: &[String]) -> Vec<(String, Result<Vec<u8>>)> {
    let mut nominal = container
        .reader()
        .ok()
        .and_then(|r| zip::ZipArchive::new(r).ok());
    let mut tolerant: Option<Result<TolerantZip>> = None;
    let mut out = Vec::with_capacity(apks.len());
    for name in apks {
        let first = match nominal.as_mut() {
            Some(zip) => read_nominal(zip, name),
            None => Err(anyhow!("archive refusée par le crate zip")),
        };
        let bytes = first.or_else(|e| {
            tracing::warn!(
                xapk = %container,
                entry = %name,
                error = %e,
                "entrée refusée par le crate zip, repli sur le lecteur tolérant"
            );
            match tolerant.get_or_insert_with(|| container.tolerant()) {
                Ok(zip) => zip.read_by_name(name),
                Err(e) => Err(anyhow!("lecteur tolérant : {e:#}")),
            }
        });
        out.push((name.clone(), bytes));
    }
    out
}

fn read_nominal(zip: &mut zip::ZipArchive<Reader>, name: &str) -> Result<Vec<u8>> {
    let mut entry = zip.by_name(name)?;
    let mut buf = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut buf)?;
    Ok(buf)
}

fn detail(anomalies: &[String]) -> String {
    if anomalies.is_empty() {
        String::new()
    } else {
        format!(" ; écartés : {}", anomalies.join(" ; "))
    }
}

/// Légende du bloc `container`, reprise telle quelle par les légendes des
/// rapports qui le portent.
pub fn container_legend() -> &'static str {
    "\
  Conteneur (container) — absent pour un APK simple :
  container                bloc présent quand l'entrée est un XAPK : zip sans
                           AndroidManifest.xml à la racine, dont au moins un .apk
                           racine porte un AndroidManifest.xml. Le rapport porte
                           alors sur le base APK, lu en mémoire, et tout SHA-256
                           « de l'échantillon » hors de ce bloc est celui des octets
                           du base. manifest.json et les autres annexes ne sont
                           pas lus.
  container.kind           xapk
  container.path           chemin du fichier conteneur
  container.sha256         SHA-256 complet du fichier conteneur
  container.base_entry     entrée du base dans le conteneur : l'unique .apk racine
                           dont le <manifest> binaire n'a pas d'attribut split
  container.base_sha256    SHA-256 complet des octets du base
  container.splits[]       .apk racine dont le <manifest> a un attribut split :
                           entry, id (valeur de l'attribut split), sha256 complet
                           des octets, native (au moins une entrée lib/**.so)
  container.anomalies[]    .apk racine écartés, avec leur raison : entrée ou
                           archive illisible, manifeste absent ou illisible.
                           Absent si vide.
  Chemins affichés         un rapport qui montre le chemin de l'APK analysé écrit
                           <chemin du .xapk>!<base_entry>.
"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::axml::tests::manifest_doc;
    use std::io::Write;

    fn zip_bytes(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            for (name, data) in entries {
                zw.start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zw.write_all(data).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    fn sha(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn container_shape_needs_a_root_apk_and_no_root_manifest() {
        assert!(looks_like_container(["icon.png", "a.apk", "config.en.apk"]));
        assert!(!looks_like_container(["icon.png", "manifest.json"]));
        assert!(!looks_like_container(["assets/inner.apk"]));
        assert!(!looks_like_container([ANDROID_MANIFEST, "inner.apk"]));
    }

    #[test]
    fn base_and_splits_come_from_the_binary_manifests_without_manifest_json() {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // little-endian
        elf[6] = 1; // EI_VERSION
        elf[18] = 183; // EM_AARCH64

        let base = zip_bytes(&[
            (ANDROID_MANIFEST, manifest_doc(&[("package", "com.x")])),
            ("classes.dex", b"dex\n035\0".to_vec()),
        ]);
        let abi = zip_bytes(&[
            (
                ANDROID_MANIFEST,
                manifest_doc(&[("package", "com.x"), ("split", "config.arm64_v8a")]),
            ),
            ("lib/arm64-v8a/x.so", elf),
        ]);
        let lang = zip_bytes(&[(
            ANDROID_MANIFEST,
            manifest_doc(&[("package", "com.x"), ("split", "config.en")]),
        )]);
        // Noms d'entrée trompeurs : seul le manifeste binaire décide.
        let xapk = zip_bytes(&[
            ("icon.png", b"png".to_vec()),
            ("config.en.apk", lang.clone()),
            ("app.apk", base.clone()),
            ("split_abi.apk", abi.clone()),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.xapk");
        std::fs::write(&path, xapk.as_slice()).unwrap();

        let input = resolve(&path).unwrap();
        let x = input.xapk().expect("reconnu comme XAPK");
        assert_eq!(x.base_entry, "app.apk");
        assert_eq!(x.base_sha256, sha(&base));
        assert_eq!(x.sha256, sha(&xapk));
        assert!(x.anomalies.is_empty(), "{:?}", x.anomalies);
        assert_eq!(
            input.source().to_string(),
            format!("{}!app.apk", path.display())
        );
        assert_eq!(input.source().sha256().unwrap(), sha(&base));

        let mut splits: Vec<(&str, &str, bool, &str)> = input
            .splits()
            .iter()
            .map(|s| (s.entry.as_str(), s.id.as_str(), s.native, s.sha256.as_str()))
            .collect();
        splits.sort();
        let (abi_sha, lang_sha) = (sha(&abi), sha(&lang));
        assert_eq!(
            splits,
            vec![
                ("config.en.apk", "config.en", false, lang_sha.as_str()),
                ("split_abi.apk", "config.arm64_v8a", true, abi_sha.as_str()),
            ]
        );

        let arch =
            crate::parser::native_arch::scan_apk_file(input.source(), input.splits()).unwrap();
        assert_eq!(arch.libs.len(), 1);
        assert_eq!(arch.libs[0].split.as_deref(), Some("config.arm64_v8a"));

        let absent = resolve(&dir.path().join("absent")).unwrap();
        assert!(absent.xapk().is_none());
    }

    #[test]
    fn two_apks_without_split_attribute_are_an_ambiguous_base() {
        let apk = |pkg: &str| zip_bytes(&[(ANDROID_MANIFEST, manifest_doc(&[("package", pkg)]))]);
        let xapk = zip_bytes(&[("a.apk", apk("com.a")), ("b.apk", apk("com.b"))]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("two.xapk");
        std::fs::write(&path, xapk.as_slice()).unwrap();

        let err = resolve(&path).unwrap_err().to_string();
        assert!(err.contains("base ambigu"), "{err}");
        assert!(is_xapk(&path));
    }
}
