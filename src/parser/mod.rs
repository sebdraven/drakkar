//! Parsing APK -> ApkFeatures + CallGraph.
//!
//! Un APK est une archive zip : on extrait les `classes*.dex` (parsés via
//! `dex_facade` + `dex-bytecode`) et les `lib/*/*.so` (parsés par LIEF,
//! derrière la feature `lief-backend`). Le manifest binaire est traité par
//! `manifest`.
//!
//! Certaines familles trafiquent la structure ZIP pour casser les outils sans
//! gêner l'installation par Android. Quand le crate `zip` refuse l'archive, on
//! bascule sur `apkzip`, un lecteur tolérant calqué sur le chargeur d'APK. Le
//! même motif vaut pour le manifest binaire : `axml` prend le relais quand
//! `axmldecoder` refuse ou panique.
pub mod api_surface;
pub mod apkzip;
pub mod arsc;
pub mod assets;
pub mod axml;
pub mod bundle_archive;
pub mod capabilities;
pub mod cert;
pub mod dart_snapshot;
pub mod dating;
pub mod decompile;
pub mod dex;
pub mod dex_facade;
pub mod dex_strings;
pub mod diff_dex;
pub mod diff_explain;
pub mod diff_matrix;
pub mod diff_strings;
pub mod disasm;
pub mod dyn_entrypoints;
pub mod elf;
pub mod entry_extract;
pub mod manifest;
pub mod manifest_info;
pub mod native_arch;
pub mod native_extract;
pub mod native_static;
pub mod reflection_inputs;
pub mod resource_xref;
pub mod source;
pub mod ui_callbacks;
pub mod xapk;

use crate::cfg::CallGraph;
use crate::model::ApkFeatures;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

/// Au-delà, un nom de sortie est raccourci : marge sous les 255 octets de
/// NAME_MAX (ENAMETOOLONG, os error 63 sur macOS).
pub const MAX_OUTPUT_NAME: usize = 200;
const MAX_OUTPUT_EXT: usize = 16;

/// Nom de fichier de sortie d'une entrée d'archive. `flat` : le chemin `entry`
/// aplati par l'appelant. Rendu tel quel jusqu'à [`MAX_OUTPUT_NAME`] octets ;
/// au-delà, `<préfixe>__<sha256 de entry><.ext>`, préfixe coupé sur une
/// frontière de caractère UTF-8 pour tenir dans [`MAX_OUTPUT_NAME`].
pub fn output_file_name(flat: &str, entry: &str) -> String {
    if flat.len() <= MAX_OUTPUT_NAME {
        return flat.to_string();
    }
    let sha256 = format!("{:x}", Sha256::digest(entry.as_bytes()));
    let base = entry.rsplit(['/', '\\']).next().unwrap_or(entry);
    let ext = match base.rfind('.') {
        Some(at) if at > 0 && at + 1 < base.len() && base.len() - at <= MAX_OUTPUT_EXT + 1 => {
            &base[at..]
        }
        _ => "",
    };
    let mut cut = MAX_OUTPUT_NAME - 2 - sha256.len() - ext.len();
    while !flat.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}__{sha256}{ext}", &flat[..cut])
}

/// Nom de sortie d'une entrée d'archive pour `--extract-libs`, `--extract-entry`
/// et `--extract-assets` : `/` et `\` deviennent `__`, borné par
/// [`output_file_name`].
pub fn flat_output_name(entry: &str) -> String {
    output_file_name(&entry.replace(['/', '\\'], "__"), entry)
}

/// Résultat complet du parsing d'un APK.
pub struct ParsedApk {
    pub features: ApkFeatures,
    pub call_graph: CallGraph,
}

/// Point d'entrée : parse un APK et construit features + CFG inter-proc.
/// `splits` : splits d'un XAPK dont `src` est le base (cf. `xapk::Input`),
/// scannés par `native_arch` ; vide pour un APK simple.
///
/// Un APK sur disque passe par un tempdir pour ses `.dex` et `.so` ; une source
/// en mémoire est lue sans rien écrire. Ses `.so` ne sont pas lus : ils ne
/// servent qu'à `elf::extract`, qui exige un chemin.
pub fn parse_apk(src: impl Into<source::Source>, splits: &[xapk::Split]) -> Result<ParsedApk> {
    let src = src.into();
    tracing::info!(apk = %src, "parsing APK");

    let mut features = ApkFeatures::default();
    let mut call_graph = CallGraph::new();

    let (tmp, want) = match &src {
        source::Source::Path(_) => (
            Some(tempfile::tempdir().context("create tempdir")?),
            Want::DexAndSo,
        ),
        source::Source::Bytes { .. } => (None, Want::DexOnly),
    };
    let entries = extract_apk(&src, tmp.as_ref().map(|t| t.path()), want)?;

    // Manifest (axml) — opère directement sur l'APK.
    manifest::extract(&src, &mut features)?;

    // DEX : chaque classes*.dex -> edges inter-proc accumulés dans le même graphe.
    for item in &entries.dex_files {
        let edges = match item {
            Extracted::File(path) => dex::extract(path, &mut features),
            Extracted::Mem(blob) => dex::extract_bytes(&blob.bytes, &blob.name, &mut features),
        };
        let edges = edges.with_context(|| format!("parse {}", item.label()))?;
        for e in edges {
            call_graph.add_call(e.caller, e.callee, e.site);
        }
    }

    // La hiérarchie de classes n'existe qu'une fois tous les DEX lus : un
    // multidex peut porter la super-classe dans un autre fichier que la sous-classe.
    call_graph.set_supers(features.superclasses.clone());

    // ELF natifs : symboles des .so.
    for item in &entries.so_files {
        if let Extracted::File(so_path) = item {
            elf::extract(so_path, &mut features)
                .with_context(|| format!("parse {}", so_path.display()))?;
        }
    }

    // Architecture native (pur en-tête ELF, en mémoire — indépendant de LIEF).
    // Conditionne la convention d'appel côté SE (Kharon) : arm=AArch32/Thumb,
    // arm64=AAPCS64. Deuxième passe zip header-only, coût négligeable.
    features.native_arch = native_arch::scan_apk_file(&src, splits).context("scan arch native")?;
    tracing::info!(
        abis = ?features.native_arch.abis,
        fat = features.native_arch.is_fat,
        anomalies = features.native_arch.anomalies.len(),
        "native arch"
    );

    Ok(ParsedApk {
        features,
        call_graph,
    })
}

/// Construit features + CFG depuis un **DEX brut** (déjà déballé) : ni
/// manifeste, ni ELF, ni architecture native — il n'y a pas d'archive.
///
/// Conséquence pour l'appelant : `features.components` reste vide, donc
/// `CallGraph::entrypoints` ne rendrait rien. Les racines viennent alors de
/// `CallGraph::heuristic_entrypoints` (cf. `bulk::build_orphan_roots`).
pub fn parse_dex(src: impl Into<source::Source>) -> Result<ParsedApk> {
    let src = src.into();
    tracing::info!(dex = %src, "parsing DEX brut");

    let mut features = ApkFeatures::default();
    let mut call_graph = CallGraph::new();

    let label = src.to_string();
    let edges = dex::extract_bytes(&src.read_all()?, &label, &mut features)
        .with_context(|| format!("parse {label}"))?;
    for e in edges {
        call_graph.add_call(e.caller, e.callee, e.site);
    }
    call_graph.set_supers(features.superclasses.clone());

    Ok(ParsedApk {
        features,
        call_graph,
    })
}

/// Route APK vs DEX brut au **contenu** (magic bytes, cf.
/// `dyn_entrypoints::sniff`) — l'extension n'entre jamais en compte. `splits` :
/// voir [`parse_apk`], sans effet sur un DEX.
pub fn parse_any(src: impl Into<source::Source>, splits: &[xapk::Split]) -> Result<ParsedApk> {
    use self::dyn_entrypoints::InputKind;
    let src = src.into();
    match src.sniff() {
        Some(InputKind::Apk) => parse_apk(src, splits),
        Some(InputKind::Dex) => parse_dex(src),
        None => anyhow::bail!(
            "{src} n'est ni un APK (PK\\x03\\x04) ni un DEX (dex\\n) — reconnu au contenu"
        ),
    }
}

/// Un `classes*.dex` en mémoire : nom d'entrée dans l'archive, ou chemin du DEX
/// brut.
pub struct DexBlob {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// Une entrée retenue : écrite dans le tempdir d'un APK sur disque, ou gardée
/// en mémoire.
enum Extracted {
    File(std::path::PathBuf),
    Mem(DexBlob),
}

impl Extracted {
    fn label(&self) -> String {
        match self {
            Extracted::File(path) => path.display().to_string(),
            Extracted::Mem(blob) => blob.name.clone(),
        }
    }

    fn into_mem(self) -> Option<DexBlob> {
        match self {
            Extracted::Mem(blob) => Some(blob),
            Extracted::File(_) => None,
        }
    }
}

/// Fichiers d'intérêt extraits de l'APK.
#[derive(Default)]
struct ApkEntries {
    dex_files: Vec<Extracted>,
    so_files: Vec<Extracted>,
}

impl ApkEntries {
    /// Range une entrée lue : écrite sous `out_dir` avec le nom `flat`, ou
    /// gardée en mémoire sans `out_dir`.
    fn keep(
        &mut self,
        out_dir: Option<&Path>,
        flat: &str,
        name: &str,
        bytes: Vec<u8>,
        is_dex: bool,
    ) -> Result<()> {
        let item = match out_dir {
            Some(dir) => {
                let dest = dir.join(flat);
                std::fs::write(&dest, &bytes)?;
                Extracted::File(dest)
            }
            None => Extracted::Mem(DexBlob {
                name: name.to_string(),
                bytes,
            }),
        };
        if is_dex {
            self.dex_files.push(item);
        } else {
            self.so_files.push(item);
        }
        Ok(())
    }
}

/// Ce qu'on tire de l'archive. Les passes qui ne relisent que du bytecode
/// (`dyn_entrypoints`, `ui_callbacks`) ne lisent pas les `.so`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    DexAndSo,
    DexOnly,
}

/// Vrai si l'entrée nous intéresse : un `classes*.dex` ou un `lib/**/*.so`.
fn wanted(name: &str, want: Want) -> (bool, bool) {
    let is_dex = name.starts_with("classes") && name.ends_with(".dex");
    let is_so = want == Want::DexAndSo && name.starts_with("lib/") && name.ends_with(".so");
    (is_dex, is_so)
}

/// Lit les `classes*.dex` d'un APK en mémoire, avec le MÊME repli tolérant que
/// [`parse_apk`].
///
/// Pour les passes qui rescannent le bytecode en dehors de `parse_apk`
/// (`dyn_entrypoints`, `ui_callbacks`) : elles ouvraient l'archive elles-mêmes
/// avec le crate `zip` et propageaient son erreur. Sur les APK trafiqués (bit de
/// chiffrement des General Purpose Flags armé, contenu en clair), `by_index`
/// répond « Password required to decrypt file » et l'échantillon entier était
/// perdu — alors même que `parse_apk` en avait tiré manifeste et DEX par le
/// lecteur tolérant.
pub(crate) fn read_dex_files(src: &source::Source) -> Result<Vec<DexBlob>> {
    let entries = extract_apk(src, None, Want::DexOnly)?;
    Ok(entries
        .dex_files
        .into_iter()
        .filter_map(Extracted::into_mem)
        .collect())
}

/// DEX d'une entrée reconnue au contenu : un DEX brut est lu tel quel, un APK
/// donne ses `classes*.dex` par [`read_dex_files`]. Un APK sans DEX est une
/// erreur.
pub(crate) fn dex_inputs(src: &source::Source) -> Result<Vec<DexBlob>> {
    use self::dyn_entrypoints::InputKind;
    match src.sniff() {
        Some(InputKind::Dex) => Ok(vec![DexBlob {
            name: src.to_string(),
            bytes: src.read_all()?,
        }]),
        Some(InputKind::Apk) => {
            let blobs = read_dex_files(src)?;
            if blobs.is_empty() {
                anyhow::bail!("aucun classes*.dex dans l'APK {src}");
            }
            Ok(blobs)
        }
        None => anyhow::bail!("{src} n'est ni un DEX ni un APK — reconnu au contenu"),
    }
}

/// Dézippe l'APK : écrit les classes*.dex et lib/**/*.so dans `out_dir`, ou les
/// garde en mémoire sans `out_dir`.
///
/// Chemin nominal via le crate `zip`. On retombe sur le lecteur tolérant dès
/// qu'il refuse quoi que ce soit — l'archive à l'ouverture, mais aussi une
/// entrée à la lecture : le drapeau de chiffrement et la méthode de compression
/// ne sont contrôlés qu'à ce moment, et c'est là que le trafiquage frappe.
fn extract_apk(src: &source::Source, out_dir: Option<&Path>, want: Want) -> Result<ApkEntries> {
    let file = src.reader().with_context(|| format!("open {src}"))?;
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(e) => {
            tracing::warn!(
                apk = %src,
                error = %e,
                "crate zip en échec, repli sur le lecteur tolérant"
            );
            return extract_apk_tolerant(src, out_dir, want);
        }
    };

    let mut entries = ApkEntries::default();

    for i in 0..zip.len() {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    apk = %src,
                    index = i,
                    error = %e,
                    "entrée refusée par le crate zip, repli sur le lecteur tolérant"
                );
                return extract_apk_tolerant(src, out_dir, want);
            }
        };
        let name = entry.name().to_string();

        let (is_dex, is_so) = wanted(&name, want);
        if !is_dex && !is_so {
            continue;
        }

        // Nom de fichier de sortie aplati (lib/arm64-v8a/foo.so -> arm64-v8a__foo.so).
        let flat = output_file_name(&name.replace('/', "__"), &name);
        let mut buf = Vec::with_capacity(entry.size() as usize);
        let read = entry.read_to_end(&mut buf);
        drop(entry);
        if let Err(e) = read {
            tracing::warn!(
                apk = %src,
                entry = %name,
                error = %e,
                "lecture d'entrée en échec, repli sur le lecteur tolérant"
            );
            return extract_apk_tolerant(src, out_dir, want);
        }
        entries.keep(out_dir, &flat, &name, buf, is_dex)?;
    }

    tracing::info!(
        dex = entries.dex_files.len(),
        so = entries.so_files.len(),
        "APK extracted"
    );
    Ok(entries)
}

/// Repli quand le crate `zip` refuse l'archive : lecteur calqué sur le
/// chargeur d'APK d'Android (cf. `apkzip`). Une entrée illisible est ignorée
/// plutôt que de faire échouer l'extraction complète.
fn extract_apk_tolerant(
    src: &source::Source,
    out_dir: Option<&Path>,
    want: Want,
) -> Result<ApkEntries> {
    let what = format!("lecteur tolérant sur {src}");
    let zip = src.tolerant().context(what)?;
    tracing::warn!(
        entries = zip.len(),
        tampered = zip.tampered_count(),
        "lecteur tolérant actif"
    );

    let mut entries = ApkEntries::default();

    for (i, entry) in zip.entries().iter().enumerate() {
        let name = &entry.name;
        let (is_dex, is_so) = wanted(name, want);
        if !is_dex && !is_so {
            continue;
        }

        // Les noms trafiqués peuvent contenir n'importe quoi : on aplatit et on
        // refuse toute tentative de sortie du répertoire de destination.
        let flat = name.replace('/', "__").replace("..", "__");
        if flat.is_empty() || flat.starts_with('/') {
            tracing::warn!(entry = %name, "nom d'entrée refusé");
            continue;
        }
        let flat = output_file_name(&flat, name);

        let buf = match zip.read(i) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(entry = %name, error = %e, "entrée illisible, ignorée");
                continue;
            }
        };

        entries.keep(out_dir, &flat, name, buf, is_dex)?;
    }

    tracing::info!(
        dex = entries.dex_files.len(),
        so = entries.so_files.len(),
        "APK extracted (lecteur tolérant)"
    );
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_entry_path_yields_a_bounded_name_with_full_hash() {
        let entry = format!("assets/{}/payload.so", "d".repeat(382));
        assert_eq!(entry.len(), 400);
        let name = output_file_name(&entry.replace('/', "__"), &entry);
        let sha256 = format!("{:x}", Sha256::digest(entry.as_bytes()));
        assert_eq!(sha256.len(), 64);
        assert!(name.len() <= 255, "{}", name.len());
        assert!(name.ends_with(".so"), "{name}");
        assert!(name.contains(&sha256), "{name}");

        let entry = format!("libs/{}.so", "é".repeat(200));
        let name = output_file_name(&entry.replace('/', "__"), &entry);
        assert!(name.len() <= MAX_OUTPUT_NAME);
        assert!(name.ends_with(".so"));
    }

    #[test]
    fn flat_output_name_is_shared_and_bounded() {
        assert_eq!(
            flat_output_name("lib/arm64-v8a/libfoo.so"),
            "lib__arm64-v8a__libfoo.so"
        );
        assert_eq!(flat_output_name("res\\raw/plugin"), "res__raw__plugin");

        let entry = format!("assets/{}/cordEX.json", "données/".repeat(30));
        let name = flat_output_name(&entry);
        let sha256 = format!("{:x}", Sha256::digest(entry.as_bytes()));
        assert!(name.len() <= MAX_OUTPUT_NAME, "{}", name.len());
        assert!(name.ends_with(".json"), "{name}");
        assert!(name.contains(&sha256), "{name}");
        assert!(name.starts_with("assets__données__"), "{name}");
    }

    #[test]
    fn short_entry_path_is_unchanged() {
        let entry = "lib/arm64-v8a/libfoo.so";
        let flat = entry.replace('/', "__");
        assert_eq!(output_file_name(&flat, entry), flat);
    }
}
