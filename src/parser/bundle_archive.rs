//! Archive d'un bundle (`--bundle --archive`) : `OUT/<sha256>.bundle.zip`, tout
//! `OUT/<sha256>/` sous le préfixe `<sha256>/`. Même contenu de répertoire,
//! mêmes octets (`--bundle --legend`, Archive).

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Seek;
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

/// Ce que le rapport de `--bundle` dit de l'archive.
#[derive(Debug, Serialize)]
pub struct ArchiveInfo {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// `OUT/<sha256>.bundle.zip`.
pub fn archive_path(out: &Path, sha256: &str) -> PathBuf {
    out.join(format!("{sha256}.bundle.zip"))
}

/// Écrit l'archive de `root` dans un fichier temporaire du répertoire de
/// `dest`, puis le renomme en `dest`. Sans `overwrite`, une archive existante
/// n'est jamais remplacée.
pub fn write(root: &Path, dest: &Path, overwrite: bool) -> Result<ArchiveInfo> {
    let prefix = root
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} : nom de répertoire illisible", root.display()))?;
    let entries = regular_files(root)?;
    let dir = match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let base = dest
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} : nom d'archive illisible", dest.display()))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{base}."))
        .suffix(".tmp")
        .tempfile_in(dir)
        .with_context(|| format!("fichier temporaire dans {}", dir.display()))?;

    let mut zip = ZipWriter::new(tmp.as_file_mut());
    for (name, path) in &entries {
        zip.start_file(format!("{prefix}/{name}"), entry_options())
            .with_context(|| format!("entrée {prefix}/{name}"))?;
        let mut file =
            std::fs::File::open(path).with_context(|| format!("lecture {}", path.display()))?;
        std::io::copy(&mut file, &mut zip)
            .with_context(|| format!("compression {}", path.display()))?;
    }
    let file = zip.finish().context("finalisation de l'archive")?;
    file.sync_all().context("synchronisation de l'archive")?;
    file.rewind()?;
    let mut hasher = Sha256::new();
    let size = std::io::copy(file, &mut hasher).context("relecture de l'archive")?;
    let sha256 = format!("{:x}", hasher.finalize());

    // Mode des fichiers du bundle, plutôt que le 0600 du fichier temporaire.
    if let Some((_, first)) = entries.first() {
        std::fs::set_permissions(tmp.path(), std::fs::metadata(first)?.permissions())?;
    }
    let persisted = if overwrite {
        tmp.persist(dest)
    } else {
        tmp.persist_noclobber(dest)
    };
    let what = format!("renommage en {}", dest.display());
    persisted.map_err(|e| e.error).context(what)?;
    Ok(ArchiveInfo {
        path: dest.display().to_string(),
        size,
        sha256,
    })
}

/// Horodatage, permissions et compression fixes ; aucun champ extra.
fn entry_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6))
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644)
}

/// Fichiers réguliers sous `root`, chemin relatif en `/`, triés par octets.
/// Tout autre type de fichier est refusé plutôt qu'omis.
fn regular_files(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).min_depth(1) {
        let entry = entry?;
        let kind = entry.file_type();
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            bail!(
                "{} n'est pas un fichier régulier : refusé dans l'archive",
                entry.path().display()
            );
        }
        let rel = entry.path().strip_prefix(root)?;
        let parts = rel
            .components()
            .map(|c| c.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow!("{} : nom non UTF-8", entry.path().display()))?;
        out.push((parts.join("/"), entry.path().to_path_buf()));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    /// SHA-256 de `abc`, comme nom de bundle.
    const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn bundle(out: &Path) -> PathBuf {
        let root = out.join(SHA);
        std::fs::create_dir_all(root.join("classes")).unwrap();
        for (name, body) in [
            ("bundle.json", "{\"schema_version\": 1}"),
            ("index.json", "[]"),
            ("errors.json", "[]"),
            ("classes/000000.java", "class A {}\n"),
            ("classes/000000.json", "[]"),
        ] {
            std::fs::write(root.join(name), body).unwrap();
        }
        root
    }

    fn names(path: &Path) -> Vec<String> {
        let file = std::fs::File::open(path).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().to_string())
            .collect()
    }

    #[test]
    fn two_packings_of_one_directory_are_byte_identical() {
        let out = tempfile::tempdir().unwrap();
        let root = bundle(out.path());
        let a = write(&root, &out.path().join("a.zip"), false).unwrap();

        let touched = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(root.join("index.json"))
            .unwrap()
            .set_modified(touched)
            .unwrap();
        let b = write(&root, &out.path().join("b.zip"), false).unwrap();

        let bytes_a = std::fs::read(&a.path).unwrap();
        assert_eq!(bytes_a, std::fs::read(&b.path).unwrap());
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.size, bytes_a.len() as u64);
        assert_eq!(a.sha256, format!("{:x}", Sha256::digest(&bytes_a)));
        assert_eq!(a.sha256.len(), 64);
    }

    #[test]
    fn every_entry_is_under_the_sha256_and_sorted() {
        let out = tempfile::tempdir().unwrap();
        let root = bundle(out.path());
        let dest = archive_path(out.path(), SHA);
        write(&root, &dest, false).unwrap();
        let listed = names(&dest);
        let prefix = format!("{SHA}/");
        assert!(listed.iter().all(|n| n.starts_with(&prefix)), "{listed:?}");
        assert!(listed.contains(&format!("{SHA}/bundle.json")), "{listed:?}");
        let java = format!("{SHA}/classes/000000.java");
        assert!(listed.contains(&java), "{listed:?}");
        assert!(!listed.iter().any(|n| n.ends_with('/')), "{listed:?}");
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(listed, sorted);
    }

    #[test]
    fn an_existing_archive_is_kept_without_overwrite() {
        let out = tempfile::tempdir().unwrap();
        let root = bundle(out.path());
        let dest = archive_path(out.path(), SHA);
        std::fs::write(&dest, "précédente").unwrap();
        assert!(write(&root, &dest, false).is_err());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "précédente");
        write(&root, &dest, true).unwrap();
        assert!(names(&dest).contains(&format!("{SHA}/bundle.json")));
    }

    #[test]
    fn the_archive_is_named_after_the_sha256() {
        assert_eq!(
            archive_path(Path::new("/out"), SHA),
            Path::new("/out").join(format!("{SHA}.bundle.zip"))
        );
    }
}
