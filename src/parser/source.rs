//! Source d'une analyse : un fichier sur disque, ou des octets déjà en mémoire
//! (APK interne d'un XAPK, cf. [`super::xapk`]).
//!
//! C'est la couche d'ouverture d'archive commune aux parseurs : ils demandent
//! un lecteur pour le crate `zip` ([`Source::reader`]), le lecteur tolérant
//! ([`Source::tolerant`]) ou le contenu entier, sans savoir d'où viennent les
//! octets. Une source en mémoire n'écrit jamais rien sur disque.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::apkzip::TolerantZip;
use super::dyn_entrypoints::InputKind;

#[derive(Debug, Clone)]
pub enum Source {
    Path(PathBuf),
    /// `name` : ce qu'affichent les rapports, `<chemin du .xapk>!<entrée>`.
    Bytes {
        name: String,
        data: Arc<[u8]>,
    },
}

/// Lecteur `Read + Seek` des deux formes de source.
pub enum Reader {
    File(std::fs::File),
    Mem(Cursor<Arc<[u8]>>),
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Reader::File(f) => f.read(buf),
            Reader::Mem(c) => c.read(buf),
        }
    }
}

impl Seek for Reader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Reader::File(f) => f.seek(pos),
            Reader::Mem(c) => c.seek(pos),
        }
    }
}

impl Source {
    pub fn bytes(name: impl Into<String>, data: Arc<[u8]>) -> Self {
        Source::Bytes {
            name: name.into(),
            data,
        }
    }

    /// Chemin sur disque ; `None` pour une source en mémoire.
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Source::Path(p) => Some(p),
            Source::Bytes { .. } => None,
        }
    }

    pub fn reader(&self) -> std::io::Result<Reader> {
        match self {
            Source::Path(p) => std::fs::File::open(p).map(Reader::File),
            Source::Bytes { data, .. } => Ok(Reader::Mem(Cursor::new(data.clone()))),
        }
    }

    /// Taille en octets.
    pub fn size(&self) -> Result<u64> {
        match self {
            Source::Path(p) => {
                let meta = std::fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
                Ok(meta.len())
            }
            Source::Bytes { data, .. } => Ok(data.len() as u64),
        }
    }

    /// Lecteur ZIP tolérant sur la source (cf. `apkzip`).
    pub fn tolerant(&self) -> Result<TolerantZip> {
        match self {
            Source::Path(p) => TolerantZip::open(p),
            Source::Bytes { data, .. } => TolerantZip::from_bytes(data.to_vec()),
        }
    }

    /// Contenu entier.
    pub fn read_all(&self) -> Result<Vec<u8>> {
        match self {
            Source::Path(p) => std::fs::read(p).with_context(|| format!("read {}", p.display())),
            Source::Bytes { data, .. } => Ok(data.to_vec()),
        }
    }

    /// SHA-256 complet du contenu, lu par blocs pour une source sur disque.
    pub fn sha256(&self) -> Result<String> {
        let what = format!("ouverture {self}");
        let mut r = self.reader().context(what)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(format!("{:x}", h.finalize()))
    }

    /// APK (`PK\x03\x04`) ou DEX (`dex\n`), reconnu aux quatre premiers octets ;
    /// même règle que `dyn_entrypoints::sniff`.
    pub fn sniff(&self) -> Option<InputKind> {
        let mut magic = [0u8; 4];
        self.reader().ok()?.read_exact(&mut magic).ok()?;
        match &magic {
            b"PK\x03\x04" => Some(InputKind::Apk),
            b"dex\n" => Some(InputKind::Dex),
            _ => None,
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::Path(p) => write!(f, "{}", p.display()),
            Source::Bytes { name, .. } => f.write_str(name),
        }
    }
}

impl From<&Path> for Source {
    fn from(p: &Path) -> Self {
        Source::Path(p.to_path_buf())
    }
}

impl From<&PathBuf> for Source {
    fn from(p: &PathBuf) -> Self {
        Source::Path(p.clone())
    }
}

impl From<PathBuf> for Source {
    fn from(p: PathBuf) -> Self {
        Source::Path(p)
    }
}

impl From<&Source> for Source {
    fn from(s: &Source) -> Self {
        s.clone()
    }
}
