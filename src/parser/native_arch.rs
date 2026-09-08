//! Détection d'architecture des bibliothèques natives (`lib/*/*.so`) d'un APK,
//! **entièrement en mémoire** : on ne lit que l'en-tête ELF (~64 octets) de
//! chaque `.so` directement depuis l'archive zip. Aucun `.so` n'est écrit sur
//! disque, LIEF n'est pas requis → le module tourne dans le build par défaut.
//!
//! Objectif : savoir *quelles ABI / quels bits* embarque un APK avant toute
//! analyse native. C'est l'info qui conditionne la convention d'appel à poser
//! côté exécution symbolique (Kharon) :
//!   - `armeabi-v7a` → AArch32 (args R0–R3 puis pile, `jlong` sur paire de
//!     registres, code éventuellement Thumb) ;
//!   - `arm64-v8a`   → AArch64/AAPCS64 (X0–X7 entiers/pointeurs, V0–V7 flottants).
//!
//! Toutes les étiquettes produites sont définies dans [`legend`] (légende
//! autonome).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};
use std::path::Path;

/// Nombre d'octets d'en-tête lus par `.so` (suffit pour EI_CLASS/EI_DATA/e_machine).
const ELF_HEADER_PROBE: usize = 64;

/// Taille (bits) du code natif — dérivée de `EI_CLASS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bits {
    /// ELFCLASS32 — pointeurs 32 bits.
    B32,
    /// ELFCLASS64 — pointeurs 64 bits.
    B64,
}

/// Boutisme — dérivé de `EI_DATA`. Sur Android : toujours `Little`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

/// Architecture machine — dérivée de `e_machine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Machine {
    /// EM_ARM (40) — ARM 32 bits (AArch32).
    Arm,
    /// EM_AARCH64 (183) — ARM 64 bits (AArch64).
    Aarch64,
    /// EM_386 (3) — x86 32 bits.
    X86,
    /// EM_X86_64 (62) — x86-64.
    X86_64,
    /// EM_MIPS (8) — MIPS (legacy Android).
    Mips,
    /// EM_RISCV (243) — RISC-V (64 bits sur Android).
    Riscv,
    /// Valeur `e_machine` non répertoriée ici.
    Unknown(u16),
}

impl Machine {
    fn from_e_machine(em: u16) -> Machine {
        match em {
            3 => Machine::X86,
            8 => Machine::Mips,
            40 => Machine::Arm,
            62 => Machine::X86_64,
            183 => Machine::Aarch64,
            243 => Machine::Riscv,
            other => Machine::Unknown(other),
        }
    }
    /// Libellé stable pour l'agrégat / le JSON.
    pub fn label(&self) -> String {
        match self {
            Machine::Arm => "arm".into(),
            Machine::Aarch64 => "aarch64".into(),
            Machine::X86 => "x86".into(),
            Machine::X86_64 => "x86_64".into(),
            Machine::Mips => "mips".into(),
            Machine::Riscv => "riscv".into(),
            Machine::Unknown(v) => format!("unknown(0x{v:04x})"),
        }
    }
}

/// ABI déclarée par le répertoire `lib/<abi>/…` (NDK ABI name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Abi {
    ArmeabiV7a,
    Armeabi,
    Arm64V8a,
    X86,
    X86_64,
    Mips,
    Mips64,
    Riscv64,
    /// Répertoire `lib/<abi>` non standard.
    Other(String),
}

impl Abi {
    pub fn from_dir(dir: &str) -> Abi {
        match dir {
            "armeabi-v7a" => Abi::ArmeabiV7a,
            "armeabi" => Abi::Armeabi,
            "arm64-v8a" => Abi::Arm64V8a,
            "x86" => Abi::X86,
            "x86_64" => Abi::X86_64,
            "mips" => Abi::Mips,
            "mips64" => Abi::Mips64,
            "riscv64" => Abi::Riscv64,
            other => Abi::Other(other.to_string()),
        }
    }
    pub fn label(&self) -> String {
        match self {
            Abi::ArmeabiV7a => "armeabi-v7a".into(),
            Abi::Armeabi => "armeabi".into(),
            Abi::Arm64V8a => "arm64-v8a".into(),
            Abi::X86 => "x86".into(),
            Abi::X86_64 => "x86_64".into(),
            Abi::Mips => "mips".into(),
            Abi::Mips64 => "mips64".into(),
            Abi::Riscv64 => "riscv64".into(),
            Abi::Other(s) => s.clone(),
        }
    }
}

/// (machine, bits) attendus pour une ABI — `None` = ABI non standard (pas de
/// contrôle de cohérence possible).
fn expected_arch(abi: &Abi) -> Option<(Machine, Bits)> {
    match abi {
        Abi::ArmeabiV7a | Abi::Armeabi => Some((Machine::Arm, Bits::B32)),
        Abi::Arm64V8a => Some((Machine::Aarch64, Bits::B64)),
        Abi::X86 => Some((Machine::X86, Bits::B32)),
        Abi::X86_64 => Some((Machine::X86_64, Bits::B64)),
        Abi::Mips => Some((Machine::Mips, Bits::B32)),
        Abi::Mips64 => Some((Machine::Mips, Bits::B64)),
        Abi::Riscv64 => Some((Machine::Riscv, Bits::B64)),
        Abi::Other(_) => None,
    }
}

/// Résultat du parsing d'un en-tête ELF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElfArch {
    pub bits: Bits,
    pub endian: Endian,
    pub machine: Machine,
}

/// Parse l'en-tête ELF (≥ 20 octets requis). `None` si ce n'est pas un ELF.
pub fn parse_elf_header(bytes: &[u8]) -> Option<ElfArch> {
    if bytes.len() < 20 || &bytes[0..4] != b"\x7FELF" {
        return None;
    }
    let bits = match bytes[4] {
        1 => Bits::B32,
        2 => Bits::B64,
        _ => return None,
    };
    let endian = match bytes[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        _ => return None,
    };
    // e_machine : offset 18, largeur 2, boutisme = EI_DATA (identique 32/64).
    let em = match endian {
        Endian::Little => u16::from_le_bytes([bytes[18], bytes[19]]),
        Endian::Big => u16::from_be_bytes([bytes[18], bytes[19]]),
    };
    Some(ElfArch {
        bits,
        endian,
        machine: Machine::from_e_machine(em),
    })
}

/// Une bibliothèque native résolue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLib {
    /// Chemin dans l'APK : `lib/arm64-v8a/libfoo.so`.
    pub entry: String,
    /// Nom de fichier : `libfoo.so`.
    pub file: String,
    /// ABI déclarée par le répertoire.
    pub declared_abi: Abi,
    pub bits: Bits,
    pub endian: Endian,
    pub machine: Machine,
    /// `true` si la machine/bits de l'ELF ne correspond pas au répertoire ABI
    /// (lib mal rangée / APK repackagé — signal CTI).
    pub abi_mismatch: bool,
}

/// Classe une entrée d'archive :
/// - `None` : ce n'est pas une `lib/<abi>/*.so` ;
/// - `Some(Ok(lib))` : en-tête ELF lisible ;
/// - `Some(Err(raison))` : c'est bien une `.so` mais l'ELF est invalide.
pub fn classify(entry: &str, header: &[u8]) -> Option<std::result::Result<NativeLib, String>> {
    if !entry.starts_with("lib/") || !entry.ends_with(".so") {
        return None;
    }
    let parts: Vec<&str> = entry.split('/').collect();
    if parts.len() < 3 {
        return None;
    }
    let abi = Abi::from_dir(parts[1]);
    let file = parts.last().copied().unwrap_or(entry).to_string();

    let arch = match parse_elf_header(header) {
        Some(a) => a,
        None => return Some(Err(format!("{entry}: en-tête ELF illisible / non-ELF"))),
    };

    // Mismatch : uniquement quand l'attendu ET la machine lue sont connus.
    let abi_mismatch = match expected_arch(&abi) {
        Some((em, eb)) => {
            !matches!(arch.machine, Machine::Unknown(_)) && (arch.machine != em || arch.bits != eb)
        }
        None => false,
    };

    Some(Ok(NativeLib {
        entry: entry.to_string(),
        file,
        declared_abi: abi,
        bits: arch.bits,
        endian: arch.endian,
        machine: arch.machine,
        abi_mismatch,
    }))
}

/// Synthèse d'architecture native pour un APK.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeArchSummary {
    /// Une entrée par `.so` trouvée.
    pub libs: Vec<NativeLib>,
    /// ABIs présentes (répertoires `lib/<abi>`), uniques et triées.
    pub abis: Vec<String>,
    /// Machines ELF présentes, uniques et triées.
    pub machines: Vec<String>,
    pub has_32: bool,
    pub has_64: bool,
    /// `true` si l'APK embarque à la fois du 32 et du 64 bits (APK "fat").
    pub is_fat: bool,
    /// Convention d'appel à poser côté SE, une par couple (machine,bits) présent.
    pub calling_conventions: Vec<String>,
    /// Incohérences (mismatch ABI, ELF invalide).
    pub anomalies: Vec<String>,
}

impl NativeArchSummary {
    /// Construit l'agrégat depuis les libs classées + anomalies déjà collectées.
    pub fn build(libs: Vec<NativeLib>, mut anomalies: Vec<String>) -> Self {
        let mut abis: Vec<String> = libs.iter().map(|l| l.declared_abi.label()).collect();
        abis.sort();
        abis.dedup();

        let mut machines: Vec<String> = libs.iter().map(|l| l.machine.label()).collect();
        machines.sort();
        machines.dedup();

        let has_32 = libs.iter().any(|l| l.bits == Bits::B32);
        let has_64 = libs.iter().any(|l| l.bits == Bits::B64);

        // Une convention d'appel par (machine, bits) distinct.
        let mut seen: Vec<(Machine, Bits)> = Vec::new();
        let mut calling_conventions = Vec::new();
        for l in &libs {
            let key = (l.machine, l.bits);
            if !seen.contains(&key) {
                seen.push(key);
                calling_conventions.push(calling_convention(l.machine, l.bits));
            }
            if l.abi_mismatch {
                anomalies.push(format!(
                    "{}: ELF {} {} rangé dans lib/{}/ (attendu {})",
                    l.entry,
                    l.machine.label(),
                    bits_label(l.bits),
                    l.declared_abi.label(),
                    expected_label(&l.declared_abi),
                ));
            }
        }

        NativeArchSummary {
            libs,
            abis,
            machines,
            has_32,
            has_64,
            is_fat: has_32 && has_64,
            calling_conventions,
            anomalies,
        }
    }
}

fn bits_label(b: Bits) -> &'static str {
    match b {
        Bits::B32 => "32-bit",
        Bits::B64 => "64-bit",
    }
}

fn expected_label(abi: &Abi) -> String {
    match expected_arch(abi) {
        Some((m, b)) => format!("{} {}", m.label(), bits_label(b)),
        None => "ABI non standard".to_string(),
    }
}

/// Convention d'appel native pour un couple (machine, bits) — le renseignement
/// clé pour poser l'état registre/pile de l'exécution symbolique.
fn calling_convention(machine: Machine, bits: Bits) -> String {
    match (machine, bits) {
        (Machine::Arm, Bits::B32) => "armeabi-v7a → AArch32 (AAPCS32) : JNIEnv*=R0, this/clazz=R1, args Java dès R2 ; R0–R3 puis pile ; jlong/jdouble sur paire de registres alignée ; code éventuellement Thumb (bit0=1 des adresses de fonction)".into(),
        (Machine::Aarch64, Bits::B64) => "arm64-v8a → AArch64 (AAPCS64) : JNIEnv*=X0, this/clazz=X1, args Java dès X2 ; entiers/pointeurs X0–X7, flottants V0–V7 ; jlong sur un seul registre X".into(),
        (Machine::X86, Bits::B32) => "x86 → SysV/cdecl 32 bits : tous les args sur la pile (JNIEnv* puis this/clazz en tête)".into(),
        (Machine::X86_64, Bits::B64) => "x86_64 → SysV AMD64 : args entiers RDI, RSI, RDX, RCX, R8, R9 puis pile ; JNIEnv*=RDI, this/clazz=RSI".into(),
        (m, b) => format!("{} {} : convention d'appel non modélisée ici", m.label(), bits_label(b)),
    }
}

/// Scanne un APK déjà chargé en mémoire (octets de l'archive zip).
pub fn scan_apk_bytes(apk: &[u8]) -> Result<NativeArchSummary> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(apk))
        .context("lecture APK (zip) depuis la mémoire")?;
    scan_archive(&mut archive)
}

/// Scanne un APK sur disque. Ne lit que les en-têtes ELF — l'APK n'est pas
/// chargé en entier, aucun `.so` n'est extrait.
///
/// Repli sur le lecteur tolérant si le crate `zip` refuse l'archive ou l'une de
/// ses entrées : sur un APK trafiqué, une seule entrée chiffrée en apparence
/// faisait échouer tout le scan.
pub fn scan_apk_file(path: &Path) -> Result<NativeArchSummary> {
    let file = std::fs::File::open(path).with_context(|| format!("ouverture {}", path.display()))?;
    let nominal = zip::ZipArchive::new(file)
        .context("lecture APK (zip)")
        .and_then(|mut archive| scan_archive(&mut archive));

    match nominal {
        Ok(summary) => Ok(summary),
        Err(e) => {
            tracing::warn!(
                apk = %path.display(),
                error = %e,
                "scan natif en échec par le crate zip, repli sur le lecteur tolérant"
            );
            scan_apk_tolerant(path)
        }
    }
}

/// Repli via le lecteur ZIP tolérant. Une entrée illisible devient une anomalie
/// au lieu de faire échouer le scan entier — un `.so` perdu vaut mieux qu'un
/// échantillon perdu.
fn scan_apk_tolerant(path: &Path) -> Result<NativeArchSummary> {
    let zip = super::apkzip::TolerantZip::open(path)?;
    let mut libs = Vec::new();
    let mut anomalies = Vec::new();

    for (i, entry) in zip.entries().iter().enumerate() {
        let name = &entry.name;
        if !name.starts_with("lib/") || !name.ends_with(".so") {
            continue;
        }
        let bytes = match zip.read(i) {
            Ok(b) => b,
            Err(e) => {
                anomalies.push(format!("{name}: entrée illisible ({e})"));
                continue;
            }
        };
        let n = bytes.len().min(ELF_HEADER_PROBE);
        match classify(name, &bytes[..n]) {
            Some(Ok(lib)) => libs.push(lib),
            Some(Err(reason)) => anomalies.push(reason),
            None => {}
        }
    }

    Ok(NativeArchSummary::build(libs, anomalies))
}

fn scan_archive<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> Result<NativeArchSummary> {
    let mut libs = Vec::new();
    let mut anomalies = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .with_context(|| format!("entrée zip #{i}"))?;
        let name = entry.name().to_string();
        if !name.starts_with("lib/") || !name.ends_with(".so") {
            continue;
        }
        let mut header = [0u8; ELF_HEADER_PROBE];
        let n = read_up_to(&mut entry, &mut header)?;
        match classify(&name, &header[..n]) {
            Some(Ok(lib)) => libs.push(lib),
            Some(Err(reason)) => anomalies.push(reason),
            None => {}
        }
    }

    Ok(NativeArchSummary::build(libs, anomalies))
}

/// Lit au plus `buf.len()` octets ; tolère les lectures courtes du décompresseur.
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// Légende autonome de toutes les étiquettes produites par ce module.
pub fn legend() -> &'static str {
    "\
Bits         B32 = ELFCLASS32 (pointeurs 32 bits) ; B64 = ELFCLASS64 (64 bits).
Endian       Little / Big (EI_DATA). Android = toujours Little.
Machine      Architecture ELF (e_machine) : arm (AArch32), aarch64 (AArch64),
             x86, x86_64, mips, riscv, unknown(0x..).
Abi          Répertoire NDK lib/<abi>/ : armeabi-v7a, arm64-v8a, x86, x86_64, …
abi_mismatch La machine/bits de l'ELF ne colle pas au répertoire ABI (lib mal
             rangée ou APK repackagé — signal CTI).
is_fat       L'APK embarque à la fois du 32 et du 64 bits.
calling_conventions
             Convention d'appel native à poser côté SE (registres d'arguments,
             position de JNIEnv*/this, largeur de jlong, Thumb éventuel) — un
             item par couple (machine,bits) présent."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header(class: u8, data: u8, machine: u16) -> [u8; 64] {
        let mut h = [0u8; 64];
        h[0..4].copy_from_slice(b"\x7FELF");
        h[4] = class;
        h[5] = data;
        h[6] = 1; // EI_VERSION
        h[16] = 3; // e_type = ET_DYN (octet bas, LE)
        let m = if data == 1 {
            machine.to_le_bytes()
        } else {
            machine.to_be_bytes()
        };
        h[18] = m[0];
        h[19] = m[1];
        h
    }

    #[test]
    fn parse_aarch64_le() {
        let a = parse_elf_header(&elf_header(2, 1, 183)).unwrap();
        assert_eq!(a.bits, Bits::B64);
        assert_eq!(a.endian, Endian::Little);
        assert_eq!(a.machine, Machine::Aarch64);
    }

    #[test]
    fn parse_arm32_le() {
        let a = parse_elf_header(&elf_header(1, 1, 40)).unwrap();
        assert_eq!(a.bits, Bits::B32);
        assert_eq!(a.machine, Machine::Arm);
    }

    #[test]
    fn rejects_non_elf() {
        assert!(parse_elf_header(b"PK\x03\x04not-an-elf-header-padding").is_none());
    }

    #[test]
    fn classify_mismatch_arm32_in_arm64_dir() {
        // ELF ARM 32 bits rangé dans arm64-v8a → mismatch détecté.
        let r = classify("lib/arm64-v8a/libx.so", &elf_header(1, 1, 40))
            .unwrap()
            .unwrap();
        assert!(r.abi_mismatch);
        assert_eq!(r.bits, Bits::B32);
        assert_eq!(r.machine, Machine::Arm);
    }

    #[test]
    fn classify_coherent_arm64() {
        let r = classify("lib/arm64-v8a/libx.so", &elf_header(2, 1, 183))
            .unwrap()
            .unwrap();
        assert!(!r.abi_mismatch);
        assert_eq!(r.file, "libx.so");
    }

    #[test]
    fn ignores_non_native_entries() {
        assert!(classify("classes.dex", &[0u8; 64]).is_none());
        assert!(classify("lib/arm64-v8a/notes.txt", &[0u8; 64]).is_none());
    }

    #[test]
    fn summary_fat_apk() {
        let libs = vec![
            classify("lib/armeabi-v7a/libx.so", &elf_header(1, 1, 40))
                .unwrap()
                .unwrap(),
            classify("lib/arm64-v8a/libx.so", &elf_header(2, 1, 183))
                .unwrap()
                .unwrap(),
        ];
        let s = NativeArchSummary::build(libs, vec![]);
        assert!(s.is_fat && s.has_32 && s.has_64);
        assert_eq!(s.abis, vec!["arm64-v8a", "armeabi-v7a"]);
        assert_eq!(s.calling_conventions.len(), 2);
        assert!(s.anomalies.is_empty());
    }
}
