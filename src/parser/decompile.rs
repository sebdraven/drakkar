//! Décompilation Java (dex-decompiler) et matière du mode `--bundle`.
//!
//! Deux lectures du même DEX coexistent : `dex_facade` pour le désassemblage,
//! les empreintes et les valeurs statiques, le `DexFile` de dex-decompiler pour
//! le Java. Elles sont appariées par index de `class_defs`, puis vérifiées par
//! `method_idx` avant toute attribution.

use crate::parser::dex_facade::{DexBin, DexClass, DexValue};
use crate::parser::diff_dex::opcode_fingerprint;
use crate::parser::diff_matrix::is_application_class;
use crate::parser::disasm::{self, ClassDisasm, DisasmReport, Insn, MethodDisasm};
use crate::parser::dyn_entrypoints::{sniff, InputKind};
use anyhow::{bail, Context, Result};
use dex_decompiler::java::descriptor_to_java;
use dex_decompiler::{Decompiler, DexFile, EncodedMethod};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

const CARGO_LOCK: &str = include_str!("../../Cargo.lock");

const UNREADABLE: &str = "dex-decompiler n'a pas pu lire ce DEX";
const MISALIGNED: &str =
    "méthodes de dex_facade et de dex-decompiler non appariables (nombre ou method_idx)";
const DASM_LAYOUT: &str = "découpage du .dasm incohérent avec disasm::render";

/// Un DEX de l'entrée.
pub struct DexEntry {
    /// Nom de l'entrée de l'archive (`/` aplati en `__`), ou nom du fichier
    /// pour un DEX brut.
    pub name: String,
    pub sha256: String,
    path: PathBuf,
}

/// L'entrée, reconnue au contenu, et ses DEX matérialisés sur disque.
pub struct Input {
    pub kind: InputKind,
    pub sha256: String,
    /// Taille du fichier d'entrée, en octets.
    pub size: u64,
    pub dexes: Vec<DexEntry>,
    _tmp: Option<tempfile::TempDir>,
}

/// Statut de décompilation d'une méthode, rangé par gravité croissante.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Partial,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    App,
    Lib,
}

/// Issue de `decompile_class`, donc présence de `classes/<id>.class.java`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClassJavaStatus {
    Ok,
    Failed,
}

/// Une entrée de `index.json`.
#[derive(Debug, Serialize)]
pub struct ClassEntry {
    pub id: usize,
    pub descriptor: Option<String>,
    pub dex: String,
    pub package: Option<String>,
    pub origin: Option<Origin>,
    pub methods: usize,
    /// `rules_direct` et `rules_path` sont remplis par l'appelant, qui détient
    /// les résultats du moteur de règles.
    pub rules_direct: Vec<String>,
    pub rules_path: Vec<String>,
    pub decompile_status: Status,
    pub class_java: ClassJavaStatus,
}

/// Une entrée de `classes/<id>.json`.
#[derive(Debug, Serialize)]
pub struct MethodRecord {
    pub signature: String,
    pub access: Option<u32>,
    pub code_offset: Option<u32>,
    pub insns_count: Option<usize>,
    pub opcode_fingerprint: Option<String>,
    pub decompile_status: Status,
    pub partial_markers: Vec<String>,
    pub error: Option<String>,
    pub java_lines: Option<[usize; 2]>,
    pub dasm_lines: Option<[usize; 2]>,
}

#[derive(Debug, Serialize)]
pub struct StaticValue {
    pub dex: String,
    pub field: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Pool {
    pub dex: String,
    pub declared: usize,
    pub unreadable: usize,
    pub strings: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub classes: usize,
    pub methods: usize,
    pub decompile_ok: usize,
    pub decompile_partial: usize,
    pub decompile_failed: usize,
}

/// Une entrée de `errors.json`.
#[derive(Debug, Serialize)]
pub struct BundleError {
    pub stage: &'static str,
    pub dex: Option<String>,
    pub class_id: Option<usize>,
    pub target: Option<String>,
    pub error: String,
}

impl BundleError {
    pub fn new(stage: &'static str, error: impl Into<String>) -> Self {
        Self {
            stage,
            dex: None,
            class_id: None,
            target: None,
            error: error.into(),
        }
    }

    fn in_dex(stage: &'static str, dex: &str, error: impl Into<String>) -> Self {
        Self {
            dex: Some(dex.to_string()),
            ..Self::new(stage, error)
        }
    }

    fn in_class(
        stage: &'static str,
        dex: &str,
        class_id: Option<usize>,
        target: Option<&str>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            dex: Some(dex.to_string()),
            class_id,
            target: target.map(str::to_string),
            ..Self::new(stage, error)
        }
    }
}

/// Ce que `decompile_all` rend en plus des fichiers de `classes/`.
#[derive(Default)]
pub struct Decompiled {
    pub classes: Vec<ClassEntry>,
    pub static_values: Vec<StaticValue>,
    pub stats: Stats,
    pub errors: Vec<BundleError>,
}

/// Version de la structure du bundle, incrémentée à toute modification
/// incompatible (`--bundle --legend`).
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Contenu de `bundle.json`.
#[derive(Serialize)]
pub struct BundleInfo<'a> {
    pub schema_version: u32,
    pub sha256: &'a str,
    pub input_size: u64,
    pub input_kind: &'static str,
    pub dex_files: Vec<DexFileInfo<'a>>,
    pub drakkar_version: &'static str,
    pub decompiler: DecompilerInfo,
    /// `None` quand rules.json est null.
    pub rules_hash: Option<String>,
    pub generated_at: String,
    pub packed: Packed,
    pub stats: &'a Stats,
}

#[derive(Serialize)]
pub struct DexFileInfo<'a> {
    pub name: &'a str,
    pub sha256: &'a str,
}

#[derive(Serialize)]
pub struct DecompilerInfo {
    #[serde(rename = "crate")]
    pub krate: &'static str,
    pub rev: Option<&'static str>,
}

/// Drakkar n'a pas de détection de packer : `detected` vaut toujours `None`.
#[derive(Serialize)]
pub struct Packed {
    pub detected: Option<bool>,
    pub packer: Option<String>,
    pub evidence: Vec<String>,
}

impl<'a> BundleInfo<'a> {
    pub fn new(
        input: &'a Input,
        stats: &'a Stats,
        generated_at: String,
        rules_hash: Option<String>,
    ) -> Self {
        Self {
            schema_version: BUNDLE_SCHEMA_VERSION,
            sha256: &input.sha256,
            input_size: input.size,
            input_kind: match input.kind {
                InputKind::Apk => "apk",
                InputKind::Dex => "dex",
            },
            dex_files: input
                .dexes
                .iter()
                .map(|d| DexFileInfo {
                    name: &d.name,
                    sha256: &d.sha256,
                })
                .collect(),
            drakkar_version: env!("CARGO_PKG_VERSION"),
            decompiler: DecompilerInfo {
                krate: "dex-decompiler",
                rev: decompiler_rev(),
            },
            rules_hash,
            generated_at,
            packed: Packed {
                detected: None,
                packer: None,
                evidence: Vec::new(),
            },
            stats,
        }
    }
}

/// Java d'une classe sélectionnée par `--decompile`.
pub struct ClassJava {
    pub descriptor: String,
    pub dex: String,
    /// Valeurs initiales des champs statiques, lues par Drakkar et non par le
    /// décompilateur.
    pub statics: Vec<disasm::StaticInit>,
    pub java: String,
    /// Raison du repli méthode par méthode, quand `decompile_class` a échoué.
    pub fallback: Option<String>,
}

pub struct DecompileReport {
    pub classes: Vec<ClassJava>,
    /// Classes lues en tout, avant filtre.
    pub scanned: usize,
}

/// Reconnaît l'entrée aux octets de tête et matérialise ses DEX. Un APK passe
/// par `parser::extract_dex_files`, donc par le repli `TolerantZip`.
pub fn open(path: &Path) -> Result<Input> {
    let Some(kind) = sniff(path) else {
        bail!(
            "{} n'est ni un APK (PK\\x03\\x04) ni un DEX (dex\\n) — reconnu au contenu",
            path.display()
        );
    };
    let (paths, tmp) = match kind {
        InputKind::Dex => (vec![path.to_path_buf()], None),
        InputKind::Apk => {
            let tmp = tempfile::tempdir().context("create tempdir")?;
            let paths = crate::parser::extract_dex_files(path, tmp.path())?;
            (paths, Some(tmp))
        }
    };
    if paths.is_empty() {
        bail!("aucun classes*.dex dans {}", path.display());
    }
    let mut dexes = Vec::with_capacity(paths.len());
    for p in paths {
        dexes.push(DexEntry {
            name: file_name(&p),
            sha256: sha256_file(&p)?,
            path: p,
        });
    }
    Ok(Input {
        kind,
        sha256: sha256_file(path)?,
        size: std::fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .len(),
        dexes,
        _tmp: tmp,
    })
}

/// Désassemble et décompile CHAQUE classe et CHAQUE méthode, sans filtre, et
/// écrit `classes/<id>.{java,dasm,json}` dans `dir`.
pub fn decompile_all(input: &Input, dir: &Path) -> Decompiled {
    let mut out = Decompiled::default();
    let loaded = load(input, &mut out.errors);
    let mut next_id = 0usize;
    for (di, dex) in loaded.iter().enumerate() {
        let make = || decompiler_for(&loaded, di);
        let ctx = Ctx {
            dex,
            rebuild: &make,
        };
        let base = next_id;
        let jobs: Vec<_> = dex
            .bin
            .classes()
            .enumerate()
            .map(|(i, class)| (base + i, i as u32, class))
            .collect();
        next_id += jobs.len();
        let outcomes: Vec<ClassOutcome> = jobs
            .into_par_iter()
            .map_init(&make, |dec, job| process_class(&ctx, dec, job, dir))
            .collect();
        for o in outcomes {
            out.stats.classes += 1;
            for s in &o.statuses {
                out.stats.methods += 1;
                match s {
                    Status::Ok => out.stats.decompile_ok += 1,
                    Status::Partial => out.stats.decompile_partial += 1,
                    Status::Failed => out.stats.decompile_failed += 1,
                }
            }
            out.static_values.extend(o.statics);
            out.errors.extend(o.errors);
            out.classes.push(o.entry);
        }
    }
    out
}

/// Pool de chaînes de chaque DEX, lu par le parseur de `--strings`.
pub fn string_pools(input: &Input) -> (Vec<Pool>, Vec<BundleError>) {
    let mut pools = Vec::new();
    let mut errors = Vec::new();
    for entry in &input.dexes {
        match crate::parser::dex_strings::extract(&entry.path) {
            Ok(p) => pools.push(Pool {
                dex: entry.name.clone(),
                declared: p.declared,
                unreadable: p.unreadable,
                strings: p.strings,
            }),
            Err(e) => {
                let error = format!("{e:#}");
                errors.push(BundleError::in_dex("strings", &entry.name, error));
            }
        }
    }
    (pools, errors)
}

/// `--decompile` : Java des classes dont le descripteur contient un motif,
/// même sélection que `--disasm`. `decompile_class` d'abord, repli méthode par
/// méthode quand il échoue.
pub fn decompile_matching(path: &Path, patterns: &[String]) -> Result<DecompileReport> {
    let input = open(path)?;
    let mut errors = Vec::new();
    let loaded = load(&input, &mut errors);
    for e in &errors {
        tracing::warn!(stage = e.stage, dex = ?e.dex, error = %e.error, "lecture du DEX");
    }
    let mut report = DecompileReport {
        classes: Vec::new(),
        scanned: 0,
    };
    for (di, dex) in loaded.iter().enumerate() {
        let make = || decompiler_for(&loaded, di);
        let ctx = Ctx {
            dex,
            rebuild: &make,
        };
        let mut dec = make();
        for (i, class) in dex.bin.classes().enumerate() {
            let class = match class {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(dex = %dex.name, error = %e, "skip unreadable class");
                    continue;
                }
            };
            report.scanned += 1;
            if !disasm::selected(class.descriptor, patterns) {
                continue;
            }
            let idx = i as u32;
            let (java, fallback) = match whole_class(&ctx, &mut dec, idx) {
                Ok(java) => (java, None),
                Err(why) => {
                    let run = AssertUnwindSafe(|| render_class(&ctx, &mut dec, idx, &class, None));
                    match catch_unwind(run) {
                        Ok(r) => (r.java, Some(why)),
                        Err(p) => {
                            dec = make();
                            let why = format!("{why} ; repli : {}", panic_message(&*p));
                            (String::new(), Some(why))
                        }
                    }
                }
            };
            report.classes.push(ClassJava {
                descriptor: class.descriptor.to_string(),
                dex: dex.name.clone(),
                statics: disasm::static_inits(&dex.bin, &class, &[]),
                java,
                fallback,
            });
        }
    }
    if report.classes.is_empty() {
        bail!(
            "aucune classe ne correspond à {:?} dans {} ({} classes lues) — le motif est \
             comparé au descripteur Dalvik, essaie `services/g` ou `Lcom/dy/`",
            patterns,
            path.display(),
            report.scanned
        );
    }
    Ok(report)
}

/// Rendu de `--decompile` sur stdout.
pub fn render(r: &DecompileReport) -> String {
    let mut s = String::new();
    for c in &r.classes {
        s.push_str(&format!("// == {} — {} ==\n", c.descriptor, c.dex));
        for st in &c.statics {
            s.push_str(&format!("// {}\n", disasm::render_static(st)));
        }
        if let Some(why) = &c.fallback {
            let why = why.replace(['\n', '\r'], " ");
            s.push_str(&format!(
                "// repli méthode par méthode — decompile_class : {why}\n"
            ));
        }
        s.push_str(&c.java);
        if !c.java.is_empty() && !c.java.ends_with('\n') {
            s.push('\n');
        }
        s.push('\n');
    }
    s
}

/// Commit complet de dex-decompiler tel que résolu dans le `Cargo.lock`
/// compilé avec ce binaire.
pub fn decompiler_rev() -> Option<&'static str> {
    locked_git_rev(CARGO_LOCK, "dex-decompiler")
}

/// Message d'une panique rattrapée par `catch_unwind`.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "charge non textuelle".to_string());
    format!("panic : {msg}")
}

struct LoadedDex {
    name: String,
    bin: DexBin,
    file: Option<DexFile>,
}

struct Ctx<'a, 'r> {
    dex: &'a LoadedDex,
    /// Un `Decompiler` neuf : ses caches internes ne sont plus fiables après
    /// une panique.
    rebuild: &'r (dyn Fn() -> Option<Decompiler<'a>> + Sync),
}

struct Failure {
    message: String,
    panicked: bool,
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            panicked: false,
        }
    }
}

#[derive(Default)]
struct Rendered {
    java: String,
    dasm: String,
    methods: Vec<MethodRecord>,
    statics: Vec<StaticValue>,
    errors: Vec<BundleError>,
}

struct ClassOutcome {
    entry: ClassEntry,
    statuses: Vec<Status>,
    statics: Vec<StaticValue>,
    errors: Vec<BundleError>,
}

type Job<'a> = (usize, u32, Result<DexClass<'a>>);

fn load(input: &Input, errors: &mut Vec<BundleError>) -> Vec<LoadedDex> {
    let mut out = Vec::new();
    for entry in &input.dexes {
        let bin = match catch_unwind(AssertUnwindSafe(|| DexBin::open(&entry.path))) {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                let error = format!("{e:#}");
                errors.push(BundleError::in_dex("dex", &entry.name, error));
                continue;
            }
            Err(p) => {
                errors.push(BundleError::in_dex("dex", &entry.name, panic_message(&*p)));
                continue;
            }
        };
        let file = match std::fs::read(&entry.path) {
            Ok(bytes) => match guarded(|| dex_decompiler::parse_dex(&bytes)) {
                Ok(f) => Some(f),
                Err(f) => {
                    errors.push(BundleError::in_dex("decompile", &entry.name, f.message));
                    None
                }
            },
            Err(e) => {
                errors.push(BundleError::in_dex("decompile", &entry.name, e.to_string()));
                None
            }
        };
        out.push(LoadedDex {
            name: entry.name.clone(),
            bin,
            file,
        });
    }
    out
}

/// Les autres DEX de l'entrée sont passés en extra : dex-decompiler y résout
/// les classes internes et anonymes d'un multidex.
fn decompiler_for(loaded: &[LoadedDex], di: usize) -> Option<Decompiler<'_>> {
    let primary = loaded[di].file.as_ref()?;
    let extras = loaded
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != di)
        .filter_map(|(_, l)| l.file.as_ref())
        .collect();
    Some(Decompiler::new(primary).with_extra_dexes(extras))
}

fn guarded<T>(run: impl FnOnce() -> dex_decompiler::Result<T>) -> Result<T, Failure> {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Failure::from(e.to_string())),
        Err(p) => Err(Failure {
            message: panic_message(&*p),
            panicked: true,
        }),
    }
}

/// `decompile_class` sur la classe d'index `idx`. Le `Decompiler` est
/// reconstruit après une panique.
fn whole_class<'a>(
    ctx: &Ctx<'a, '_>,
    dec: &mut Option<Decompiler<'a>>,
    idx: u32,
) -> Result<String, String> {
    let (Some(file), Some(d)) = (&ctx.dex.file, dec.as_ref()) else {
        return Err(UNREADABLE.to_string());
    };
    let outcome = match file.get_class_def(idx) {
        Ok(class_def) => guarded(|| d.decompile_class(&class_def)),
        Err(e) => Err(Failure::from(e.to_string())),
    };
    outcome.map_err(|f| {
        if f.panicked {
            *dec = (ctx.rebuild)();
        }
        f.message
    })
}

fn process_class<'a>(
    ctx: &Ctx<'a, '_>,
    dec: &mut Option<Decompiler<'a>>,
    (id, idx, class): Job<'_>,
    dir: &Path,
) -> ClassOutcome {
    let dex = ctx.dex;
    let mut errors = Vec::new();
    let (descriptor, rendered) = match class {
        Ok(class) => {
            let descriptor = class.descriptor.to_string();
            let run = AssertUnwindSafe(|| render_class(ctx, dec, idx, &class, Some(id)));
            match catch_unwind(run) {
                Ok(r) => (Some(descriptor), Some(r)),
                Err(p) => {
                    *dec = (ctx.rebuild)();
                    errors.push(BundleError::in_class(
                        "class",
                        &dex.name,
                        Some(id),
                        Some(&descriptor),
                        panic_message(&*p),
                    ));
                    (Some(descriptor), None)
                }
            }
        }
        Err(e) => {
            let descriptor = dex.file.as_ref().and_then(|f| descriptor_of(f, idx));
            errors.push(BundleError::in_class(
                "class",
                &dex.name,
                Some(id),
                descriptor.as_deref(),
                format!("{e:#}"),
            ));
            (descriptor, None)
        }
    };
    let failed = rendered.is_none();
    let Rendered {
        java,
        dasm,
        methods,
        statics,
        errors: render_errors,
    } = rendered.unwrap_or_default();
    errors.extend(render_errors);
    let class_java = whole_class(ctx, dec, idx);
    if let Err(why) = &class_java {
        errors.push(BundleError::in_class(
            "decompile_class",
            &dex.name,
            Some(id),
            descriptor.as_deref(),
            why.clone(),
        ));
    }
    let class_java_body = class_java.as_deref().ok();
    if let Err(e) = write_class_files(dir, id, &java, &dasm, &methods, class_java_body) {
        errors.push(BundleError::in_class(
            "write",
            &dex.name,
            Some(id),
            descriptor.as_deref(),
            format!("{e:#}"),
        ));
    }
    let statuses: Vec<Status> = methods.iter().map(|m| m.decompile_status).collect();
    let decompile_status = if failed {
        Status::Failed
    } else {
        statuses.iter().copied().max().unwrap_or(Status::Ok)
    };
    ClassOutcome {
        entry: ClassEntry {
            id,
            package: descriptor.as_deref().map(package_of),
            origin: descriptor.as_deref().map(origin_of),
            descriptor,
            dex: dex.name.clone(),
            methods: methods.len(),
            rules_direct: Vec::new(),
            rules_path: Vec::new(),
            decompile_status,
            class_java: if class_java.is_ok() {
                ClassJavaStatus::Ok
            } else {
                ClassJavaStatus::Failed
            },
        },
        statuses,
        statics,
        errors,
    }
}

fn render_class<'a>(
    ctx: &Ctx<'a, '_>,
    dec: &mut Option<Decompiler<'a>>,
    idx: u32,
    class: &DexClass<'_>,
    id: Option<usize>,
) -> Rendered {
    let dex = ctx.dex;
    let mut out = Rendered::default();
    let members = match &dex.file {
        Some(file) => encoded_members(file, idx).map_err(|e| format!("{e:#}")),
        None => Err(UNREADABLE.to_string()),
    };
    let encoded = match &members {
        Ok((methods, _)) if aligned(methods, class) => Ok(methods.as_slice()),
        Ok(_) => Err(MISALIGNED.to_string()),
        Err(e) => Err(e.clone()),
    };
    if let Err(e) = &encoded {
        out.errors.push(BundleError::in_class(
            "decompile",
            &dex.name,
            id,
            Some(class.descriptor),
            e.clone(),
        ));
    }

    let java_name = descriptor_to_java(class.descriptor);
    let simple_arg = Some(simple_name(&java_name));
    let class_arg = Some(java_name.as_str());
    let mut java_line = 0usize;
    let mut dasm_methods = Vec::new();
    let mut dasm_slots = Vec::with_capacity(class.methods.len());
    let mut codeless = 0usize;

    for (k, m) in class.methods.iter().enumerate() {
        let signature = format!(
            "{}->{}({}){}",
            class.descriptor,
            m.name,
            m.params.concat(),
            m.return_type
        );
        let enc = encoded.as_ref().ok().map(|e| &e[k]);

        let mut insns_count = None;
        let mut fingerprint = None;
        let mut slot = None;
        match &m.code {
            None => codeless += 1,
            Some(code) => match dex_bytecode::decode_all(code.insns, 0) {
                Ok(instructions) => {
                    let fp = opcode_fingerprint(&instructions);
                    insns_count = Some(instructions.len());
                    fingerprint = Some(format!("{fp:016x}"));
                    slot = Some(dasm_methods.len());
                    dasm_methods.push(MethodDisasm {
                        name: m.name.to_string(),
                        params: m.params.to_vec(),
                        registers_size: code.registers_size,
                        ins_size: code.ins_size,
                        fingerprint: fp,
                        insns: instructions
                            .iter()
                            .map(|ins| Insn {
                                offset: ins.offset as u64,
                                mnemonic: ins.mnemonic().to_string(),
                                operands: ins.operands().to_string(),
                                resolved: disasm::resolve(&dex.bin, ins).map(|o| o.render()),
                            })
                            .collect(),
                    });
                }
                Err(e) => out.errors.push(BundleError::in_class(
                    "disasm",
                    &dex.name,
                    id,
                    Some(&signature),
                    e.to_string(),
                )),
            },
        }
        dasm_slots.push(slot);

        let outcome = match (enc, dec.as_ref()) {
            (Some(enc), Some(d)) => guarded(|| d.decompile_method(enc, simple_arg, class_arg)),
            (Some(_), None) => Err(Failure::from(UNREADABLE.to_string())),
            (None, _) => Err(Failure::from(encoded.clone().err().unwrap_or_default())),
        };
        if matches!(&outcome, Err(f) if f.panicked) {
            *dec = (ctx.rebuild)();
        }

        if k > 0 {
            out.java.push('\n');
            java_line += 1;
        }
        let (status, error, java_lines, markers) = match outcome {
            Ok(text) => {
                let markers = partial_markers(&text);
                let status = if markers.is_empty() {
                    Status::Ok
                } else {
                    Status::Partial
                };
                let n = text.lines().count();
                out.java.push_str(&text);
                if !text.is_empty() && !text.ends_with('\n') {
                    out.java.push('\n');
                }
                let span = if n > 0 {
                    Some([java_line + 1, java_line + n])
                } else {
                    None
                };
                java_line += n;
                (status, None, span, markers)
            }
            Err(f) => {
                let message = f.message;
                let note = format!("    // {signature} : décompilation en échec — {message}");
                out.java.push_str(&note.replace(['\n', '\r'], " "));
                out.java.push('\n');
                java_line += 1;
                if encoded.is_ok() {
                    out.errors.push(BundleError::in_class(
                        "decompile",
                        &dex.name,
                        id,
                        Some(&signature),
                        message.clone(),
                    ));
                }
                (Status::Failed, Some(message), None, Vec::new())
            }
        };

        out.methods.push(MethodRecord {
            signature,
            access: enc.map(|e| e.access_flags),
            code_offset: enc.map(|e| e.code_off),
            insns_count,
            opcode_fingerprint: fingerprint,
            decompile_status: status,
            partial_markers: markers,
            error,
            java_lines,
            dasm_lines: None,
        });
    }

    let sizes: Vec<usize> = dasm_methods.iter().map(|m| m.insns.len()).collect();
    let statics = disasm::static_inits(&dex.bin, class, &[]);
    let header = usize::from(codeless > 0) + statics.len();
    out.dasm = disasm::render(&DisasmReport {
        input: String::new(),
        classes: vec![ClassDisasm {
            descriptor: class.descriptor.to_string(),
            statics,
            methods: dasm_methods,
            codeless,
        }],
        scanned: 0,
    });
    match dasm_spans(&sizes, header, &out.dasm) {
        Some(spans) => {
            for (record, slot) in out.methods.iter_mut().zip(dasm_slots) {
                record.dasm_lines = slot.map(|s| spans[s]);
            }
        }
        None => out.errors.push(BundleError::in_class(
            "disasm",
            &dex.name,
            id,
            Some(class.descriptor),
            DASM_LAYOUT,
        )),
    }

    let field_idx = members.as_ref().map(|(_, fields)| fields.as_slice());
    match dex.bin.static_fields(class) {
        Ok(fields) => {
            for (k, f) in fields.into_iter().enumerate() {
                let Some(value) = f.value else { continue };
                match static_descriptor(dex.file.as_ref(), field_idx, k, &f.name) {
                    Ok(field) => out.statics.push(StaticValue {
                        dex: dex.name.clone(),
                        field,
                        value: value_json(&value),
                    }),
                    Err(e) => out.errors.push(BundleError::in_class(
                        "static_values",
                        &dex.name,
                        id,
                        Some(class.descriptor),
                        e,
                    )),
                }
            }
        }
        Err(e) => out.errors.push(BundleError::in_class(
            "static_values",
            &dex.name,
            id,
            Some(class.descriptor),
            format!("{e:#}"),
        )),
    }
    out
}

fn encoded_members(file: &DexFile, idx: u32) -> Result<(Vec<EncodedMethod>, Vec<u32>)> {
    let class_def = file.get_class_def(idx)?;
    let Some(data) = file.get_class_data(&class_def)? else {
        return Ok((Vec::new(), Vec::new()));
    };
    let methods = data
        .direct_methods
        .iter()
        .chain(&data.virtual_methods)
        .cloned()
        .collect();
    let statics = data.static_fields.iter().map(|f| f.field_idx).collect();
    Ok((methods, statics))
}

fn aligned(encoded: &[EncodedMethod], class: &DexClass<'_>) -> bool {
    encoded.len() == class.methods.len()
        && encoded
            .iter()
            .zip(&class.methods)
            .all(|(e, m)| e.method_idx == m.method_idx)
}

/// Descripteur complet d'un champ statique. L'appariement avec la façade est
/// positionnel (ordre des `static_fields` du `class_data_item`) et contrôlé par
/// le nom.
fn static_descriptor(
    file: Option<&DexFile>,
    fields: Result<&[u32], &String>,
    k: usize,
    name: &str,
) -> Result<String, String> {
    let (Some(file), Ok(fields)) = (file, fields) else {
        return Err(format!(
            "{name} : classe non lue par dex-decompiler, type inconnu"
        ));
    };
    let idx = fields
        .get(k)
        .ok_or_else(|| format!("{name} : absent du class_data de dex-decompiler"))?;
    let info = file
        .get_field_info(*idx)
        .map_err(|e| format!("{name} : {e}"))?;
    if info.name != name {
        let found = info.name;
        return Err(format!(
            "{name} : appariement positionnel incohérent ({found})"
        ));
    }
    Ok(format!("{}->{}:{}", info.class, info.name, info.typ))
}

fn descriptor_of(file: &DexFile, idx: u32) -> Option<String> {
    let class_def = file.get_class_def(idx).ok()?;
    file.get_type(class_def.class_idx).ok()
}

/// Bornes `[en-tête, dernière instruction]` de chaque méthode dans la sortie de
/// `disasm::render` pour une classe. `header` : lignes sous `== … ==` (méthodes
/// sans code, valeurs statiques). `None` si le nombre de lignes rendu ne
/// correspond pas au gabarit — un descripteur portant un saut de ligne suffit.
fn dasm_spans(sizes: &[usize], header: usize, rendered: &str) -> Option<Vec<[usize; 2]>> {
    let mut line = 1 + header;
    let mut spans = Vec::with_capacity(sizes.len());
    for n in sizes {
        spans.push([line + 2, line + 2 + n]);
        line += 2 + n;
    }
    (rendered.lines().count() == line + 1).then_some(spans)
}

/// Marqueurs de repli de dex-decompiler présents dans le Java d'une méthode,
/// dans l'ordre d'apparition, sans doublon. Seuls des marqueurs exacts sont
/// reconnus ; un repli silencieux n'est pas vu.
fn partial_markers(java: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut push = |marker: &str| {
        if !found.iter().any(|f| f == marker) {
            found.push(marker.to_string());
        }
    };
    for line in java.lines() {
        let trimmed = line.trim();
        if is_try_catch_marker(trimmed) {
            push(trimmed);
        }
        let mut rest = line;
        while let Some(pos) = rest.find("/* ") {
            let after = &rest[pos + 3..];
            let Some(end) = after.find(" */") else { break };
            let inner = &after[..end];
            let opcode =
                rest[..pos].ends_with("; ") && dex_bytecode::opcode_for_mnemonic(inner).is_some();
            if opcode || inner.starts_with("fill-array-data ") {
                push(&rest[pos..pos + end + 6]);
            }
            rest = &after[end + 3..];
        }
    }
    found
}

/// `// try/catch (N tries)` et `// try/catch (N tries) - failed to parse
/// handlers`, émis par `wrap_body_with_try_catch` de dex-decompiler.
fn is_try_catch_marker(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("// try/catch (") else {
        return false;
    };
    let Some((count, tail)) = rest.split_once(" tries)") else {
        return false;
    };
    !count.is_empty()
        && count.bytes().all(|b| b.is_ascii_digit())
        && (tail.is_empty() || tail == " - failed to parse handlers")
}

fn write_class_files(
    dir: &Path,
    id: usize,
    java: &str,
    dasm: &str,
    methods: &[MethodRecord],
    class_java: Option<&str>,
) -> Result<()> {
    let json = serde_json::to_string_pretty(methods)?;
    let mut files = vec![("java", java), ("dasm", dasm), ("json", json.as_str())];
    if let Some(body) = class_java {
        files.push(("class.java", body));
    }
    for (ext, body) in files {
        let path = dir.join(format!("{id:06}.{ext}"));
        std::fs::write(&path, body).with_context(|| format!("écriture {}", path.display()))?;
    }
    Ok(())
}

fn value_json(v: &DexValue) -> serde_json::Value {
    use serde_json::{json, Value};
    let (kind, value) = match v {
        DexValue::Byte(n) => ("byte", json!(n)),
        DexValue::Short(n) => ("short", json!(n)),
        DexValue::Char(n) => ("char", json!(n)),
        DexValue::Int(n) => ("int", json!(n)),
        DexValue::Long(n) => ("long", json!(n)),
        DexValue::Float(n) => ("float", json!(n.to_string())),
        DexValue::Double(n) => ("double", json!(n.to_string())),
        DexValue::Bool(b) => ("boolean", json!(b)),
        DexValue::Null => ("null", Value::Null),
        DexValue::Str(s) => ("string", json!(s)),
        DexValue::Type(s) => ("type", json!(s)),
        DexValue::Field(s) => ("field", json!(s)),
        DexValue::Enum(s) => ("enum", json!(s)),
        DexValue::Method(s) => ("method", json!(s)),
        DexValue::Array(vs) => ("array", vs.iter().map(value_json).collect()),
        DexValue::Opaque(what) => ("opaque", json!(what)),
    };
    json!({ "type": kind, "value": value })
}

fn simple_name(java_name: &str) -> &str {
    let simple = java_name.rsplit('.').next().unwrap_or(java_name);
    simple.rsplit_once('$').map_or(simple, |(_, s)| s)
}

fn package_of(descriptor: &str) -> String {
    let inner = descriptor
        .strip_prefix('L')
        .and_then(|d| d.strip_suffix(';'))
        .unwrap_or(descriptor);
    inner
        .rsplit_once('/')
        .map_or_else(String::new, |(pkg, _)| pkg.replace('/', "."))
}

fn origin_of(descriptor: &str) -> Origin {
    if is_application_class(descriptor) {
        Origin::App
    } else {
        Origin::Lib
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn locked_git_rev<'a>(lock: &'a str, package: &str) -> Option<&'a str> {
    let mut current = false;
    for line in lock.lines() {
        if let Some(name) = line.strip_prefix("name = \"") {
            current = name.strip_suffix('"') == Some(package);
            continue;
        }
        if !current {
            continue;
        }
        if let Some(source) = line.strip_prefix("source = \"git+") {
            return source
                .trim_end_matches('"')
                .rsplit_once('#')
                .map(|(_, rev)| rev);
        }
    }
    None
}

/// Légende (`--bundle --legend`, `--decompile --legend`).
pub fn legend() -> String {
    "\
== Bundle (--bundle) et décompilation (--decompile) — légende ==

CE QUE C'EST : pour UN échantillon (APK ou DEX brut, reconnu aux octets de
tête, jamais à l'extension), tout ce que Drakkar sait en extraire, plus chaque
classe et chaque méthode désassemblées et décompilées en Java par
dex-decompiler. Aucun filtre : bibliothèques comprises.

Arborescence : OUT/<sha256 complet de l'entrée>/
  bundle.json          Identité de l'entrée, provenance, statistiques.
  manifest.json        Sortie de --manifest --format json.
  cert.json            Sortie de --cert --format json.
  dating.json          Sortie de --dating --format json.
                       Ces trois-là valent null pour un DEX brut (pas
                       d'archive) ou en cas d'échec, alors consigné dans
                       errors.json.
  rules.json           Sortie du pipeline par défaut (moteur de règles MITRE).
                       null en cas d'échec. Pour un DEX brut, pas de
                       manifeste donc aucun point d'entrée : toute preuve API
                       y est reachable=false.
  strings.json         Pool de chaînes et valeurs statiques (ci-dessous).
  dyn_entrypoints.tsv  Sortie de --dyn-entrypoints, colonnes ci-dessous. En-tête
                       seul si l'extraction échoue.
  index.json           Une entrée par classe.
  errors.json          Tout échec, une entrée chacun. Rien n'est omis en silence.
  classes/<id>.java    Java, méthode par méthode.
  classes/<id>.class.java
                       Java de la classe entière ; absent quand
                       decompile_class échoue.
  classes/<id>.dasm    Désassemblage, format --disasm (--disasm --legend).
  classes/<id>.json    Une entrée par méthode.
Avec --archive, en plus : OUT/<sha256>.bundle.zip, voir Archive plus bas.
Les fichiers de classes/ sont nommés par id, JAMAIS par descripteur : sur un
système de fichiers insensible à la casse (APFS par défaut), les classes
obfusquées La; et LA; s'écraseraient. La correspondance id ↔ descripteur
n'existe que dans index.json.

bundle.json
  schema_version   Entier, vaut 1. Version de la STRUCTURE du bundle : noms et
                   emplacements des fichiers, champs, types et sémantique.
                   Incrémenté à toute modification incompatible : fichier ou
                   champ renommé, déplacé ou retiré, type ou sens d'un champ
                   changé. Un fichier ou un champ AJOUTÉ ne l'incrémente pas :
                   un lecteur ignore ce qu'il ne connaît pas. Absent des
                   bundles écrits avant son introduction.
  sha256           SHA-256 complet du fichier d'entrée.
  input_size       Taille du fichier d'entrée, en octets.
  input_kind       apk (PK\\x03\\x04) | dex (dex\\n).
  dex_files        {name, sha256} par DEX lu, dans l'ordre de l'archive. name :
                   chemin de l'entrée, `/` aplati en `__` ; nom du fichier pour
                   un DEX brut.
  drakkar_version  Version du paquet drakkar.
  decompiler       {crate, rev}. rev = commit complet de dex-decompiler résolu
                   dans le Cargo.lock compilé avec ce binaire ; null s'il n'y
                   figure pas.
  rules_hash       SHA-256 complet (64 hex minuscules) du jeu de règles qui a
                   produit rules.json et du catalogue MITRE dont il vient.
                   Entrée hachée, octet pour octet :
                     `drakkar-rules/1` puis \\n ;
                     le JSON compact de catalog, puis \\n ;
                     pour chaque règle chargée, son JSON compact puis \\n, les
                     règles triées par ordre d'octets de ce JSON.
                   JSON d'une règle : la règle telle que Drakkar l'a lue,
                   {meta: {id, name, tactic, references, authors,
                   detectability, platforms}, features}, champs dans cet
                   ordre ; features est l'arbre lu, variantes nommées comme
                   dans src/rules/schema.rs ({\"And\": […]}, {\"Api\": \"…\"}…).
                   Une clé YAML que Drakkar ignore n'y entre pas, ni le nom
                   ou l'ordre des fichiers du répertoire de règles.
                   catalog : null avec --rules DIR (aucun catalogue chargé) ;
                   sinon {catalog_sha256, stix_sha256} : SHA-256 du source du
                   catalogue de détection compilé dans drakkar
                   (src/rules/catalog.rs), et SHA-256 du STIX MITRE en cache
                   (mobile-attack.json), null s'il en est absent.
                   Une règle ou le catalogue change : le hash change. Mêmes
                   règles et même catalogue : même hash, d'une exécution ou
                   d'une machine à l'autre. null quand rules.json est null
                   (errors.json, stage rules).
  generated_at     Date de génération, ISO 8601 UTC.
  packed           {detected, packer, evidence}. detected :
                     null  = non évalué. ⚠️ Drakkar n'a PAS de détection de
                             packer : en v0 c'est toujours {null, null, []}.
                     false = évalué, aucun packer reconnu.
                     true  = packer reconnu (packer le nomme, evidence dit
                             pourquoi) : classes/ décrit le STUB du packer,
                             pas la charge utile, absente des DEX lus.
  stats            classes = entrées de index.json ; methods = entrées de tous
                   les classes/<id>.json ; decompile_ok / decompile_partial /
                   decompile_failed = décompte des decompile_status par méthode.

index.json — une entrée par classe, dans l'ordre des DEX puis des class_defs
  id               Entier à partir de 0 ; nom des fichiers classes/<id>.*,
                   zéro-padé sur 6 chiffres au moins.
  descriptor       Descripteur Dalvik, ex. Lcom/a/B$1;. null si illisible.
  dex              Le name de dex_files d'où vient la classe. Une classe
                   définie dans deux DEX a deux entrées : rien n'est
                   dédoublonné.
  package          Package Java pointé (com.a) ; vide pour le package par
                   défaut ; null si le descripteur est illisible.
  origin           app | lib. lib = le descripteur commence par un préfixe de
                   la liste d'exclusion de --diff-matrix (Landroid/,
                   Landroidx/, Ljava/, Lkotlin/, Lokhttp3/, Lcom/google/…).
                   ⚠️ Liste SUR-INCLUSIVE côté app : une bibliothèque non
                   listée, ou renommée par ProGuard (a/b/c), sort en app. app
                   ne veut pas dire « écrit par l'auteur de l'échantillon ».
  methods          Nombre d'entrées de classes/<id>.json. 0 quand la classe
                   entière a échoué (voir errors.json, stage class).
  rules_direct     Identifiants des règles de rules.json dont une preuve cite
                   la classe directement : son descripteur complet figure
                   dans evidence.value, ou elle est le propriétaire de
                   l'APPELANT IMMÉDIAT de l'API dans un chemin (avant-dernier
                   nœud de evidence.paths ; le dernier nœud est l'API
                   elle-même).
  rules_path       Règles dont la classe n'apparaît qu'ailleurs dans un
                   chemin, comme propriétaire d'un nœud traversé. Une règle
                   n'est jamais dans les deux listes pour une même classe.
                   ⚠️ Un chemin part d'un point d'entrée (Application,
                   activités, receivers…) ou du pivot d'une règle
                   co-reachable / intimacy : rules_path cite toutes les
                   classes traversées, il ne sert pas à prioriser.
  decompile_status Pire statut parmi ses méthodes (failed > partial > ok).
                   failed si la classe entière a échoué ; ok si elle n'a
                   aucune méthode.
  class_java       ok | failed : issue de decompile_class, donc présence ou
                   absence de classes/<id>.class.java. Indépendant de
                   decompile_status.

classes/<id>.json — une entrée par méthode : direct puis virtual, ordre du DEX
  signature        Lowner;->nom(params)retour, types exacts.
  access           access_flags de l'encoded_method, en entier.
  code_offset      Offset du code_item dans le DEX ; 0 sans code.
                   access et code_offset valent null quand dex-decompiler n'a
                   pas lu la classe.
  insns_count      Nombre d'instructions Dalvik décodées. null sans code
                   (abstraite, native) ou si le décodage échoue.
  opcode_fingerprint
                   Empreinte d'opcodes, calcul de --diff-dex (hachage des
                   mnémoniques seuls), 16 chiffres hexadécimaux. null : idem
                   insns_count. ⚠️ DefaultHasher : stable pour un même binaire
                   seulement. Comparer deux bundles produits par le MÊME
                   drakkar ; ne jamais la publier comme IOC.
  decompile_status ok | partial | failed, voir plus bas.
  partial_markers  Marqueurs de repli trouvés dans le Java de la méthode,
                   texte exact, sans doublon ; vide sauf pour partial.
  error            Message de l'échec quand failed, null sinon.
  java_lines       [début, fin] dans classes/<id>.java, lignes numérotées à
                   partir de 1, bornes incluses. null si failed ou si le
                   décompilateur n'a rien rendu.
  dasm_lines       [début, fin] dans classes/<id>.dasm : ligne d'en-tête de la
                   méthode, puis ses instructions. null sans code, si le
                   décodage échoue, ou si le .dasm ne suit pas le gabarit de
                   --disasm (errors.json, stage disasm).

decompile_status
  ok       decompile_method de dex-decompiler a rendu du Java sans erreur et
           sans aucun des marqueurs ci-dessous, ou une simple signature pour
           une méthode sans code. ⚠️ Ne garantit PAS la fidélité : certains
           replis ne laissent aucune trace (listage linéaire quand le CFG est
           vide, try/catch reconstruit au jugé).
  partial  Java produit, mais le décompilateur y a laissé au moins un
           marqueur de repli de la liste suivante, recopié dans
           partial_markers. Détection HEURISTIQUE, limitée à ces marqueurs
           exacts :
             `; /* <mnémonique> */`  instruction non traduite, mnémonique
                                     Dalvik reconnu par dex-bytecode, ex.
                                     `; /* move-exception */` ;
             `/* fill-array-data …`  payload de fill-array-data non lu ;
             `// try/catch (N tries) - failed to parse handlers`
                                     handlers du try non parsés ;
             `// try/catch (N tries)`
                                     try présent, aucun handler apparié :
                                     corps émis sans try/catch.
           Un littéral de chaîne qui contiendrait l'un de ces textes serait
           pris pour un marqueur.
  failed   decompile_method a rendu une erreur ou a paniqué, ou
           dex-decompiler n'a pas pu lire le DEX ou la classe. Le message est
           dans error et dans errors.json.

classes/<id>.java
  Chaque méthode décompilée ISOLÉMENT (decompile_method), séparées par une
  ligne vide. Pas d'en-tête de classe, de champs, d'imports ni de classes
  internes : decompile_class ne donne pas les bornes de chaque méthode et
  s'arrête à la première qui échoue. Sans ce contexte de classe, les accès
  synthétiques (access$000) et les littéraux de constantes de champ ne sont
  pas réécrits. Une méthode failed y laisse une ligne de commentaire écrite par
  Drakkar, pas par le décompilateur. C'est ce fichier que désignent java_lines.

classes/<id>.class.java
  Java de la classe entière par decompile_class : en-tête, imports, champs,
  constantes static final, classes internes nommées, accès synthétiques
  réécrits. AUCUNE correspondance ligne à ligne avec classes/<id>.json. Absent
  quand decompile_class échoue — il s'arrête à la première méthode en erreur ;
  la raison est dans errors.json, stage decompile_class.

classes/<id>.dasm
  Rendu de --disasm pour la classe seule, valeurs statiques comprises sous
  l'en-tête. Une méthode dont le code ne se décode pas n'y figure pas.

strings.json
  pool             Une entrée par DEX : {dex, declared, unreadable, strings}.
                   Pool complet, lu par le parseur de --strings. declared =
                   taille annoncée par l'en-tête ; unreadable = entrées
                   illisibles, absentes de strings.
  static_values    {dex, field, value} pour chaque champ statique auquel
                   l'encoded_static_values du class_def donne une valeur.
                   Toutes les valeurs du tableau sont émises, final ou non ;
                   un champ que le tableau ne couvre pas est absent. C'est là
                   que vivent les constantes de compilation (static final
                   String), invisibles aux instructions — endpoints C2 compris.
    field          Lowner;->nom:Ltype;
    value          {type, value}. type : byte, short, int, long (value
                   entière) ; char (unité UTF-16, entière) ; float, double
                   (texte décimal, aller-retour exact, NaN et inf compris) ;
                   boolean ; null ; string ; type (descripteur) ; field et
                   enum (Lowner;->nom:Ltype;) ; method (Lowner;->nom) ; array
                   (value = liste de {type, value}) ; opaque (method-type,
                   method-handle, annotation, ou index de pool non résolu).

dyn_entrypoints.tsv — colonnes de --dyn-entrypoints
  sample    SHA-256 complet de l'entrée (le nom du fichier pour
            --dyn-entrypoints seul).
  origine   D'où vient la classe atteinte : new (new-instance, exact) ; class
            (const-class, exact) ; string (const-string, nom de classe
            textuel) ; field~ (type DÉCLARÉ d'un champ, borne supérieure :
            peut être une super-classe ou une interface) ; field= (classe
            concrète assignée au champ, exact) ; this (la méthode s'enregistre
            elle-même) ; xml (android:onClick d'un layout). ? : sink non résolu.
  classe    Descripteur de la classe atteinte ; vide si non résolu.
  sink      Méthode par laquelle elle est atteinte (registerReceiver,
            startActivity, <init> d'Intent, forName…).
  offset    +offset du call site dans l'appelant, en décimal, même unité que
            la colonne offset de --disasm.
  appelant  Lowner;->nom de la méthode qui porte le call site.
  detail    Non résolus seulement : raison (param-or-this, field, call-result,
            other, no-strategy), registre visé (vN, ou -), mnémonique de
            l'instruction qui bloque la remontée (ou -).

errors.json — {stage, dex, class_id, target, error}
  stage    dex : DEX illisible par la façade, aucune de ses classes au bundle ;
           class : classe illisible, ou panique sur la classe ;
           decompile : dex-decompiler a refusé le DEX, la classe ou la méthode ;
           decompile_class : decompile_class a échoué, pas de .class.java ;
           disasm : décodage d'une méthode, ou .dasm hors gabarit ;
           static_values : valeur statique non attribuable à un champ ;
           write : écriture d'un fichier de classes/ ;
           manifest, cert, dating, rules, strings, dyn_entrypoints : la partie
           du même nom.
  dex      Le name de dex_files concerné, null s'il n'y en a pas.
  class_id L'id de index.json concerné, null s'il n'y en a pas.
  target   Descripteur de classe ou signature de méthode, null sinon.

Archive (--archive) — OUT/<sha256>.bundle.zip, écrite après le répertoire
  Contenu        Tous les fichiers de OUT/<sha256>/, chacun sous le préfixe
                 `<sha256>/` : <sha256>/bundle.json, <sha256>/index.json…,
                 <sha256>/classes/000000.java… Fichiers réguliers seulement,
                 aucune entrée de répertoire ; un lien symbolique ou tout
                 autre fichier non régulier fait échouer l'archive.
  Déterminisme   Entrées triées par chemin, ordre d'octets. Horodatage fixe
                 1980-01-01 00:00:00, permissions fixes 0644, aucun champ
                 extra (ni uid/gid, ni temps étendus), compression deflate
                 niveau 6.
  Garantie       Même contenu de répertoire → mêmes octets, donc même
                 SHA-256, quels que soient les dates, propriétaires et modes
                 des fichiers sur disque, à binaire drakkar égal (le
                 compresseur deflate est celui compilé dedans). ⚠️ Pas
                 « même entrée → même archive » : generated_at, dans
                 bundle.json, change à chaque exécution, donc deux bundles
                 d'une même entrée et leurs archives diffèrent. Pour savoir si
                 deux bundles décrivent la même chose, comparer sha256,
                 rules_hash et le contenu, pas l'archive.
  Écriture       Fichier temporaire caché dans OUT, renommé en
                 <sha256>.bundle.zip une fois complet : l'archive est entière
                 ou absente. Existante : refus sans --overwrite, comme le
                 répertoire, avant toute écriture. Avec --overwrite, une
                 archive existante est remplacée avec --archive, supprimée
                 sans, en même temps que le répertoire : elle ne survit
                 jamais à la régénération du bundle.

Rapport de --bundle, sur stdout
  text (défaut)  Une ligne clé<TAB>valeur : bundle_dir, puis avec --archive
                 archive_path, archive_size, archive_sha256.
  json           --format json : {bundle_dir, stats, errors, archive} ;
                 stats comme dans bundle.json, errors = nombre d'entrées de
                 errors.json, archive = {path, size, sha256}, null sans
                 --archive. --json-out FILE l'écrit dans FILE.
  archive_size (size) est en octets ; archive_sha256 (sha256) est le SHA-256
  complet du .bundle.zip. La ligne [OK] de stderr ne change pas.

--decompile <MOTIF>
  Même sélection que --disasm : sous-chaîne du descripteur Dalvik, insensible
  à la casse, répétable ; sans motif, toutes les classes. Chaque classe sort
  précédée de `// == <descripteur> — <dex> ==`, puis d'une ligne
  `// static <nom> : <type> = <valeur>` par champ statique doté d'une valeur
  initiale dans l'encoded_array de static_values_off, lue par Drakkar et rendue
  comme dans --disasm (--disasm --legend, En-tête de classe) : présentes même
  quand le décompilateur omet l'initialiseur ou que la classe passe en repli
  méthode par méthode, qui n'a pas de champs. Puis le Java de classe entière
  (decompile_class). Si decompile_class échoue, une ligne
  `// repli méthode par méthode — decompile_class : <raison>` précède le rendu
  de classes/<id>.java. Une classe interne nommée (A$B) sort aussi dans le Java
  de A.\
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(name: &str, insns: usize) -> MethodDisasm {
        MethodDisasm {
            name: name.to_string(),
            params: vec!["I".to_string()],
            registers_size: 2,
            ins_size: 1,
            fingerprint: 0,
            insns: (0..insns)
                .map(|i| Insn {
                    offset: i as u64,
                    mnemonic: "nop".to_string(),
                    operands: String::new(),
                    resolved: None,
                })
                .collect(),
        }
    }

    #[test]
    fn bornes_dasm_suivent_le_rendu_de_disasm() {
        let rendered = disasm::render(&DisasmReport {
            input: String::new(),
            classes: vec![ClassDisasm {
                descriptor: "La;".to_string(),
                statics: Vec::new(),
                methods: vec![method("a", 2), method("b", 0), method("c", 3)],
                codeless: 1,
            }],
            scanned: 0,
        });
        let spans = dasm_spans(&[2, 0, 3], 1, &rendered).expect("gabarit respecté");
        let lines: Vec<&str> = rendered.lines().collect();
        for (span, name) in spans.iter().zip(["a", "b", "c"]) {
            assert!(lines[span[0] - 1].starts_with(&format!("  {name}(")));
        }
        assert_eq!(spans[0], [4, 6]);
        assert_eq!(spans[1], [8, 8]);
        assert_eq!(spans[2], [10, 13]);
        assert!(lines[spans[2][1] - 1].starts_with("    0002"));
    }

    #[test]
    fn bornes_dasm_comptent_les_valeurs_statiques() {
        let statics = vec![
            disasm::StaticInit {
                name: "a".into(),
                typ: "Ljava/lang/String;".into(),
                value: "\"x\"".into(),
            },
            disasm::StaticInit {
                name: "b".into(),
                typ: "I".into(),
                value: "1".into(),
            },
        ];
        let rendered = disasm::render(&DisasmReport {
            input: String::new(),
            classes: vec![ClassDisasm {
                descriptor: "La;".to_string(),
                statics,
                methods: vec![method("m", 1)],
                codeless: 1,
            }],
            scanned: 0,
        });
        let spans = dasm_spans(&[1], 3, &rendered).expect("gabarit respecté");
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[spans[0][0] - 1].starts_with("  m("));
        assert!(dasm_spans(&[1], 1, &rendered).is_none());
    }

    #[test]
    fn decompile_rend_les_valeurs_statiques_en_commentaire() {
        let report = DecompileReport {
            classes: vec![ClassJava {
                descriptor: "Lalxu/taw/ce/dw6cyh;".into(),
                dex: "classes.dex".into(),
                statics: vec![disasm::StaticInit {
                    name: "a".into(),
                    typ: "Ljava/lang/String;".into(),
                    value: "\"93hjbo029kfjsv79emkcxsfqu80kr5wb\"".into(),
                }],
                java: "class dw6cyh {}\n".into(),
                fallback: None,
            }],
            scanned: 1,
        };
        let lines: Vec<String> = render(&report).lines().map(str::to_string).collect();
        assert_eq!(
            lines[1],
            "// static a : Ljava/lang/String; = \"93hjbo029kfjsv79emkcxsfqu80kr5wb\""
        );
        assert_eq!(lines[2], "class dw6cyh {}");
    }

    #[test]
    fn bornes_dasm_refusees_hors_gabarit() {
        assert!(dasm_spans(&[1], 0, "== La; ==\n\n").is_none());
    }

    #[test]
    fn package_pointe_depuis_le_descripteur() {
        assert_eq!(package_of("Lcom/a/B$1;"), "com.a");
        assert_eq!(package_of("LB;"), "");
    }

    #[test]
    fn nom_simple_de_classe_interne() {
        assert_eq!(simple_name("com.a.B$Inner"), "Inner");
        assert_eq!(simple_name("B"), "B");
    }

    #[test]
    fn rev_complet_lu_dans_le_lock() {
        let lock = r#"[[package]]
name = "dex-bytecode"
version = "0.0.1"
source = "git+https://github.com/androguard/dex-bytecode#847090298e79c22b0572fca82b1ee5316d6ee57e"

[[package]]
name = "dex-decompiler"
version = "0.1.0"
source = "git+https://github.com/androguard/dex-decompiler?rev=f7fa4a4853d957ebc3c54355d128a3835ef5ae22#f7fa4a4853d957ebc3c54355d128a3835ef5ae22"
"#;
        assert_eq!(
            locked_git_rev(lock, "dex-decompiler"),
            Some("f7fa4a4853d957ebc3c54355d128a3835ef5ae22")
        );
        assert_eq!(locked_git_rev(lock, "absent"), None);
    }

    #[test]
    fn flottants_en_texte_exact() {
        assert_eq!(
            value_json(&DexValue::Float(0.1)),
            serde_json::json!({ "type": "float", "value": "0.1" })
        );
        assert_eq!(
            value_json(&DexValue::Double(f64::NAN)),
            serde_json::json!({ "type": "double", "value": "NaN" })
        );
    }

    #[test]
    fn marqueurs_partial_exacts_seulement() {
        let java = "    public void f() {
        // try/catch (2 tries) - failed to parse handlers
        v3; /* move-exception */
        v3; /* move-exception */
        /* fill-array-data v0, +12 */
        Object x = /* Unit */ null;
        int y = 1; /* compteur */
    }
";
        assert_eq!(
            partial_markers(java),
            [
                "// try/catch (2 tries) - failed to parse handlers",
                "/* move-exception */",
                "/* fill-array-data v0, +12 */",
            ]
        );
        assert_eq!(
            partial_markers("        // try/catch (3 tries)\n"),
            ["// try/catch (3 tries)"]
        );
        assert!(partial_markers("        // try/catch (x tries)\n").is_empty());
        assert!(partial_markers("        return v0;\n").is_empty());
    }

    /// Un DEX reconnu au magic ; `open` ne le parse pas.
    fn dex_brut(dir: &Path) -> PathBuf {
        let path = dir.join("classes.dex");
        std::fs::write(&path, b"dex\n035\0").unwrap();
        path
    }

    #[test]
    fn bundle_json_porte_schema_version_et_taille_de_l_entree() {
        let tmp = tempfile::tempdir().unwrap();
        let path = dex_brut(tmp.path());
        let input = open(&path).unwrap();
        let stats = Stats::default();
        let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let info = BundleInfo::new(&input, &stats, String::new(), Some(hash.into()));
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["input_size"], std::fs::metadata(&path).unwrap().len());
        assert_eq!(json["rules_hash"], hash);

        let info = BundleInfo::new(&input, &stats, String::new(), None);
        assert!(serde_json::to_value(&info).unwrap()["rules_hash"].is_null());
    }

    #[test]
    fn statut_le_plus_grave_l_emporte() {
        assert_eq!(
            [Status::Ok, Status::Failed, Status::Partial].iter().max(),
            Some(&Status::Failed)
        );
    }
}
