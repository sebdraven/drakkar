use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use drakkar::{bulk, export, parser, rules::Engine};
use std::path::PathBuf;

/// Rendu des sorties d'inventaire (`--manifest`, `--cert`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Tableau lisible, sur stdout. Rien d'autre n'est émis. Mode single.
    Text,
    /// Single : JSON seul sur stdout, pipeable vers `jq`.
    /// Bulk : un fichier `<stem>.<kind>.json` par APK dans --out.
    Json,
    /// Single : tableau sur stdout + JSON dans `--json-out` (requis).
    Both,
    /// Bulk uniquement : un seul CSV pour tout le lot dans --out, une ligne par
    /// échantillon. Vue de synthèse — les structures imbriquées sont réduites à
    /// des compteurs.
    Csv,
}

impl Format {
    fn wants_text(self) -> bool {
        matches!(self, Format::Text | Format::Both)
    }
    fn wants_json(self) -> bool {
        matches!(self, Format::Json | Format::Both)
    }
    /// Traduction vers la forme de sortie du mode bulk : seul `csv` s'y
    /// distingue, tout le reste produit un fichier JSON par APK.
    fn to_bulk(self) -> bulk::BulkFormat {
        match self {
            Format::Csv => bulk::BulkFormat::Csv,
            _ => bulk::BulkFormat::Json,
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "drakkar", version, about = "MITRE ATT&CK for Mobile detection on APKs")]
struct Cli {
    /// APK à analyser (mode single). Omettre si --bulk est utilisé.
    apk: Option<PathBuf>,

    /// Mode bulk : analyse tous les .apk d'un répertoire (un <stem>.json par APK).
    #[arg(long, value_name = "DIR", conflicts_with = "apk")]
    bulk: Option<PathBuf>,

    /// Répertoire de sortie en mode bulk. La valeur `-` écrit tout sur stdout
    /// au lieu de créer des fichiers.
    #[arg(long, value_name = "DIR", default_value = "./reports")]
    out: PathBuf,

    /// Parcours récursif des sous-répertoires (mode bulk).
    #[arg(long)]
    recursive: bool,

    /// Ré-analyse même si le JSON de sortie existe déjà (mode bulk).
    #[arg(long)]
    overwrite: bool,

    /// Threads rayon en mode bulk (0 = auto, tous les cœurs).
    #[arg(short = 'j', long, default_value_t = 0)]
    jobs: usize,

    /// Répertoire de règles à utiliser à la place du cache auto-généré (override).
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Force le re-téléchargement du catalogue MITRE et la régénération du cache.
    #[arg(long)]
    refresh: bool,

    /// Export du CFG en NetworkX node-link JSON (mode single uniquement).
    #[arg(long)]
    export_graph: Option<PathBuf>,

    /// Audit d'architecture native seul (ABI/bits/machine des .so) puis sort,
    /// sans exécuter le pipeline complet ni charger le catalogue (mode single).
    #[arg(long)]
    native_arch: bool,

    /// Extrait toutes les bibliothèques natives (.so ELF) de l'APK — y compris
    /// hors lib/ (assets/libjiagu*.so des packers) — vers --out, puis sort
    /// (mode single). N'exécute pas le pipeline complet.
    #[arg(long)]
    extract_libs: bool,

    /// Inventaire complet du AndroidManifest.xml (permissions, composants,
    /// intent-filters, points d'entrée dérivés) puis sort. Fonctionne en single
    /// (APK en argument) comme en bulk (--bulk DIR).
    #[arg(long, conflicts_with = "cert")]
    manifest: bool,

    /// Inventaire de la signature : schémas v1/v2/v3/v3.1 et certificats X.509
    /// (DN, validité, empreintes) puis sort. Single ou bulk.
    #[arg(long)]
    cert: bool,

    /// Rendu des sorties --manifest / --cert.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Fichier de sortie du JSON (--format json | both). Sans lui, `json` écrit
    /// sur stdout ; `both` l'exige pour ne jamais mélanger les deux flux.
    #[arg(long, value_name = "FILE")]
    json_out: Option<PathBuf>,

    /// Affiche la légende des étiquettes et règles de dérivation, puis sort.
    /// Se combine avec --manifest ou --cert.
    #[arg(long)]
    legend: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        // Les journaux vont sur stderr : stdout est réservé aux données (JSON,
        // CSV, tableaux), pour que `| jq` et `> fichier` restent propres.
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Sortie rapide : audit d'architecture native seul (pas de moteur de règles,
    // pas de catalogue MITRE) — lit uniquement les en-têtes ELF, en mémoire.
    if cli.native_arch {
        let Some(apk) = &cli.apk else {
            bail!("--native-arch requiert un APK (mode single)");
        };
        let summary = parser::native_arch::scan_apk_file(apk)?;
        print_native_arch(&summary);
        return Ok(());
    }

    // Sortie rapide : légende seule (aucun APK requis).
    if cli.legend {
        if cli.cert {
            println!("{}", parser::cert::legend());
        } else {
            println!("{}", parser::manifest_info::legend());
        }
        return Ok(());
    }

    // Sortie rapide : inventaires manifest / signature. Aucun DEX n'est parsé,
    // le catalogue MITRE n'est pas chargé. Single (APK) ou bulk (--bulk DIR).
    if cli.manifest || cli.cert {
        let what = if cli.manifest {
            bulk::Inventory::Manifest
        } else {
            bulk::Inventory::Cert
        };

        match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => {
                if cli.format == Format::Csv {
                    bail!("--format csv n'existe qu'en mode bulk (--bulk <DIR>)");
                }
                check_json_dest(cli.format, cli.json_out.as_deref())?;
                match what {
                    bulk::Inventory::Manifest => {
                        let report = parser::manifest_info::extract(apk)?;
                        if cli.format.wants_text() {
                            print_manifest(&report);
                        }
                        if cli.format.wants_json() {
                            emit_json(&report, cli.json_out.as_deref())?;
                        }
                    }
                    bulk::Inventory::Cert => {
                        let report = parser::cert::extract(apk)?;
                        if cli.format.wants_text() {
                            print_cert(&report);
                        }
                        if cli.format.wants_json() {
                            emit_json(&report, cli.json_out.as_deref())?;
                        }
                    }
                }
            }
            (None, Some(dir)) => {
                setup_jobs(cli.jobs)?;
                bulk::run_inventory(dir, what, &bulk_options(&cli))?;
            }
            _ => bail!("fournis un APK (single) ou --bulk <DIR> (répertoire)"),
        }
        return Ok(());
    }

    // Sortie rapide : extraction des .so natifs (lib/ ET hors-lib, ex. Jiagu
    // assets/libjiagu*.so) vers --out. Pas de moteur de règles ni de catalogue.
    if cli.extract_libs {
        let Some(apk) = &cli.apk else {
            bail!("--extract-libs requiert un APK (mode single)");
        };
        let extraction = parser::native_extract::extract_apk_file(apk)?;
        print_and_dump_extract(&extraction, &cli.out)?;
        return Ok(());
    }

    // Moteur de règles : chargé une seule fois, réutilisé en single comme en bulk.
    let engine = match &cli.rules {
        Some(dir) => Engine::load(dir)?,
        None => Engine::load_cached(cli.refresh)?,
    };

    match (&cli.apk, &cli.bulk) {
        // ── Mode bulk : répertoire d'APK, parallèle ──
        (None, Some(dir)) => {
            if cli.jobs > 0 {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(cli.jobs)
                    .build_global()?;
            }
            let opts = bulk::BulkOptions {
                out_dir: cli.out.clone(),
                recursive: cli.recursive,
                overwrite: cli.overwrite,
            };
            bulk::run(dir, &engine, &opts)?;
        }

        // ── Mode single : comportement historique inchangé ──
        (Some(apk), None) => {
            let parsed = parser::parse_apk(apk)?;
            let matches = engine.run(&parsed.features, &parsed.call_graph);

            if let Some(out) = &cli.export_graph {
                export::networkx::write(&parsed.call_graph, out)?;
            }

            println!("{}", serde_json::to_string_pretty(&matches)?);
        }

        (None, None) => bail!("fournis un APK (mode single) ou --bulk <DIR> (mode répertoire)"),
        // clap (conflicts_with) empêche déjà ce cas.
        (Some(_), Some(_)) => unreachable!("apk et --bulk sont mutuellement exclusifs"),
    }

    Ok(())
}

/// Affiche l'audit d'architecture native (mode `--native-arch`).
fn print_native_arch(s: &drakkar::parser::native_arch::NativeArchSummary) {
    use drakkar::parser::native_arch::Bits;

    println!("== Architecture native ==\n");
    println!("{}\n", drakkar::parser::native_arch::legend());

    if s.libs.is_empty() {
        println!("Aucune bibliothèque native (lib/*/*.so).");
        return;
    }

    println!("Libs :");
    for l in &s.libs {
        let bits = if l.bits == Bits::B64 { "64-bit" } else { "32-bit" };
        let flag = if l.abi_mismatch { "  ⚠ MISMATCH" } else { "" };
        println!("  {:<40} {:<8} {}{}", l.entry, l.machine.label(), bits, flag);
    }

    println!("\nABIs : {}   (fat: {})", s.abis.join(", "), s.is_fat);

    println!("\nConventions d'appel (SE) :");
    for c in &s.calling_conventions {
        println!("  - {c}");
    }

    if !s.anomalies.is_empty() {
        println!("\nAnomalies :");
        for a in &s.anomalies {
            println!("  - {a}");
        }
    }
}

/// Extrait les .so natifs vers `out_dir` et affiche le récap (mode `--extract-libs`).
fn print_and_dump_extract(
    ex: &drakkar::parser::native_extract::NativeExtraction,
    out_dir: &std::path::Path,
) -> Result<()> {
    use drakkar::parser::native_arch::Bits;

    println!("== Extraction des bibliothèques natives ==\n");
    println!("{}\n", drakkar::parser::native_extract::legend());

    if ex.is_empty() {
        println!("Aucune bibliothèque native (.so ELF) dans l'APK.");
        if !ex.skipped_non_elf.is_empty() {
            println!(
                "Entrées .so non-ELF ignorées : {}",
                ex.skipped_non_elf.join(", ")
            );
        }
        return Ok(());
    }

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("création {}", out_dir.display()))?;

    println!("Libs extraites ({}) -> {} :", ex.count(), out_dir.display());
    for l in &ex.libs {
        let bits = if l.arch.bits == Bits::B64 { "64-bit" } else { "32-bit" };
        let flag = if l.out_of_lib() { "  ⚠ HORS lib/ (packer)" } else { "" };
        // nom de sortie aplati : lib/arm64-v8a/foo.so -> lib__arm64-v8a__foo.so
        let flat = l.entry.replace('/', "__");
        let dest = out_dir.join(&flat);
        std::fs::write(&dest, &l.bytes)
            .with_context(|| format!("écriture {}", dest.display()))?;
        println!(
            "  {:<38} {:<8} {:<7} {:>9} o  -> {}{}",
            l.entry,
            l.arch.machine.label(),
            bits,
            l.bytes.len(),
            flat,
            flag
        );
    }

    if !ex.skipped_non_elf.is_empty() {
        println!("\n.so non-ELF ignorés ({}) :", ex.skipped_non_elf.len());
        for s in &ex.skipped_non_elf {
            println!("  {s}");
        }
    }

    Ok(())
}

/// Dimensionne le pool rayon global (0 = auto, tous les cœurs).
fn setup_jobs(jobs: usize) -> Result<()> {
    if jobs > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()?;
    }
    Ok(())
}

/// Options de traitement par lot, communes au pipeline complet et aux inventaires.
fn bulk_options(cli: &Cli) -> bulk::BulkOptions {
    bulk::BulkOptions {
        out_dir: cli.out.clone(),
        recursive: cli.recursive,
        overwrite: cli.overwrite,
        format: cli.format.to_bulk(),
    }
}

/// `--format both` exige une destination fichier : sinon les deux flux se
/// retrouveraient mélangés sur stdout.
fn check_json_dest(format: Format, dest: Option<&std::path::Path>) -> Result<()> {
    if format == Format::Both && dest.is_none() {
        bail!("--format both requiert --json-out <FILE> (le tableau va sur stdout)");
    }
    Ok(())
}

/// Sérialise un rapport en JSON : vers `dest` si fourni, sinon sur stdout.
fn emit_json<T: serde::Serialize>(report: &T, dest: Option<&std::path::Path>) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    match dest {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("création {}", parent.display()))?;
                }
            }
            std::fs::write(path, json)
                .with_context(|| format!("écriture {}", path.display()))?;
            eprintln!("JSON écrit dans {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// Rendu console de l'inventaire du manifest (mode `--manifest`).
fn print_manifest(r: &drakkar::parser::manifest_info::ManifestReport) {
    println!("== Manifest ==\n");

    println!("Identité :");
    println!("  package        {}", r.package);
    println!(
        "  version        {} (code {})",
        r.version_name.as_deref().unwrap_or("?"),
        r.version_code.as_deref().unwrap_or("?")
    );
    println!(
        "  sdk            min={} target={} compile={}",
        opt_num(r.sdk.min_sdk),
        opt_num(r.sdk.target_sdk),
        opt_num(r.sdk.compile_sdk)
    );
    if let Some(uid) = &r.shared_user_id {
        println!("  sharedUserId   {uid}");
    }

    println!("\nApplication :");
    println!(
        "  name                   {}",
        r.application.name.as_deref().unwrap_or("(par défaut)")
    );
    if let Some(f) = &r.application.app_component_factory {
        println!("  appComponentFactory    {f}");
    }
    println!(
        "  allowBackup={}  debuggable={}  cleartext={}  hasCode={}  extractNativeLibs={}",
        opt_bool(r.application.allow_backup),
        opt_bool(r.application.debuggable),
        opt_bool(r.application.uses_cleartext_traffic),
        opt_bool(r.application.has_code),
        opt_bool(r.application.extract_native_libs)
    );

    println!(
        "\nPermissions requises ({}) :",
        r.uses_permissions.len()
    );
    for p in &r.uses_permissions {
        let mut notes = Vec::new();
        if p.sdk23_only {
            notes.push("sdk23+".to_string());
        }
        if let Some(m) = p.max_sdk_version {
            notes.push(format!("maxSdk={m}"));
        }
        let suffix = if notes.is_empty() {
            String::new()
        } else {
            format!("  [{}]", notes.join(", "))
        };
        println!("  {}{}", p.name, suffix);
    }

    if !r.declared_permissions.is_empty() {
        println!(
            "\nPermissions définies par l'app ({}) :",
            r.declared_permissions.len()
        );
        for p in &r.declared_permissions {
            println!(
                "  {:<60} {}",
                p.name,
                p.protection_level.as_deref().unwrap_or("normal")
            );
        }
    }

    println!("\nComposants ({}) :", r.components.total());
    println!(
        "  activities={}  aliases={}  services={}  receivers={}  providers={}",
        r.components.activities.len(),
        r.components.activity_aliases.len(),
        r.components.services.len(),
        r.components.receivers.len(),
        r.components.providers.len()
    );
    println!(
        "\n  {:<16} {:<58} {:<9} {}",
        "TYPE", "CLASSE", "EXPORTED", "PERMISSION"
    );
    for c in r.components.iter_all() {
        let exported = match (c.exported_declared, c.exported_effective) {
            (Some(true), _) => "oui",
            (Some(false), _) => "non",
            (None, true) => "oui*",
            (None, false) => "non*",
        };
        println!(
            "  {:<16} {:<58} {:<9} {}",
            c.kind.label(),
            truncate(&c.name, 58),
            exported,
            c.permission.as_deref().unwrap_or("-")
        );
    }
    println!("  (* valeur déduite : android:exported absent du manifest)");

    println!("\nPoints d'entrée ({}) :", r.entrypoints.len());
    if r.entrypoints.is_empty() {
        println!("  aucun");
    }
    for e in &r.entrypoints {
        println!(
            "  {:<24} {:<52} {}",
            e.trigger.label(),
            truncate(&e.component, 52),
            e.detail
        );
    }

    if !r.anomalies.is_empty() {
        println!("\nObservations ({}) :", r.anomalies.len());
        for a in &r.anomalies {
            println!("  - {a}");
        }
    }

    println!("\n(légende des étiquettes : --manifest --legend)");
}

/// Rendu console de l'inventaire de signature (mode `--cert`).
fn print_cert(r: &drakkar::parser::cert::SigningReport) {
    use drakkar::parser::cert::hex_colons;

    println!("== Signature ==\n");

    let schemes = r.schemes.labels();
    println!(
        "Schémas détectés : {}",
        if schemes.is_empty() {
            "aucun".to_string()
        } else {
            schemes.join(", ")
        }
    );
    if !r.v1_signature_files.is_empty() {
        println!("Fichiers v1      : {}", r.v1_signature_files.join(", "));
    }
    if !r.signing_block_ids.is_empty() {
        println!("Blocs de signature : {}", r.signing_block_ids.join(", "));
    }

    println!("\nCertificats ({}) :", r.certificates.len());
    for (i, c) in r.certificates.iter().enumerate() {
        let sources: Vec<String> = c.sources.iter().map(|s| s.label()).collect();
        println!("\n  [{}] sources : {}", i + 1, sources.join(", "));
        println!("      subject      {}", c.subject);
        println!(
            "      issuer       {}{}",
            c.issuer,
            if c.self_signed { "  (auto-signé)" } else { "" }
        );
        println!("      serial       {}", c.serial);
        println!(
            "      validité     {} -> {}  ({:.1} ans)",
            c.not_before, c.not_after, c.validity_years
        );
        println!("      signature    {}", c.signature_algorithm);
        println!(
            "      clé publique {}{}{}",
            c.public_key.algorithm,
            c.public_key
                .size_bits
                .map(|b| format!(" {b} bits"))
                .unwrap_or_default(),
            c.public_key
                .curve
                .as_deref()
                .map(|k| format!(" ({k})"))
                .unwrap_or_default()
        );
        println!("      SHA-256      {}", hex_colons(&c.fingerprints.sha256));
        println!("      SHA-1        {}", hex_colons(&c.fingerprints.sha1));
        println!("      MD5          {}", hex_colons(&c.fingerprints.md5));
        println!("      clé SHA-256  {}", c.public_key_sha256);
    }

    if !r.anomalies.is_empty() {
        println!("\nObservations ({}) :", r.anomalies.len());
        for a in &r.anomalies {
            println!("  - {a}");
        }
    }

    println!("\n(légende des champs : --cert --legend)");
}

fn opt_num(v: Option<u32>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
}

fn opt_bool(v: Option<bool>) -> String {
    match v {
        Some(true) => "true".into(),
        Some(false) => "false".into(),
        None => "-".into(),
    }
}

/// Tronque une chaîne à `max` caractères en préservant la fin (le nom de classe
/// discriminant est en suffixe : `com.très.long.package.MaClasse`).
fn truncate(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let skip = n - (max - 1);
    format!("…{}", s.chars().skip(skip).collect::<String>())
}
