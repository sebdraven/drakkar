use anyhow::{bail, Result};
use clap::Parser;
use drakkar::{bulk, export, parser, rules::Engine};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "drakkar", version, about = "MITRE ATT&CK for Mobile detection on APKs")]
struct Cli {
    /// APK à analyser (mode single). Omettre si --bulk est utilisé.
    apk: Option<PathBuf>,

    /// Mode bulk : analyse tous les .apk d'un répertoire (un <stem>.json par APK).
    #[arg(long, value_name = "DIR", conflicts_with = "apk")]
    bulk: Option<PathBuf>,

    /// Répertoire de sortie des JSON en mode bulk.
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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

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
