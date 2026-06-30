use anyhow::Result;
use clap::Parser;
use drakkar::{export, parser, rules::Engine};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "drakkar", version, about = "MITRE ATT&CK for Mobile detection on APKs")]
struct Cli {
    /// APK à analyser
    apk: PathBuf,

    /// Répertoire de règles à utiliser à la place du cache auto-généré (override).
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Force le re-téléchargement du catalogue MITRE et la régénération du cache.
    #[arg(long)]
    refresh: bool,

    /// Export du CFG en NetworkX node-link JSON (pour APKolgomorov)
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

    let parsed = parser::parse_apk(&cli.apk)?;
    let engine = match &cli.rules {
        Some(dir) => Engine::load(dir)?,
        None => Engine::load_cached(cli.refresh)?,
    };
    let matches = engine.run(&parsed.features, &parsed.call_graph);

    if let Some(out) = &cli.export_graph {
        export::networkx::write(&parsed.call_graph, out)?;
    }

    println!("{}", serde_json::to_string_pretty(&matches)?);
    Ok(())
}
