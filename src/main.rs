use anyhow::Result;
use clap::Parser;
use drakkar::{export, kharon, parser, rules::Engine};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "drakkar", version, about = "MITRE ATT&CK for Mobile detection on APKs")]
struct Cli {
    /// APK à analyser
    apk: PathBuf,

    /// Répertoire des règles MITRE (*.yaml)
    #[arg(short, long, default_value = "rules/mitre")]
    rules: PathBuf,

    /// Export du CFG en NetworkX node-link JSON (pour APKolgomorov)
    #[arg(long)]
    export_graph: Option<PathBuf>,

    /// Summary Kharon pour confirmation dynamique des candidats
    #[arg(long)]
    kharon: Option<PathBuf>,
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
    let engine = Engine::load(&cli.rules)?;
    let mut matches = engine.run(&parsed.features, &parsed.call_graph);

    if let Some(k) = &cli.kharon {
        let summary = kharon::load_summary(k)?;
        kharon::confirm(&mut matches, &summary);
    }

    if let Some(out) = &cli.export_graph {
        export::networkx::write(&parsed.call_graph, out)?;
    }

    println!("{}", serde_json::to_string_pretty(&matches)?);
    Ok(())
}
