use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use drakkar::{bulk, enrich, export, parser, rules::Engine};
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

    /// Extrait de l'APK les entrées dont le chemin correspond au motif, vers
    /// --out. Répétable. Trois formes : chemin exact (`res/raw/plugin`), glob
    /// (`assets/*.so`, `res/raw/*`), ou sous-chaîne (`plugin`). Insensible à la
    /// casse. N'extrait QUE les entrées demandées — l'archive n'est jamais
    /// déballée en entier. Le SHA-256 et le type réel (reniflé sur les octets de
    /// tête, pas l'extension) sont affichés. Mode single.
    #[arg(long, value_name = "MOTIF", num_args = 1..)]
    extract_entry: Vec<String>,

    /// Liste les chemins de toutes les entrées de l'APK, puis sort. Sert à
    /// trouver quoi passer à --extract-entry. Mode single, rien n'est extrait.
    #[arg(long)]
    list_entries: bool,

    /// Points d'entrée DYNAMIQUES : classes de composants atteintes autrement
    /// que par une déclaration au manifest — registerReceiver, startActivity,
    /// startService, bindService, new Intent(ctx, X.class), setClass*,
    /// setComponent, Class.forName. Accepte un **APK ou un DEX brut** (reconnu
    /// au contenu, pas à l'extension), ce qui permet de passer les DEX déballés
    /// des échantillons packés. Single ou bulk (--bulk DIR), puis sort.
    #[arg(long)]
    dyn_entrypoints: bool,

    /// Chaînes littérales du pool DEX. Sans motif : dump complet. Avec un ou
    /// plusieurs motifs (répéter l'option) : ne sort que les chaînes qui les
    /// contiennent, comparaison INSENSIBLE À LA CASSE. Accepte APK ou DEX brut,
    /// single ou bulk. Sortie TSV : sample, motif, chaine.
    #[arg(long, value_name = "MOTIF", num_args = 0..)]
    strings: Option<Vec<String>>,

    /// Inventaire complet du AndroidManifest.xml (permissions, composants,
    /// intent-filters, points d'entrée dérivés) puis sort. Fonctionne en single
    /// (APK en argument) comme en bulk (--bulk DIR).
    #[arg(long, conflicts_with_all = ["cert", "dating"])]
    manifest: bool,

    /// Inventaire de la signature : schémas v1/v2/v3/v3.1 et certificats X.509
    /// (DN, validité, empreintes) puis sort. Single ou bulk.
    #[arg(long, conflicts_with = "dating")]
    cert: bool,

    /// Indicateurs de datation bruts : dates de signature, planchers de chaîne de
    /// build (format DEX, schémas, compileSdk, versions de bibliothèques),
    /// horodatages de l'archive, littéraux de date du code, cibles d'API.
    /// Aucune date n'est estimée — voir --dating --legend. Single ou bulk.
    #[arg(long)]
    dating: bool,

    /// Diff sémantique de deux DEX (ou APK) par empreinte d'opcodes. Prend deux
    /// entrées A et B ; chaque entrée est un DEX brut ou un APK (reconnu au
    /// contenu). Mesure « même arbre source » en s'affranchissant du renommage
    /// de package et de ProGuard : de chaque méthode seule la séquence de
    /// mnémoniques est retenue. Puis sort.
    /// Réf. : Lee, Jung, Kim & Kim, ICTC 2019, p. 178-183 (vérifiée à la source).
    #[arg(long, value_names = ["A", "B"], num_args = 2)]
    diff_dex: Option<Vec<PathBuf>>,

    /// (--diff-dex) Ne comparer que les classes dont le descripteur Dalvik
    /// commence par ce préfixe (ex. Lcom/dy/). Répétable — passer les préfixes
    /// applicatifs des DEUX côtés. Sans lui : exclusion best-effort des libs.
    #[arg(long, value_name = "PREFIXE", num_args = 1..)]
    diff_include: Vec<String>,

    /// (--diff-dex) Seuil de Jaccard des méthodes au-delà duquel deux classes
    /// non identiques sont dites « proches ». ⚠️ 0.85 est un paramètre de cet
    /// outil, PAS un seuil empirique publié — ne pas l'attribuer au papier.
    #[arg(long, default_value_t = 0.85)]
    diff_threshold: f64,

    /// (--diff-dex) Taille de fenêtre du n-gram global de mots-méthodes, comme
    /// dans le papier. Défaut : 2.
    #[arg(long, default_value_t = 2)]
    diff_ngram: usize,

    /// (--diff-dex) Substitution `DEPUIS=VERS` appliquée au descripteur de classe
    /// pour construire la CLÉ d'appariement (ex. `com/duiyun=com/dy`). Répétable.
    /// N'affecte ni les empreintes, ni les mesures, ni les noms affichés. Sans
    /// elle, entre deux namespaces différents, l'appariement par nom échoue et on
    /// retombe sur le glouton par empreinte — qui mélange les POJO.
    #[arg(long, value_name = "DEPUIS=VERS", num_args = 1..)]
    diff_normalize: Vec<String>,

    /// Désassemble les classes dont le descripteur Dalvik contient l'un des
    /// motifs, avec les opérandes indexées RÉSOLUES en clair (chaînes, types,
    /// méthodes, champs). Accepte un APK ou un DEX brut, reconnu au contenu.
    /// Complément de --diff-dex, qui est aveugle aux opérandes. Ce n'est PAS un
    /// décompilateur — pas de reconstruction de flot ni de types. Puis sort.
    #[arg(long, value_name = "MOTIF", num_args = 0..)]
    disasm: Option<Vec<String>>,

    /// (--disasm) Substitution `DEPUIS=VERS` appliquée aux descripteurs et aux
    /// chaînes avant affichage, pour comparer deux lots de namespaces
    /// différents (ex. `com/duiyun=com/dy`). Répétable. N'affecte que
    /// l'affichage, jamais l'empreinte d'opcodes.
    #[arg(long, value_name = "DEPUIS=VERS", num_args = 1..)]
    disasm_normalize: Vec<String>,

    /// Diff EXPLIQUÉ de deux DEX (ou APK), en mémoire : compare les opérandes
    /// RÉSOLUES des méthodes de même empreinte d'opcodes, index par index, et
    /// catégorise chaque divergence (chaîne / cible de méthode / type / champ
    /// réel / champ renommé). Ferme l'angle mort de --diff-dex, qui est aveugle
    /// aux opérandes. Sortie colorée. Puis sort.
    #[arg(long, value_names = ["A", "B"], num_args = 2)]
    diff_explain: Option<Vec<PathBuf>>,

    /// (--diff-explain) Ne comparer que les classes dont le descripteur Dalvik
    /// commence par ce préfixe. Répétable — passer les préfixes des DEUX côtés.
    #[arg(long, value_name = "PREFIXE", num_args = 1..)]
    explain_include: Vec<String>,

    /// (--diff-explain) Substitution `DEPUIS=VERS` appliquée AVANT comparaison
    /// (ex. `com/duiyun=com/dy`). Répétable. Indispensable entre deux lots de
    /// namespaces différents, sinon chaque opérande diverge sur le namespace.
    #[arg(long, value_name = "DEPUIS=VERS", num_args = 1..)]
    explain_normalize: Vec<String>,

    /// (--diff-explain) Lignes de contexte identiques affichées autour de chaque
    /// changement dans le rendu aligné par LCS. 0 = changements seuls.
    #[arg(long, default_value_t = 3)]
    explain_context: usize,

    /// (--diff-explain) Plafond d'instructions par méthode pour l'alignement
    /// LCS. La table de programmation dynamique est en O(n·m) en temps et en
    /// mémoire ; au-delà la méthode est signalée mais pas alignée.
    #[arg(long, default_value_t = 2000)]
    explain_align_cap: usize,

    /// Diff des POOLS DE CHAÎNES de deux DEX (ou APK). Complément indispensable
    /// de --diff-explain : un champ `static final String` n'est pas écrit par une
    /// instruction (sa valeur vit dans `encoded_static_values`), donc les diffs
    /// d'instructions y sont aveugles — endpoints C2 compris. Le pool, lui,
    /// contient tout. Divergences classées par nature. Puis sort.
    #[arg(long, value_names = ["A", "B"], num_args = 2)]
    diff_strings: Option<Vec<PathBuf>>,

    /// (--diff-strings) Substitution `DEPUIS=VERS` appliquée AVANT comparaison.
    /// Répétable. Ex. `com/duiyun=com/dy`, ou `spyzie=<MARQUE>` et
    /// `safespy=<MARQUE>` pour ne garder que ce qui diffère au-delà du nom.
    #[arg(long, value_name = "DEPUIS=VERS", num_args = 1..)]
    strings_normalize: Vec<String>,

    /// (--diff-strings) Masque le bruit structurel du format DEX : descripteurs
    /// Dalvik et identifiants nus (noms de méthodes, de champs). Ne garde que
    /// les vraies constantes.
    #[arg(long)]
    strings_literals: bool,

    /// (--diff-strings) Ignore les chaînes plus courtes que N caractères.
    #[arg(long, default_value_t = 0)]
    strings_min_len: usize,

    /// Couleur des sorties qui en ont. `auto` (défaut) n'émet des séquences ANSI
    /// que si stdout est un terminal et que NO_COLOR est absent.
    #[arg(long, value_name = "QUAND", default_value = "auto")]
    color: String,

    /// Rendu des sorties --manifest / --cert.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Fichier de sortie du JSON (--format json | both). Sans lui, `json` écrit
    /// sur stdout ; `both` l'exige pour ne jamais mélanger les deux flux.
    #[arg(long, value_name = "FILE")]
    json_out: Option<PathBuf>,

    /// Affiche la légende des étiquettes et règles de dérivation, puis sort.
    /// Se combine avec --manifest, --cert, --dating ou --enrich.
    #[arg(long)]
    legend: bool,

    /// Enrichit une liste de SHA-256 via les services externes : `vt`, `koodous`,
    /// ou les deux séparés par une virgule. Les jetons se lisent dans
    /// VT_API_KEY et KOODOUS_TOKEN — jamais en argument.
    #[arg(long, value_name = "SOURCES")]
    enrich: Option<String>,

    /// Entrée de --enrich : CSV de datation (colonne file_sha256), liste d'un
    /// hachage par ligne, répertoire de *.dating.json, ou `-` pour stdin.
    #[arg(long, value_name = "PATH", default_value = "-")]
    enrich_input: PathBuf,

    /// Cache des réponses brutes, un sous-répertoire par service. Une réponse
    /// déjà obtenue n'est jamais redemandée : le lot est reprenable.
    #[arg(long, value_name = "DIR", default_value = "./cache/enrich")]
    cache: PathBuf,

    /// Requêtes par minute et par service. 4 = quota public VirusTotal.
    #[arg(long, default_value_t = 4)]
    rate: u32,

    /// Ignore le cache et refait tous les appels.
    #[arg(long)]
    force: bool,
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

    // Sortie rapide : points d'entrée dynamiques. Ne charge ni le catalogue
    // MITRE ni le moteur de règles — deux passages sur les classes*.dex.
    // Fonctionne en single (APK en argument) comme en bulk (--bulk DIR).
    if cli.dyn_entrypoints {
        let apks: Vec<PathBuf> = match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => vec![apk.clone()],
            (None, Some(dir)) => {
                let found = parser::dyn_entrypoints::collect_inputs(dir, cli.recursive)?;
                if found.is_empty() {
                    bail!("aucun APK ni DEX trouvé dans {}", dir.display());
                }
                found
            }
            _ => bail!("--dyn-entrypoints requiert soit un APK ou un DEX, soit --bulk DIR"),
        };

        // Traitement séquentiel : la sortie est un flux TSV ordonné, destiné à
        // être filtré (`awk`, `sort`). Du parallélisme entrelacerait les lignes
        // pour un gain négligeable sur un corpus de quelques dizaines d'APK.
        println!("sample\torigine\tclasse\tsink\toffset\tappelant\tdetail");
        for apk in &apks {
            let sample = apk
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());

            // Un DEX malformé peut faire paniquer le crate : on isole pour qu'un
            // échantillon pourri ne tue pas le lot.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parser::dyn_entrypoints::extract_any(apk)
            }));
            let report = match outcome {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    eprintln!("[FAIL]  {sample} — {e:#}");
                    continue;
                }
                Err(_) => {
                    eprintln!("[PANIC] {sample} — parsing abandonné");
                    continue;
                }
            };

            for e in &report.entrypoints {
                println!(
                    "{}\t{}\t{}\t{}\t+{}\t{}\t",
                    sample,
                    e.provenance.as_str(),
                    e.class,
                    e.via,
                    e.site,
                    e.caller.api()
                );
            }
            for u in &report.unresolved {
                println!(
                    "{}\t?\t\t{}\t+{}\t{}\t{} {} {}",
                    sample,
                    u.via,
                    u.site,
                    u.caller.api(),
                    u.reason.as_str(),
                    u.target_reg.map(|r| format!("v{r}")).unwrap_or_else(|| "-".into()),
                    u.blocking_insn.as_deref().unwrap_or("-")
                );
            }
            eprintln!(
                "[OK]    {sample} — {} resolus ({} classes distinctes), {} non resolus",
                report.entrypoints.len(),
                report.classes().len(),
                report.unresolved.len()
            );
        }
        return Ok(());
    }

    // Sortie rapide : chaines litterales du pool DEX. Single ou bulk, APK ou DEX.
    if let Some(motifs) = &cli.strings {
        let inputs: Vec<PathBuf> = match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => vec![apk.clone()],
            (None, Some(dir)) => {
                let found = parser::dyn_entrypoints::collect_inputs(dir, cli.recursive)?;
                if found.is_empty() {
                    bail!("aucun APK ni DEX trouvé dans {}", dir.display());
                }
                found
            }
            _ => bail!("--strings requiert soit un APK ou un DEX, soit --bulk DIR"),
        };

        // Motifs normalisés une fois pour toutes : la comparaison est
        // insensible à la casse, car les constantes hexadécimales du corpus
        // apparaissent tantôt en majuscules tantôt en minuscules.
        let needles: Vec<(String, String)> = motifs
            .iter()
            .map(|m| (m.clone(), m.to_lowercase()))
            .collect();

        println!("sample\tmotif\tchaine");
        for input in &inputs {
            let sample = input
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());

            let pool = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parser::dex_strings::extract_any(input)
            })) {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    eprintln!("[FAIL]  {sample} — {e:#}");
                    continue;
                }
                Err(_) => {
                    eprintln!("[PANIC] {sample} — parsing abandonné");
                    continue;
                }
            };

            let mut hits = 0usize;
            for s in &pool.strings {
                if needles.is_empty() {
                    // Dump complet : les retours à la ligne casseraient le TSV.
                    println!("{}\t-\t{}", sample, s.replace(['\n', '\r', '\t'], " "));
                    hits += 1;
                    continue;
                }
                let lower = s.to_lowercase();
                for (motif, needle) in &needles {
                    if lower.contains(needle) {
                        println!(
                            "{}\t{}\t{}",
                            sample,
                            motif,
                            s.replace(['\n', '\r', '\t'], " ")
                        );
                        hits += 1;
                    }
                }
            }
            eprintln!(
                "[OK]    {sample} — {} chaines lues sur {} declarees, {} illisibles, {} correspondances",
                pool.strings.len(),
                pool.declared,
                pool.unreadable,
                hits
            );
        }
        return Ok(());
    }

    // Sortie rapide : diff sémantique de deux DEX/APK par empreinte d'opcodes.
    // Ne charge ni catalogue MITRE ni moteur de règles. L'appariement des
    // classes est nom-agnostique : com.dy↔com.duiyun et ProGuard sont absorbés.
    if let Some(pair) = &cli.diff_dex {
        if cli.legend {
            println!("{}", parser::diff_dex::legend());
            return Ok(());
        }
        check_json_dest(cli.format, cli.json_out.as_deref())?;
        let opts = parser::diff_dex::DiffOptions {
            include_prefixes: cli.diff_include.clone(),
            threshold: cli.diff_threshold,
            ngram: cli.diff_ngram,
            normalize: parse_substitutions(&cli.diff_normalize, "--diff-normalize")?,
        };
        let report = parser::diff_dex::run(&pair[0], &pair[1], &opts)?;
        if cli.format.wants_text() {
            print_diff_dex(&report);
        }
        if cli.format.wants_json() {
            emit_json(&report, cli.json_out.as_deref())?;
        }
        return Ok(());
    }

    // Sortie rapide : diff des pools de chaînes. Ferme l'angle mort des diffs
    // d'instructions sur les constantes `static final`.
    if let Some(pair) = &cli.diff_strings {
        use parser::diff_explain::ColorMode;

        if cli.legend {
            println!("{}", parser::diff_strings::legend());
            return Ok(());
        }
        let color = match cli.color.as_str() {
            "auto" => ColorMode::Auto,
            "always" => ColorMode::Always,
            "never" => ColorMode::Never,
            other => bail!("--color attend auto|always|never, reçu {other:?}"),
        };
        check_json_dest(cli.format, cli.json_out.as_deref())?;
        let opts = parser::diff_strings::StringDiffOptions {
            normalize: parse_substitutions(&cli.strings_normalize, "--strings-normalize")?,
            literals_only: cli.strings_literals,
            min_len: cli.strings_min_len,
            color,
            ..Default::default()
        };
        let report = parser::diff_strings::run(&pair[0], &pair[1], &opts)?;
        if cli.format.wants_text() {
            print!("{}", parser::diff_strings::render(&report, &opts));
        }
        if cli.format.wants_json() {
            emit_json(&report, cli.json_out.as_deref())?;
        }
        return Ok(());
    }

    // Sortie rapide : diff expliqué. Compare les OPÉRANDES des méthodes de même
    // empreinte — là où --diff-dex ne voit que la structure. En mémoire, donc
    // sans la dérive d'offsets qui pourrit un diff textuel de désassemblage.
    if let Some(pair) = &cli.diff_explain {
        use parser::diff_explain::ColorMode;

        let color = match cli.color.as_str() {
            "auto" => ColorMode::Auto,
            "always" => ColorMode::Always,
            "never" => ColorMode::Never,
            other => bail!("--color attend auto|always|never, reçu {other:?}"),
        };

        let opts = parser::diff_explain::ExplainOptions {
            include_prefixes: cli.explain_include.clone(),
            normalize: parse_substitutions(&cli.explain_normalize, "--explain-normalize")?,
            color,
            context: cli.explain_context,
            align_cap: cli.explain_align_cap,
            ..Default::default()
        };

        if cli.legend {
            println!("{}", parser::diff_explain::legend());
            return Ok(());
        }

        let report = parser::diff_explain::run(&pair[0], &pair[1], &opts)?;
        if cli.format.wants_text() {
            print!("{}", parser::diff_explain::render_report(&report, &opts));
        }
        if cli.format.wants_json() {
            emit_json(&report, cli.json_out.as_deref())?;
        }
        return Ok(());
    }

    // Sortie rapide : désassemblage lisible d'une sélection de classes. Ne
    // charge ni catalogue MITRE ni moteur de règles. Mode single uniquement :
    // la sortie est destinée à être diffée, un fichier par binaire.
    if let Some(patterns) = &cli.disasm {
        if cli.legend {
            println!("{}", parser::disasm::legend());
            return Ok(());
        }
        let Some(input) = &cli.apk else {
            bail!("--disasm requiert un APK ou un DEX en argument (mode single)");
        };

        // `DEPUIS=VERS` : on découpe sur le PREMIER `=` seulement, pour ne pas
        // casser un motif qui en contiendrait un.
        let normalize = parse_substitutions(&cli.disasm_normalize, "--disasm-normalize")?;

        let opts = parser::disasm::DisasmOptions {
            patterns: patterns.clone(),
            normalize,
        };
        let report = parser::disasm::run(input, &opts)?;
        print!("{}", parser::disasm::render(&report));
        eprintln!(
            "[OK]    {} classe(s) désassemblée(s) sur {} lues",
            report.classes.len(),
            report.scanned
        );
        return Ok(());
    }

    // Sortie rapide : légende seule (aucun APK requis).
    if cli.legend {
        if cli.cert {
            println!("{}", parser::cert::legend());
        } else if cli.dating {
            println!("{}", parser::dating::legend());
        } else if !cli.extract_entry.is_empty() || cli.list_entries {
            println!("{}", parser::entry_extract::legend());
        } else if cli.enrich.is_some() {
            println!("{}", enrich::legend());
        } else {
            println!("{}", parser::manifest_info::legend());
        }
        return Ok(());
    }

    // Sortie rapide : enrichissement réseau. Ne lit aucun APK — il n'a besoin que
    // des SHA-256, produits par la passe --dating.
    if let Some(sources) = &cli.enrich {
        let sources = enrich::Source::parse_list(sources)?;
        let hashes = enrich::read_hashes(&cli.enrich_input)?;
        if hashes.is_empty() {
            bail!(
                "aucun SHA-256 lu depuis {} — attendu un CSV à colonne file_sha256, \
                 une liste d'un hachage par ligne, ou un répertoire de *.dating.json",
                cli.enrich_input.display()
            );
        }
        let opts = enrich::EnrichOptions {
            sources,
            cache_dir: cli.cache.clone(),
            rate_per_min: cli.rate,
            force: cli.force,
        };
        let rows = enrich::run(&hashes, &opts)?;

        if cli.format == Format::Json {
            emit_json(&rows, cli.json_out.as_deref())?;
        } else {
            print!("{}", enrich::to_csv(&rows));
        }
        return Ok(());
    }

    // Sortie rapide : inventaires manifest / signature / datation. Aucun DEX n'est
    // décompilé, le catalogue MITRE n'est pas chargé. Single (APK) ou bulk.
    if cli.manifest || cli.cert || cli.dating {
        let what = if cli.manifest {
            bulk::Inventory::Manifest
        } else if cli.cert {
            bulk::Inventory::Cert
        } else {
            bulk::Inventory::Dating
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
                    bulk::Inventory::Dating => {
                        let report = parser::dating::extract(apk)?;
                        if cli.format.wants_text() {
                            print_dating(&report);
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

    // Sortie rapide : liste des entrées de l'archive. Rien n'est extrait.
    if cli.list_entries {
        let Some(apk) = &cli.apk else {
            bail!("--list-entries requiert un APK (mode single)");
        };
        for name in parser::entry_extract::list_entries(apk)? {
            println!("{name}");
        }
        return Ok(());
    }

    // Sortie rapide : extraction ciblée d'entrées par motif de chemin. Seules
    // les entrées demandées sont lues — l'archive n'est jamais déballée en
    // entier. Cas d'usage : APK de plugin embarqué (res/raw/plugin des
    // conteneurs DroidPlugin), payload d'un packer dans assets/.
    if !cli.extract_entry.is_empty() {
        let Some(apk) = &cli.apk else {
            bail!("--extract-entry requiert un APK (mode single)");
        };
        let extraction = parser::entry_extract::extract_matching(apk, &cli.extract_entry)?;
        print_and_dump_entries(&extraction, &cli.out)?;
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
            setup_jobs(cli.jobs)?;
            bulk::run(dir, &engine, &bulk_options(&cli))?;
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

/// Analyse une liste de substitutions `DEPUIS=VERS`.
///
/// Découpe sur le PREMIER `=` seulement : un motif peut lui-même en contenir.
fn parse_substitutions(specs: &[String], flag: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for spec in specs {
        match spec.split_once('=') {
            Some((from, to)) if !from.is_empty() => out.push((from.to_string(), to.to_string())),
            _ => bail!("{flag} attend `DEPUIS=VERS`, reçu {spec:?}"),
        }
    }
    Ok(out)
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

/// Rendu console des indicateurs de datation (mode `--dating`).
fn print_dating(r: &drakkar::parser::dating::DatingReport) {
    println!("== Indicateurs de datation ==\n");
    println!("{} {}", r.package, r.version_name.as_deref().unwrap_or(""));

    println!("\nCibles d'API (déclarées, pas des dates) :");
    println!(
        "  min={}  target={}  compile={}{}",
        opt_num(r.sdk.min_sdk),
        opt_num(r.sdk.target_sdk),
        opt_num(r.sdk.compile_sdk),
        r.sdk
            .compile_sdk_codename
            .as_deref()
            .map(|c| format!(" ({c})"))
            .unwrap_or_default()
    );
    match r.sdk.compile_minus_target {
        Some(d) => println!("  compile - target = {d}"),
        None => println!("  compile - target = indisponible (compileSdk absent)"),
    }
    if let Some(p) = &r.sdk.platform_build_version_code {
        println!("  platformBuildVersion   {p}");
    }

    println!("\nBornes basses (le build est postérieur) :");
    for s in &r.signatures {
        println!(
            "  clé {}  {}  ({})",
            s.not_before,
            s.subject_cn.as_deref().unwrap_or("?"),
            s.source
        );
    }
    if !r.signing_schemes.is_empty() {
        println!("  schémas de signature   {}", r.signing_schemes.join("+"));
    }
    for d in &r.dex_files {
        println!(
            "  {:<14} format {}  -> API {}  ({} chaînes)",
            d.entry,
            d.format_version,
            d.api_floor.map(|a| a.to_string()).unwrap_or_else(|| "?".into()),
            d.string_count
        );
    }
    println!(
        "  plancher retenu        {}",
        r.toolchain_floor_api
            .map(|a| format!("API {a}"))
            .unwrap_or_else(|| "indisponible".into())
    );

    println!("\nHorodatages de l'archive ({} entrées) :", r.archive.entry_count);
    println!(
        "  {} -> {}  ({} valeurs distinctes)",
        r.archive.earliest.as_deref().unwrap_or("?"),
        r.archive.latest.as_deref().unwrap_or("?"),
        r.archive.distinct_count
    );
    if r.archive.normalized {
        println!("  NORMALISÉS — build reproductible, ces dates ne datent rien");
    }
    if let Some(s) = &r.archive.sentinel {
        println!("  sentinelle reconnue    {s}");
    }

    if !r.library_versions.is_empty() {
        println!("\nVersions de bibliothèques ({}) :", r.library_versions.len());
        for l in &r.library_versions {
            println!("  {:<48} {}", l.module, l.version);
        }
    }

    if !r.build_metadata.is_empty() {
        println!("\nMétadonnées de build :");
        for m in &r.build_metadata {
            println!("  {}  ({} o conservés)", m.entry, m.content.len());
        }
    }

    if r.code_dates.is_empty() {
        println!("\nLittéraux de date dans le code : aucun");
    } else {
        println!("\nLittéraux de date dans le code ({}) :", r.code_dates.len());
        for d in &r.code_dates {
            println!("  {}  ({} occurrence(s))", d.value, d.occurrences);
        }
    }

    println!("\n(nature exacte de chaque indicateur : --dating --legend)");
}

fn opt_num(v: Option<u32>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "?".into())
}

/// Rendu console du diff DEX (mode `--diff-dex`).
fn print_diff_dex(r: &drakkar::parser::diff_dex::DiffReport) {
    println!("== Diff DEX ==\n");
    println!("A  {}", r.input_a);
    println!("B  {}", r.input_b);
    println!(
        "\nClasses applicatives : A={}  B={}   Méthodes : A={}  B={}",
        r.classes_a, r.classes_b, r.methods_a, r.methods_b
    );

    println!("\nSimilarité globale :");
    println!(
        "  méthodes identiques (Jaccard, ordre-insensible)   {:.4}",
        r.jaccard_methods
    );
    println!(
        "  {}-gramme de méthodes (Jaccard, ordre-sensible)    {:.4}",
        r.ngram, r.jaccard_ngram
    );

    println!("\nAppariement par classe (seuil proche = {:.2}) :", r.threshold);
    println!(
        "  identiques   {}   (par nom {}, par empreinte seule {})",
        r.identical_classes, r.identical_by_name, r.identical_by_hash
    );
    if r.identical_by_hash > 0 {
        println!(
            "               /!\\ {} paire(s) appariée(s) sur la seule empreinte : soit un renommage",
            r.identical_by_hash
        );
        println!("                   réel de classe, soit un appariement douteux entre classes de");
        println!("                   même forme (POJO). À vérifier dans le JSON.");
    }
    println!("  proches      {}", r.near_classes);
    println!("  only in A    {}", r.only_in_a.len());
    println!("  only in B    {}", r.only_in_b.len());

    if !r.near.is_empty() {
        println!("\nClasses proches (Jaccard décroissant) :");
        for p in &r.near {
            println!(
                "  {:.4}  {:<44} ↔ {:<44} ({}/{} méthodes)",
                p.jaccard, p.class_a, p.class_b, p.methods_a, p.methods_b
            );
        }
    }

    if !r.only_in_a.is_empty() {
        println!("\nClasses propres à A ({}) :", r.only_in_a.len());
        for c in &r.only_in_a {
            println!("  {c}");
        }
    }
    if !r.only_in_b.is_empty() {
        println!("\nClasses propres à B ({}) :", r.only_in_b.len());
        for c in &r.only_in_b {
            println!("  {c}");
        }
    }

    println!("\n(le détail des classes identiques est dans le JSON ; légende : --diff-dex --legend)");
}

/// Affiche le résultat d'une extraction ciblée et écrit les entrées dans `dir`.
///
/// Le SHA-256 est celui du contenu **décompressé** : c'est lui qu'on rapproche du
/// corpus. Le type est reniflé sur les octets de tête, jamais déduit de
/// l'extension — un APK embarqué s'appelle souvent `plugin`, sans extension.
fn print_and_dump_entries(
    ex: &drakkar::parser::entry_extract::EntryExtraction,
    dir: &std::path::Path,
) -> Result<()> {
    println!("== Extraction ciblée ==");
    println!("Motifs   : {}", ex.patterns.join(", "));
    println!("Entrées  : {} retenue(s) sur {} dans l'archive", ex.count(), ex.scanned);

    if ex.is_empty() {
        println!("\nAucune entrée ne correspond. `--list-entries` donne l'arborescence.");
        return Ok(());
    }

    println!();
    for e in &ex.entries {
        let dest = e.write_to(dir)?;
        println!("  {}", e.entry);
        println!("      type      {}", e.kind);
        println!(
            "      taille    {} o  (compressé {} o)",
            e.size, e.compressed_size
        );
        println!("      entropie  {:.2}", e.entropy);
        println!("      SHA-256   {}", e.sha256);
        println!("      écrit     {}", dest.display());
    }

    println!("\n(nature exacte de chaque champ : --extract-entry --legend)");
    Ok(())
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
