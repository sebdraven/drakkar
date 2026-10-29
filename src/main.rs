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
#[command(
    name = "drakkar",
    version,
    about = "MITRE ATT&CK for Mobile detection on APKs"
)]
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

    /// Ré-analyse même si le JSON de sortie existe déjà (mode bulk). Avec
    /// --bundle : remplace le répertoire OUT/<sha256> existant.
    #[arg(long)]
    overwrite: bool,

    /// Threads rayon en mode bulk et --bundle (0 = auto, tous les cœurs).
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

    /// Analyse statique de TOUS les ELF de l'APK (lib/, assets/, res/raw/,
    /// ailleurs), reconnus au contenu : sections, segments, imports classés,
    /// chaînes, exports Java_*, tables JNINativeMethod reconstruites à travers
    /// les relocations relatives, puis liaison avec les méthodes `native` du DEX.
    /// Aucune exécution ; désassemblage seulement avec --native-disasm. Texte par
    /// défaut, --format json|both disponible ; --native --legend définit chaque
    /// champ. Mode single.
    #[arg(long, conflicts_with = "native_arch")]
    native: bool,

    /// (--native) Désassemble statiquement, dans chaque ELF, les fonctions liées
    /// au DEX, JNI_OnLoad / JNI_OnUnload, DT_INIT, DT_INIT_ARRAY et e_entry, et
    /// décode leurs appels JNIEnv, imports appelés, chaînes référencées et appels
    /// système. Rien n'est exécuté ni émulé.
    #[arg(long)]
    native_disasm: bool,

    /// (--native-disasm) Profondeur des fonctions internes suivies depuis les
    /// points d'entrée : 0 = points d'entrée seuls. Défaut 1.
    #[arg(long, value_name = "N")]
    disasm_depth: Option<u8>,

    /// (--native-disasm) Plafond d'instructions par fonction ; atteint, la
    /// fonction est marquée truncated. Défaut 4000.
    #[arg(long, value_name = "N")]
    disasm_max_insns: Option<usize>,

    /// (--native-disasm) Instructions dans la sortie texte. Le JSON les porte
    /// toujours.
    #[arg(long)]
    disasm_full: bool,

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

    /// Inventaire des entrées `assets/` de l'APK, puis sort. RIEN n'est écrit.
    /// Sortie TSV : chemin, taille compressée, taille décompressée, méthode
    /// déclarée, SHA-256 complet, type reniflé sur les octets de tête, entropie.
    /// Passe par le lecteur tolérant (src/parser/apkzip.rs) quand le crate `zip`
    /// refuse l'archive — sans quoi les APK trafiqués du corpus ressortiraient
    /// sans assets. Single ou bulk (--bulk DIR).
    #[arg(long)]
    list_assets: bool,

    /// Extrait les entrées `assets/` vers DIR : les fichiers, en reproduisant
    /// l'arborescence de l'archive, plus un `assets.json` (SHA-256 de l'APK, une
    /// entrée par asset avec les mêmes champs que --list-assets + le chemin
    /// réellement écrit). Un asset qui est lui-même un ZIP, un APK ou un DEX est
    /// typé et écrit TEL QUEL — pas de déballage récursif. En bulk, un
    /// sous-répertoire par échantillon + un `assets_index.json` global.
    #[arg(long, value_name = "DIR", conflicts_with = "list_assets")]
    extract_assets: Option<PathBuf>,

    /// Empreinte d'ensemble des assets SEULE, puis sort. Rien n'est écrit.
    /// Sortie TSV : sample, empreinte, statut, assets, non_evalues. L'empreinte
    /// n'est émise que si elle porte sur la TOTALITÉ des assets ; sinon la
    /// colonne vaut ABSENTE et `statut` dit pourquoi (aucun-asset, ou incomplet
    /// avec la cause). --assets-include et --assets-max-size sont acceptés ici —
    /// c'est le seul moyen d'observer un statut « incomplet » sur un lot — mais
    /// les filtres par hash sont refusés : l'empreinte ne les honore pas.
    /// Single ou bulk (--bulk DIR).
    #[arg(long, conflicts_with_all = ["list_assets", "extract_assets"])]
    assets_fingerprint: bool,

    /// (--list-assets / --extract-assets / --assets-fingerprint) Ne retient que
    /// les entrées dont le chemin CONTIENT ce motif. Répétable, insensible à la
    /// casse.
    #[arg(long, value_name = "MOTIF", num_args = 1..)]
    assets_include: Vec<String>,

    /// (--list-assets / --extract-assets / --assets-fingerprint) Plafond en octets sur la taille
    /// décompressée. Au-delà, l'asset est ignoré et consigné (jamais d'omission
    /// silencieuse). Contrôlé sur la taille déclarée avant lecture, puis sur la
    /// taille réelle après — le central directory d'une archive trafiquée ment.
    #[arg(long, value_name = "N")]
    assets_max_size: Option<u64>,

    /// (--list-assets / --extract-assets) Ne conserve que les assets dont le
    /// SHA-256 figure dans l'ensemble. Répétable. Pivot sur une charge connue :
    /// « quels binaires du corpus portent cet asset ? ». Sortie TSV étroite
    /// sample / chemin / sha256 ; un échantillon sans correspondance ne produit
    /// aucune ligne. N'écrit rien, sauf si --extract-assets est aussi passé —
    /// auquel cas seuls les assets retenus sont écrits.
    #[arg(long, value_name = "SHA256", num_args = 1..)]
    assets_hash: Vec<String>,

    /// (--list-assets / --extract-assets) Même chose depuis un fichier : un
    /// SHA-256 par ligne, `#` en commentaire, casse indifférente.
    #[arg(long, value_name = "FICHIER")]
    assets_hash_file: Option<PathBuf>,

    /// (--list-assets / --extract-assets) Sens inverse de --assets-hash : RETIRE
    /// les assets déjà qualifiés (polices, libs de SDK, ressources tierces
    /// récurrentes) pour ne laisser que le reliquat. Répétable. Exclusif de
    /// --assets-hash / --assets-hash-file.
    #[arg(
        long,
        value_name = "SHA256",
        num_args = 1..,
        conflicts_with_all = ["assets_hash", "assets_hash_file"]
    )]
    assets_hash_exclude: Vec<String>,

    /// (--list-assets / --extract-assets) Même chose depuis un fichier, même
    /// format que --assets-hash-file.
    #[arg(
        long,
        value_name = "FICHIER",
        conflicts_with_all = ["assets_hash", "assets_hash_file"]
    )]
    assets_hash_exclude_file: Option<PathBuf>,

    /// Points d'entrée DYNAMIQUES : classes de composants atteintes autrement
    /// que par une déclaration au manifest — registerReceiver, startActivity,
    /// startService, bindService, new Intent(ctx, X.class), setClass*,
    /// setComponent, Class.forName. Accepte un **APK ou un DEX brut** (reconnu
    /// au contenu, pas à l'extension), ce qui permet de passer les DEX déballés
    /// des échantillons packés. Single ou bulk (--bulk DIR), puis sort.
    #[arg(long)]
    dyn_entrypoints: bool,

    /// MESURE (jetable) : d'où vient le NOM des cibles de réflexion ?
    /// Classe chaque site Method.invoke / Class.forName / getMethod /
    /// getDeclaredMethod selon la provenance de son registre-nom : const,
    /// decrypt-const (déchiffreur à argument littéral, donc rejouable),
    /// runtime, param, indirect, unknown. Le ratio decrypt-const/runtime dit si
    /// un interpréteur Dalvik de déobfuscation vaut le coup. Accepte un APK ou
    /// un DEX brut (reconnu au contenu). Single ou bulk (--bulk DIR), TSV, puis sort.
    #[arg(long)]
    reflection_inputs: bool,

    /// Audit d'orphelins : partitionne les méthodes NON atteignables depuis les
    /// entrypoints en composantes faiblement connexes, et marque celles qui
    /// contiennent System.loadLibrary. Mesure la saturation des racines à quatre
    /// étages : manifest -> +dynamiques -> +handlers UI -> +<clinit>. Accepte un
    /// **APK ou un DEX brut** (reconnu au contenu) : sans manifeste, les racines
    /// sont heuristiques, ce que reporte `roots_mode`. Single ou bulk (--bulk DIR).
    #[arg(long)]
    orphan_audit: bool,

    /// Sonde une API précise (sous-chaîne de `class->name`, ex.
    /// `System;->loadLibrary` ou `Lorg/c/b;->a`) : dit si c'est un nœud du graphe
    /// et si elle est atteignable depuis les racines (manifest + dyn + ui +
    /// <clinit>), chemins à l'appui. Accepte un APK ou un DEX brut (reconnu au
    /// contenu). Mode single, puis sort.
    #[arg(long, value_name = "API")]
    probe: Option<String>,

    /// Surface d'API DÉCLARÉE par les annotations : verbe HTTP, gabarit de route
    /// et noms de paramètres depuis Retrofit (@GET, @POST, @Path, @Query…),
    /// noms sérialisés depuis Gson (@SerializedName). Lit
    /// l'annotation_directory_item, aucune instruction : une route construite à
    /// l'exécution lui est invisible, et une sortie vide veut dire « pas
    /// Retrofit », pas « pas de route » (--api-surface --legend). Accepte APK ou
    /// DEX brut, single ou bulk. Sortie TSV, --format json disponible.
    #[arg(long)]
    api_surface: bool,

    /// Chaînes littérales du pool DEX. Sans motif : dump complet. Avec un ou
    /// plusieurs motifs (répéter l'option) : ne sort que les chaînes qui les
    /// contiennent, comparaison INSENSIBLE À LA CASSE. Accepte APK ou DEX brut,
    /// single ou bulk. Sortie TSV : sample, motif, chaine.
    #[arg(long, value_name = "MOTIF", num_args = 0..)]
    strings: Option<Vec<String>>,

    /// Résout un NOM de ressource (la clé de `R.<type>.<nom>`) en type,
    /// identifiant et valeur, en lisant `resources.arsc`. Répétable. Un même nom
    /// peut exister dans plusieurs types : toutes les correspondances sortent.
    /// Sortie TSV : sample, type, nom, id en hexadécimal, valeur. Single ou bulk
    /// (--bulk DIR), --format json disponible.
    #[arg(long, value_name = "NOM")]
    resource: Vec<String>,

    /// Résout un IDENTIFIANT de ressource en type, nom et valeur. Trois formes
    /// acceptées : 0x7f110228, 7f110228, 2131886120 — une suite de chiffres est
    /// lue en décimal puis en hexadécimal, et la lecture qui résout est retenue.
    /// Répétable. Même sortie que --resource. Single ou bulk.
    #[arg(long, value_name = "ID")]
    resource_id: Vec<String>,

    /// Dump de la table des ressources, nom vers valeur. Sans argument : tout.
    /// Avec un ou plusieurs types (répéter l'option) : seulement ceux-là
    /// (string, layout, drawable, id…). Sortie TSV : sample, type, nom, id en
    /// hexadécimal, valeur. Single ou bulk.
    #[arg(long, value_name = "TYPE", num_args = 0.., conflicts_with_all = ["resource", "resource_id"])]
    resources: Option<Vec<String>>,

    /// Jointure DEX -> ressources : balaye les constantes entières des
    /// classes*.dex dans la plage des packages de la table, ne retient que
    /// celles qui désignent une entrée RÉELLE, et rend une ligne par usage —
    /// classe, méthode, offset, id, type, nom, valeur, origine, consommateur.
    /// Le résumé de fin de passe donne de quoi encadrer le taux de faux
    /// positifs (--resource-xref --legend). Single ou bulk.
    #[arg(long, conflicts_with_all = ["resource", "resource_id", "resources"])]
    resource_xref: bool,

    /// Ressources qu'AUCUNE constante du DEX ne référence. « Orpheline » veut
    /// dire NON RÉFÉRENCÉE DEPUIS LE CODE, jamais « inutilisée » : une ressource
    /// citée par un layout, un style ou le manifeste est orpheline ici tout en
    /// étant parfaitement utilisée. Même sortie TSV que --resources. Single ou bulk.
    #[arg(long, conflicts_with_all = ["resource", "resource_id", "resources", "resource_xref"])]
    resource_orphans: bool,

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

    /// Décompile en Java (dex-decompiler) les classes dont le descripteur
    /// Dalvik contient l'un des motifs. Même sélection que --disasm :
    /// sous-chaîne insensible à la casse, répétable, sans motif = toutes les
    /// classes. Accepte un APK ou un DEX brut, reconnu au contenu. Java sur
    /// stdout, puis sort.
    #[arg(long, value_name = "MOTIF", num_args = 0..)]
    decompile: Option<Vec<String>>,

    /// Écrit OUT/<sha256 de l'entrée>/ : manifeste, signature, datation,
    /// règles, chaînes, points d'entrée dynamiques, et chaque classe
    /// désassemblée et décompilée. Accepte un APK ou un DEX brut, reconnu au
    /// contenu. Mode single : `drakkar <APK> --bundle <OUT>`. Refuse un
    /// répertoire existant sans --overwrite. --bundle --legend définit chaque
    /// fichier et chaque champ.
    #[arg(long, value_name = "OUT", num_args = 0..=1, conflicts_with = "bulk")]
    bundle: Option<Option<PathBuf>>,

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

    /// Matrice de similarité TOUS-CONTRE-TOUS sur un répertoire d'échantillons
    /// (APK ou DEX, reconnus au contenu). Chaque entrée n'est parsée QU'UNE FOIS,
    /// puis les n(n-1)/2 comparaisons se font sur des ensembles en mémoire.
    /// Sort la matrice, le classement des paires et un regroupement par lien
    /// simple. Puis sort.
    #[arg(long, value_name = "DIR")]
    diff_matrix: Option<PathBuf>,

    /// (--diff-matrix) Métrique qui pilote la matrice et le regroupement.
    /// `opcodes` = « même moteur ? », `strings` = « mêmes constantes ? ».
    /// Les deux sont calculées dans tous les cas.
    #[arg(long, value_name = "NOM", default_value = "opcodes")]
    matrix_metric: String,

    /// (--diff-matrix) Substitution `DEPUIS=VERS` appliquée aux descripteurs ET
    /// aux chaînes avant comparaison. Répétable. Indispensable sur un lot
    /// multi-namespace (`com/duiyun=com/dy`), sinon les descripteurs font
    /// chuter la similarité pour une raison qui n'a rien à voir avec le code.
    #[arg(long, value_name = "DEPUIS=VERS", num_args = 1..)]
    matrix_normalize: Vec<String>,

    /// (--diff-matrix) Seuil de regroupement par lien simple.
    #[arg(long, default_value_t = 0.85)]
    matrix_threshold: f64,

    /// (--diff-matrix) Nombre de paires listées dans le classement. 0 = toutes.
    #[arg(long, default_value_t = 40)]
    matrix_top: usize,

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
    /// Se combine avec --manifest, --cert, --dating, --enrich, --decompile,
    /// --bundle ou --native.
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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Un --assets-* sans mode actif serait ignoré en silence. Sur un filtre par
    // hash, cela rendrait un inventaire complet en le faisant passer pour le
    // résultat d'un filtrage : l'absence de correspondance se lirait comme une
    // correspondance universelle.
    let assets_mode = cli.list_assets || cli.extract_assets.is_some() || cli.assets_fingerprint;
    let resource_mode = !cli.resource.is_empty()
        || !cli.resource_id.is_empty()
        || cli.resources.is_some()
        || cli.resource_xref
        || cli.resource_orphans;
    let assets_tuning = !cli.assets_include.is_empty()
        || cli.assets_max_size.is_some()
        || !cli.assets_hash.is_empty()
        || cli.assets_hash_file.is_some()
        || !cli.assets_hash_exclude.is_empty()
        || cli.assets_hash_exclude_file.is_some();
    if assets_tuning && !assets_mode {
        bail!(
            "les options --assets-* n'ont d'effet qu'avec --list-assets, \
             --extract-assets <DIR> ou --assets-fingerprint"
        );
    }

    // Même règle pour --native-disasm : un réglage ignoré ferait passer un rapport
    // sans désassemblage pour le résultat demandé.
    if cli.native_disasm && !cli.native {
        bail!("--native-disasm requiert --native : drakkar <APK> --native --native-disasm");
    }
    let disasm_tuning = cli.disasm_depth.is_some() || cli.disasm_max_insns.is_some();
    if (disasm_tuning || cli.disasm_full) && !cli.native_disasm {
        bail!(
            "--disasm-depth, --disasm-max-insns et --disasm-full n'ont d'effet qu'avec \
             --native --native-disasm"
        );
    }
    if cli.disasm_max_insns == Some(0) {
        bail!("--disasm-max-insns doit valoir au moins 1");
    }

    // Sortie rapide : audit d'architecture native seul (pas de moteur de règles,
    // pas de catalogue MITRE) — lit uniquement les en-têtes ELF, en mémoire.
    if cli.native_arch {
        reject_format(
            "--native-arch",
            cli.format,
            "cet audit d'en-têtes ELF n'a pas de forme structurée ; pour un inventaire des \
             binaires natifs, passer par --list-assets (TSV) ou --extract-libs",
        )?;
        let Some(apk) = &cli.apk else {
            bail!("--native-arch requiert un APK (mode single)");
        };
        let summary = parser::native_arch::scan_apk_file(apk)?;
        print_native_arch(&summary);
        return Ok(());
    }

    // Sortie rapide : analyse statique des ELF et liaison JNI avec le DEX. Ni
    // catalogue MITRE ni moteur de règles.
    if cli.native {
        if cli.legend {
            println!("{}", parser::native_static::legend());
            return Ok(());
        }
        if cli.format == Format::Csv {
            bail!("--format csv n'existe pas pour --native : passer --format json ou both");
        }
        if cli.disasm_full && !cli.format.wants_text() {
            bail!(
                "--disasm-full ne concerne que la sortie texte, le JSON porte toujours les \
                 instructions : retirer --disasm-full, ou passer --format text ou both"
            );
        }
        check_json_dest(cli.format, cli.json_out.as_deref())?;
        let Some(apk) = &cli.apk else {
            bail!("--native requiert un APK (mode single)");
        };
        let mut options = parser::native_static::DisasmOptions::default();
        if let Some(depth) = cli.disasm_depth {
            options.depth = depth;
        }
        if let Some(max_insns) = cli.disasm_max_insns {
            options.max_insns = max_insns;
        }
        let disasm = cli.native_disasm.then_some(&options);
        let report = parser::native_static::analyze_apk(apk, disasm)?;
        if cli.format.wants_text() {
            print_native(&report, cli.disasm_full);
        }
        if cli.format.wants_json() {
            emit_json(&report, cli.json_out.as_deref())?;
        }
        return Ok(());
    }

    // Sortie rapide : points d'entrée dynamiques. Ne charge ni le catalogue
    // MITRE ni le moteur de règles — deux passages sur les classes*.dex.
    // Fonctionne en single (APK en argument) comme en bulk (--bulk DIR).
    if cli.dyn_entrypoints {
        reject_format(
            "--dyn-entrypoints",
            cli.format,
            "la sortie est un flux TSV à en-tête, fait pour être filtré ou joint en aval ; \
             pour du JSON sur le graphe d'appel, utiliser --orphan-audit",
        )?;
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
        println!("{DYN_ENTRYPOINTS_HEADER}");
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

            print!("{}", dyn_entrypoints_tsv(&sample, &report));
            eprintln!(
                "[OK]    {sample} — {} resolus ({} classes distinctes), {} non resolus",
                report.entrypoints.len(),
                report.classes().len(),
                report.unresolved.len()
            );
        }
        return Ok(());
    }

    // Sortie rapide : mesure de provenance des cibles de réflexion. Même routage
    // APK/DEX que --dyn-entrypoints, même traitement séquentiel (flux TSV).
    if cli.reflection_inputs {
        reject_format(
            "--reflection-inputs",
            cli.format,
            "la sortie est un TSV déjà agrégé (sample, category, count), à joindre en aval",
        )?;
        let inputs: Vec<PathBuf> = match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => vec![apk.clone()],
            (None, Some(dir)) => {
                let found = parser::dyn_entrypoints::collect_inputs(dir, cli.recursive)?;
                if found.is_empty() {
                    bail!("aucun APK ni DEX trouvé dans {}", dir.display());
                }
                found
            }
            _ => bail!("--reflection-inputs requiert soit un APK ou un DEX, soit --bulk DIR"),
        };

        println!("sample\tcategory\tcount");
        for input in &inputs {
            let sample = input
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());

            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parser::reflection_inputs::extract_any(input)
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

            // Toutes les catégories, y compris à zéro : les colonnes restent
            // comparables d'un échantillon à l'autre.
            for c in parser::reflection_inputs::CATEGORIES {
                println!("{}\t{}\t{}", sample, c.as_str(), report.count(*c));
            }
            eprintln!("[OK]    {sample} — {} sites de réflexion", report.total());
        }
        return Ok(());
    }

    // Sortie rapide : audit d'orphelins. Ne charge pas le catalogue MITRE.
    // Construit le graphe (parse_apk), puis mesure les méthodes hors R(M) à
    // trois étages de racines : manifest -> +dynamiques -> +handlers UI. La
    // courbe de saturation dit ce qui reste vraiment orphelin (le résidu), par
    // opposition à ce qui n'était qu'une racine non semée.
    if cli.orphan_audit {
        // Mode bulk : une ligne CSV (ou JSON) par échantillon = la table de corpus.
        if let Some(dir) = &cli.bulk {
            setup_jobs(cli.jobs)?;
            return bulk::run_orphan_audit(dir, &bulk_options(&cli));
        }
        let Some(apk) = &cli.apk else {
            bail!("--orphan-audit requiert un APK ou un DEX brut (mode single) ou --bulk <DIR>");
        };
        check_json_dest(cli.format, cli.json_out.as_deref())?;

        let parsed = parser::parse_any(apk)?;
        let cg = &parsed.call_graph;
        let roots = bulk::build_orphan_roots(apk, &parsed)?;
        let bulk::OrphanRoots {
            mode,
            base,
            with_dyn,
            with_ui,
            all,
        } = &roots;

        let report = cg.orphan_audit(all, "loadLibrary");

        if cli.format.wants_json() {
            // Le rapport seul ne dit pas sous quel régime il a été mesuré : on
            // l'enveloppe avec le régime et les quatre étages de racines.
            let payload = serde_json::json!({
                "roots_mode": mode.as_str(),
                "roots_manifest": base.len(),
                "roots_dyn": with_dyn.len(),
                "roots_ui": with_ui.len(),
                "roots_clinit": all.len(),
                "report": report,
            });
            emit_json(&payload, cli.json_out.as_deref())?;
        }
        if cli.format.wants_text() {
            let n_manifest = cg.reachable_set(base).len();
            let n_dyn = cg.reachable_set(with_dyn).len();
            let n_ui = cg.reachable_set(with_ui).len();
            println!("== Audit d'orphelins ==\n");
            println!("Nœuds du graphe        {}", report.total_nodes);
            println!(
                "Régime de racines      {}{}",
                mode.as_str(),
                match mode {
                    bulk::RootsMode::Manifest => "",
                    bulk::RootsMode::Heuristic =>
                        "  (pas de composant déclaré : tout callback de cycle de vie \
est racine — ne pas comparer à une mesure `manifest`)",
                }
            );
            // L'étage 1 porte le nom du régime : `manifest=` ou `heuristic=`.
            let l1 = mode.as_str();
            println!(
                "Racines        {l1}={}  +dyn={}  +ui={}  +clinit={}",
                base.len(),
                with_dyn.len(),
                with_ui.len(),
                all.len()
            );
            println!(
                "Atteignables   {l1}={}  +dyn={}  +ui={}  +clinit={}   (orphelins finaux {})",
                n_manifest, n_dyn, n_ui, report.reachable, report.orphan
            );
            println!(
                "\nÎlots orphelins : {} (franchissement en tête, puis taille)",
                report.islands.len()
            );
            for isl in report.islands.iter().take(40) {
                let tag = if isl.touches_crossing {
                    "  ⚠ loadLibrary"
                } else {
                    ""
                };
                let pct = (100 * isl.author_nodes).checked_div(isl.size).unwrap_or(0);
                println!(
                    "  taille {:>5}  {pct:>3}% auteur  {} racine(s) de degré entrant nul{}",
                    isl.size,
                    isl.roots.len(),
                    tag
                );
                if !isl.prefix_histogram.is_empty() {
                    let top: Vec<String> = isl
                        .prefix_histogram
                        .iter()
                        .take(5)
                        .map(|(pkg, n)| format!("{pkg} ({n})"))
                        .collect();
                    let reste = isl.prefix_histogram.len().saturating_sub(5);
                    let suite = if reste > 0 {
                        format!("  … +{reste} préfixes")
                    } else {
                        String::new()
                    };
                    println!("           paquets  {}{}", top.join("   "), suite);
                }
                for r in isl.roots.iter().take(5) {
                    println!("           {r}");
                }
                if isl.roots.len() > 5 {
                    println!("           … +{} autres", isl.roots.len() - 5);
                }
            }
            println!("\n(atteignabilité dirigée ; les orphelins restants après +clinit sont le résidu interprétable)");
        }
        return Ok(());
    }

    // Sortie rapide : sonde d'une API contre le graphe. Même construction de
    // racines que --orphan-audit, mais on interroge une API précise (est-elle un
    // nœud ? atteignable ? par quels chemins ?).
    if let Some(api) = &cli.probe {
        reject_format(
            "--probe",
            cli.format,
            "cette sonde rend un verdict et ses chemins en texte ; pour du JSON sur le graphe, \
             utiliser --orphan-audit --format json",
        )?;
        let Some(apk) = &cli.apk else {
            bail!("--probe requiert un APK ou un DEX brut (mode single)");
        };
        let parsed = parser::parse_any(apk)?;
        let cg = &parsed.call_graph;

        let roots = bulk::build_orphan_roots(apk, &parsed)?;
        let eps = &roots.all;

        let is_node = cg.has_api(api);
        let reach = cg.reachability(api, eps);

        println!("== Sonde : {api} ==\n");
        println!(
            "nœud du graphe   {}",
            if is_node {
                "oui"
            } else {
                "NON (absente du CFG : pas d'arête vers cette API)"
            }
        );
        println!(
            "atteignable      {}",
            if reach.reachable { "oui" } else { "non" }
        );
        println!("racines          {} ({})", eps.len(), roots.mode.as_str());
        if reach.paths.is_empty() {
            println!("\naucun chemin depuis une racine.");
        } else {
            println!("\nchemins ({}) :", reach.paths.len());
            for (i, p) in reach.paths.iter().take(10).enumerate() {
                println!("  [{i}] {}", p.join("  ->  "));
            }
        }
        return Ok(());
    }

    // Sortie rapide : surface d'API déclarée par les annotations. Ne charge ni
    // catalogue MITRE ni moteur de règles, et ne décode AUCUNE instruction :
    // une passe sur les class_def pour lire les annotation_directory_item.
    if cli.api_surface {
        if cli.legend {
            println!("{}", parser::api_surface::legend());
            return Ok(());
        }
        if cli.format == Format::Csv {
            bail!(
                "--format csv n'existe pas pour --api-surface : la sortie texte est déjà un TSV \
                 plat, utiliser text (par défaut) ou json"
            );
        }
        check_json_dest(cli.format, cli.json_out.as_deref())?;

        let inputs: Vec<PathBuf> = match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => vec![apk.clone()],
            (None, Some(dir)) => {
                let found = parser::dyn_entrypoints::collect_inputs(dir, cli.recursive)?;
                if found.is_empty() {
                    bail!("aucun APK ni DEX trouvé dans {}", dir.display());
                }
                found
            }
            _ => bail!("--api-surface requiert soit un APK ou un DEX, soit --bulk DIR"),
        };

        if cli.format.wants_text() {
            println!("sample\tniveau\tclasse\tmembre\tcle\tvaleur\tdetail");
        }
        let mut reports = Vec::new();
        for input in &inputs {
            let sample = input
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());

            // Un DEX malformé peut faire paniquer le crate : on isole pour
            // qu'un échantillon pourri ne tue pas le lot.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                parser::api_surface::scan_any(input)
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

            if cli.format.wants_text() {
                for r in &report.routes {
                    println!(
                        "{}\troute\t{}\t{}\t{}\t{}\t{}",
                        sample,
                        r.class,
                        r.method,
                        r.verb.as_deref().unwrap_or(""),
                        r.path.as_deref().unwrap_or(""),
                        parser::api_surface::route_detail(r)
                    );
                }
                for f in &report.fields {
                    println!(
                        "{}\tchamp\t{}\t{}\tSerializedName\t{}\t{}",
                        sample,
                        f.class,
                        f.field,
                        f.serialized,
                        parser::api_surface::field_detail(f)
                    );
                }
            }

            let s = &report.stats;
            eprintln!(
                "[API]   {sample} — {} classes, {} annotees, {} annotations ; {} routes \
                 ({} sans_gabarit), {} params_seuls, {} params, {} champs ; {} autres, \
                 {} directory_ko, {} orphelines, {} index_hors_plage",
                s.classes,
                s.annotated_classes,
                s.annotations_seen,
                s.routes,
                s.routes_without_path,
                s.params_only_methods,
                s.params_recognized,
                s.serialized_fields,
                s.other_annotations,
                s.directory_failures,
                s.orphan_method_annotations,
                s.param_index_mismatch
            );
            reports.push((sample, report));
        }

        if cli.format.wants_json() {
            // Une entrée par échantillon : le mode bulk et le mode single
            // rendent la même forme, seule la longueur change.
            let json: Vec<_> = reports
                .iter()
                .map(|(sample, r)| serde_json::json!({ "sample": sample, "report": r }))
                .collect();
            emit_json(&json, cli.json_out.as_deref())?;
        }
        return Ok(());
    }

    // Sortie rapide : chaines litterales du pool DEX. Single ou bulk, APK ou DEX.
    if let Some(motifs) = &cli.strings {
        reject_format(
            "--strings",
            cli.format,
            "le pool est un TSV à en-tête (sample, motif, chaine), à joindre en aval ; pour \
             comparer deux pools en JSON, utiliser --diff-strings",
        )?;
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

    // Sortie rapide : table des ressources (resources.arsc) et jointure vers le
    // DEX. Ne charge ni catalogue MITRE ni moteur de règles. Une passe sur
    // l'archive pour la table, une seconde sur les classes*.dex pour la
    // jointure — cette dernière seulement si elle est demandée.
    if resource_mode {
        if cli.legend {
            println!("{}", parser::arsc::legend());
            println!("\n{}", parser::resource_xref::legend());
            return Ok(());
        }
        if cli.format == Format::Csv {
            bail!(
                "--format csv n'existe pas pour les sorties ressources : la table est \
                 déjà plate, utiliser text (TSV, par défaut) ou json"
            );
        }
        check_json_dest(cli.format, cli.json_out.as_deref())?;

        let mode = if cli.resource_xref {
            ResourceOutput::Xref
        } else if cli.resource_orphans {
            ResourceOutput::Orphans
        } else if let Some(types) = &cli.resources {
            ResourceOutput::Dump(types.clone())
        } else {
            ResourceOutput::Lookup {
                names: cli.resource.clone(),
                ids: cli.resource_id.clone(),
            }
        };

        // Un DEX brut n'a pas d'archive, donc pas de resources.arsc : seuls les
        // APK sont recevables ici, contrairement à --strings ou --orphan-audit.
        let (inputs, rejected, bulk_mode) = match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => (vec![apk.clone()], Vec::new(), false),
            (None, Some(dir)) => {
                let found = bulk::collect_apks(dir, cli.recursive)?;
                if found.apks.is_empty() && found.rejected.is_empty() {
                    bail!("aucun APK trouvé dans {}", dir.display());
                }
                (found.apks, found.rejected, true)
            }
            _ => {
                bail!("les options --resource* requièrent soit un APK (single), soit --bulk <DIR>")
            }
        };

        run_resources(
            &inputs,
            &rejected,
            &mode,
            bulk_mode,
            cli.format,
            cli.json_out.as_deref(),
        )?;
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

        if cli.legend {
            println!("{}", parser::diff_explain::legend());
            return Ok(());
        }
        let color = match cli.color.as_str() {
            "auto" => ColorMode::Auto,
            "always" => ColorMode::Always,
            "never" => ColorMode::Never,
            other => bail!("--color attend auto|always|never, reçu {other:?}"),
        };
        check_json_dest(cli.format, cli.json_out.as_deref())?;

        let opts = parser::diff_explain::ExplainOptions {
            include_prefixes: cli.explain_include.clone(),
            normalize: parse_substitutions(&cli.explain_normalize, "--explain-normalize")?,
            color,
            context: cli.explain_context,
            align_cap: cli.explain_align_cap,
            ..Default::default()
        };

        let report = parser::diff_explain::run(&pair[0], &pair[1], &opts)?;
        if cli.format.wants_text() {
            print!("{}", parser::diff_explain::render_report(&report, &opts));
        }
        if cli.format.wants_json() {
            emit_json(&report, cli.json_out.as_deref())?;
        }
        return Ok(());
    }

    // Sortie rapide : matrice de similarité sur un répertoire. Un parsing par
    // échantillon, puis des intersections d'ensembles — c'est ce qui rend le
    // tous-contre-tous tenable sur un corpus entier.
    if let Some(dir) = &cli.diff_matrix {
        use parser::diff_matrix::Metric;

        if cli.legend {
            println!("{}", parser::diff_matrix::legend());
            return Ok(());
        }
        let metric = match cli.matrix_metric.as_str() {
            "opcodes" => Metric::Opcodes,
            "strings" | "chaines" | "chaînes" => Metric::Strings,
            other => bail!("--matrix-metric attend opcodes|strings, reçu {other:?}"),
        };
        check_json_dest(cli.format, cli.json_out.as_deref())?;
        let opts = parser::diff_matrix::MatrixOptions {
            metric,
            normalize: parse_substitutions(&cli.matrix_normalize, "--matrix-normalize")?,
            threshold: cli.matrix_threshold,
            recursive: cli.recursive,
            top: cli.matrix_top,
        };
        let report = parser::diff_matrix::run(dir, &opts)?;
        if cli.format.wants_text() {
            print!("{}", parser::diff_matrix::render(&report, &opts));
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
        reject_format(
            "--disasm",
            cli.format,
            "le désassemblage est du texte, fait pour être lu et diffé tel quel ; pour une \
             comparaison structurée, utiliser --diff-explain (opérandes résolues) ou \
             --diff-dex (empreintes d'opcodes), qui ont tous deux --format json",
        )?;
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

    // Sortie rapide : Java des classes sélectionnées, même sélection que
    // --disasm. Ni catalogue MITRE ni moteur de règles.
    if let Some(patterns) = &cli.decompile {
        if cli.legend {
            println!("{}", parser::decompile::legend());
            return Ok(());
        }
        reject_format(
            "--decompile",
            cli.format,
            "le Java est du texte ; pour une sortie structurée par méthode, utiliser \
             --bundle <OUT>",
        )?;
        let Some(input) = &cli.apk else {
            bail!("--decompile requiert un APK ou un DEX en argument (mode single)");
        };
        let report = parser::decompile::decompile_matching(input, patterns)?;
        print!("{}", parser::decompile::render(&report));
        eprintln!(
            "[OK]    {} classe(s) décompilée(s) sur {} lues, {} en repli méthode par méthode",
            report.classes.len(),
            report.scanned,
            report
                .classes
                .iter()
                .filter(|c| c.fallback.is_some())
                .count()
        );
        return Ok(());
    }

    // Bundle d'un échantillon. Charge le moteur de règles pour rules.json ; une
    // partie en échec n'arrête pas le bundle, elle part dans errors.json.
    if let Some(out) = &cli.bundle {
        if cli.legend {
            println!("{}", parser::decompile::legend());
            return Ok(());
        }
        reject_format(
            "--bundle",
            cli.format,
            "le bundle est une arborescence fixe de fichiers JSON, TSV et texte, décrite par \
             --bundle --legend",
        )?;
        let Some(out) = out else {
            bail!("--bundle requiert un répertoire de sortie : drakkar <APK> --bundle <OUT>");
        };
        let Some(input) = &cli.apk else {
            bail!("--bundle requiert un APK ou un DEX en argument (mode single)");
        };
        setup_jobs(cli.jobs)?;
        return run_bundle(input, out, &cli);
    }

    // Sortie rapide : légende seule (aucun APK requis).
    if cli.legend {
        if cli.cert {
            println!("{}", parser::cert::legend());
        } else if cli.dating {
            println!("{}", parser::dating::legend());
        } else if cli.list_assets || cli.extract_assets.is_some() || cli.assets_fingerprint {
            println!("{}", parser::assets::legend());
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

    // Sortie rapide : inventaire / export des entrées assets/. Ni catalogue MITRE
    // ni moteur de règles — une seule passe sur l'archive. Single ou bulk.
    if assets_mode {
        reject_format(
            "--list-assets / --extract-assets / --assets-fingerprint",
            cli.format,
            "l'inventaire est un TSV à en-tête ; --extract-assets <DIR> écrit déjà un \
             assets.json structuré, plus un assets_index.json global en bulk",
        )?;
        // Les hashes sont validés AVANT toute lecture d'archive : un ensemble de
        // référence mal formé doit échouer tout de suite, pas au bout du lot.
        let hash_filter = parser::assets::build_hash_filter(
            &cli.assets_hash,
            cli.assets_hash_file.as_deref(),
            &cli.assets_hash_exclude,
            cli.assets_hash_exclude_file.as_deref(),
        )?;

        // Refusés plutôt qu'ignorés : l'empreinte porte sur l'ensemble complet
        // et n'honore pas ces filtres. Les accepter en silence laisserait croire
        // qu'elle décrit le sous-ensemble filtré.
        if cli.assets_fingerprint && hash_filter.is_some() {
            bail!(
                "--assets-fingerprint n'honore pas les filtres par hash : l'empreinte \
                 porte toujours sur la totalité des assets. Retirer --assets-hash* ou \
                 passer par --list-assets."
            );
        }
        let opts = parser::assets::AssetsOptions {
            include: cli.assets_include.clone(),
            max_size: cli.assets_max_size,
            hash_filter,
        };
        let (inputs, rejected, bulk_mode) = match (&cli.apk, &cli.bulk) {
            (Some(apk), None) => (vec![apk.clone()], Vec::new(), false),
            (None, Some(dir)) => {
                let found = bulk::collect_apks(dir, cli.recursive)?;
                if found.apks.is_empty() && found.rejected.is_empty() {
                    bail!("aucun APK trouvé dans {}", dir.display());
                }
                (found.apks, found.rejected, true)
            }
            _ => bail!(
                "--list-assets / --extract-assets / --assets-fingerprint requiert \
                 soit un APK (single), soit --bulk <DIR>"
            ),
        };
        let mode = if cli.assets_fingerprint {
            AssetsOutput::Fingerprint
        } else {
            AssetsOutput::Inventory
        };
        run_assets(
            &inputs,
            &rejected,
            &opts,
            cli.extract_assets.as_deref(),
            bulk_mode,
            mode,
        )?;
        return Ok(());
    }

    // Sortie rapide : extraction des .so natifs (lib/ ET hors-lib, ex. Jiagu
    // assets/libjiagu*.so) vers --out. Pas de moteur de règles ni de catalogue.
    if cli.extract_libs {
        reject_format(
            "--extract-libs",
            cli.format,
            "les bibliothèques sont écrites dans --out et récapitulées en texte ; il n'existe \
             pas de forme structurée de ce récapitulatif",
        )?;
        let Some(apk) = &cli.apk else {
            bail!("--extract-libs requiert un APK (mode single)");
        };
        let extraction = parser::native_extract::extract_apk_file(apk)?;
        print_and_dump_extract(&extraction, &cli.out)?;
        return Ok(());
    }

    // Sortie rapide : liste des entrées de l'archive. Rien n'est extrait.
    if cli.list_entries {
        reject_format(
            "--list-entries",
            cli.format,
            "la liste est un chemin par ligne, directement consommable ; pour des tailles, un \
             SHA-256 et un type reniflé, utiliser --list-assets",
        )?;
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
        reject_format(
            "--extract-entry",
            cli.format,
            "les entrées retenues sont écrites dans --out et récapitulées en texte, avec le \
             SHA-256 du contenu décompressé",
        )?;
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

        // ── Mode single : APK, JAR ou DEX brut, reconnu au contenu ──
        (Some(apk), None) => {
            reject_non_json_format(cli.format)?;
            // Pas parse_any : il refuse une archive dont le premier local header
            // est abîmé, que parse_apk ouvre par le lecteur tolérant.
            let parsed = match parser::dyn_entrypoints::sniff(apk) {
                Some(parser::dyn_entrypoints::InputKind::Dex) => parser::parse_dex(apk)?,
                _ => parser::parse_apk(apk)?,
            };
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
        let bits = if l.bits == Bits::B64 {
            "64-bit"
        } else {
            "32-bit"
        };
        let flag = if l.abi_mismatch { "  ⚠ MISMATCH" } else { "" };
        println!(
            "  {:<40} {:<8} {}{}",
            l.entry,
            l.machine.label(),
            bits,
            flag
        );
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

/// Affiche l'analyse native statique (mode `--native`). `full` : instructions
/// désassemblées (`--disasm-full`).
fn print_native(r: &drakkar::parser::native_static::NativeReport, full: bool) {
    println!("== Analyse native statique ==\n");
    println!("APK       {}", r.sha256);
    println!("Légende   drakkar --native --legend");

    if r.elfs.is_empty() {
        println!("\nAucun ELF dans l'APK.");
    }
    for e in &r.elfs {
        print_native_elf(e, full);
    }

    println!("\nLiaison DEX ↔ natif (ELF de lib/ seulement) :");
    if r.binding.is_empty() {
        println!("  (aucune ligne)");
    }
    for b in &r.binding {
        println!("  {:<22} {}", b.status, b.java);
        if let (Some(elf), Some(sha256)) = (&b.elf, &b.elf_sha256) {
            let at = b.fn_offset.as_deref().unwrap_or("-");
            println!("                         {elf}  {sha256}  {at}");
        }
        if !b.candidates.is_empty() {
            let candidates = b.candidates.join(", ");
            println!("                         candidats : {candidates}");
        }
        if let (Some(by), Some(class)) = (b.disambiguated_by, &b.class) {
            println!("                         classe retenue ({by}) : {class}");
        }
    }

    let s = &r.summary;
    println!("\nSynthèse :");
    println!("  ELF                        {}", s.elf_count);
    println!("  méthodes natives du DEX    {}", s.native_methods_declared);
    println!("  static                     {}", s.bound_static);
    println!("  registered                 {}", s.bound_registered);
    println!("  registered_ambiguous       {}", s.ambiguous);
    println!("  declared_unbound           {}", s.unbound);
    println!("  native_unclaimed           {}", s.unclaimed);

    if !r.errors.is_empty() {
        println!("\nNon lu ({}) :", r.errors.len());
        for err in &r.errors {
            println!("  - {err}");
        }
    }
}

fn print_native_elf(e: &drakkar::parser::native_static::ElfReport, full: bool) {
    let abi = e.declared_abi.as_deref().unwrap_or("-");
    let interp = e.interp.as_deref().unwrap_or("-");
    let init = e.init.as_deref().unwrap_or("-");
    let init_array = e.init_array_count;

    let (origin, size) = (e.origin, e.size);
    let (machine, bits, endian) = (&e.machine, e.bits, e.endian);
    let (elf_type, pie, stripped) = (e.elf_type, e.pie, e.stripped);

    println!("\n{}", e.path);
    println!("  sha256        {}", e.sha256);
    println!("  origine       {origin}  abi {abi}  taille {size} o");
    println!("  machine       {machine}  {bits} bits  {endian}");
    println!("  type          {elf_type}  pie {pie}  stripped {stripped}  interp {interp}");
    if !e.needed.is_empty() {
        println!("  needed        {}", e.needed.join(", "));
    }
    if let Some(soname) = &e.soname {
        println!("  soname        {soname}");
    }
    println!("  init          DT_INIT {init}  init_array {init_array}");

    for (category, symbols) in e.imports.categories() {
        if !symbols.is_empty() {
            println!("  import {category:<14} {}", symbols.join(", "));
        }
    }
    let other = e.imports.other_count;
    let exports = e.exports_count;
    println!("  import other         {other}   exports {exports}");

    let jni = &e.jni;
    let onload = jni.jni_onload;
    let hint = jni.registernatives_string;
    let registration = jni.jni_registration;
    println!("  jni           JNI_OnLoad {onload}  RegisterNatives {hint}  {registration}");
    for x in &jni.static_exports {
        let args = x.signature.as_deref().unwrap_or("");
        println!("    {}  →  {}->{}{args}", x.symbol, x.class, x.method);
    }
    for t in &jni.registered {
        let (table, name, sig, at) = (&t.table_offset, &t.name, &t.signature, &t.fn_offset);
        let thumb = if t.thumb { "  thumb" } else { "" };
        println!("    table {table}  {name}{sig}  →  {at}{thumb}");
    }
    for u in &jni.swig_director_upcalls {
        let (table, name, sig) = (&u.table_offset, &u.name, &u.signature);
        println!("    swig  {table}  {name}{sig}  (upcall de director SWIG, pas native)");
    }

    for (category, bucket) in e.strings.categories() {
        if bucket.total == 0 {
            continue;
        }
        let total = bucket.total;
        println!("  chaînes {category:<14} {total}");
        for item in &bucket.items {
            println!("    {item}");
        }
    }

    println!("  sections ({})", e.sections.len());
    for s in &e.sections {
        let (name, size, flags, entropy) = (&s.name, s.size, &s.flags, s.entropy);
        println!("    {name:<24} {size:>10} {flags:<3} {entropy:.3}");
    }
    println!("  segments ({})", e.segments.len());
    for s in &e.segments {
        let (kind, flags, vaddr, size) = (&s.kind, &s.flags, &s.vaddr, s.size);
        println!("    {kind:<14} {flags} {vaddr:>12} {size:>10}");
    }

    if let Some(d) = &e.disasm {
        print_native_disasm(d, full);
    }

    if !e.anomalies.is_empty() {
        println!("  anomalies");
        for a in &e.anomalies {
            println!("    - {a}");
        }
    }
}

/// Un bloc par fonction désassemblée (`--native-disasm`), puis la synthèse de
/// l'ELF.
fn print_native_disasm(d: &drakkar::parser::native_static::ElfDisasm, full: bool) {
    println!("  désassemblage ({} fonctions)", d.functions.len());
    for f in &d.functions {
        let (address, origin, status) = (&f.address, f.origin, f.disasm_status);
        let count = f.instructions.len();
        println!("    {address}  {origin}  {status}  {count} instructions");
        if let Some(reason) = f.truncated_reason {
            println!("      tronquée : {reason}");
        }
        for c in &f.calls {
            let (kind, target) = (c.kind, c.target.as_deref().unwrap_or("?"));
            let name = match (&c.import, &c.symbol) {
                (Some(name), _) | (None, Some(name)) => name.as_str(),
                (None, None) => "",
            };
            println!("      call     {kind:<9} {target}  {name}");
        }
        for j in &f.jni_calls {
            let (name, index, form) = (j.name, j.index, j.form);
            let class = j.class.as_deref().unwrap_or("");
            let method = j.method.as_deref().unwrap_or("");
            let signature = j.signature.as_deref().unwrap_or("");
            let reason = match j.unresolved_reason {
                Some(reason) => format!("  ({reason})"),
                None => String::new(),
            };
            println!("      jni      {name} #{index} {form}  {class} {method}{signature}{reason}");
        }
        for s in &f.string_refs {
            let (address, target, value) = (&s.address, &s.target, &s.value);
            println!("      chaîne   {address}  {target}  {value}");
        }
        for s in &f.syscalls {
            let number = s.number.map_or_else(|| "?".to_string(), |n| n.to_string());
            println!("      syscall  {}  {number}", s.address);
        }
        if full {
            for i in &f.instructions {
                let (address, bytes) = (&i.address, &i.bytes);
                let (mnemonic, operands) = (&i.mnemonic, &i.operands);
                println!("      {address}  {bytes:<20} {mnemonic} {operands}");
            }
        }
    }
    for m in &d.upcalls {
        let (class, name, signature) = (&m.class, &m.name, &m.signature);
        println!("    upcall           {class}->{name}{signature}");
    }
    for m in &d.registered_by_code {
        let (class, name, signature) = (&m.class, &m.name, &m.signature);
        println!("    RegisterNatives  {class}->{name}{signature}");
    }
    for (category, names) in &d.imports_called {
        let names = names.join(", ");
        println!("    import appelé {category:<14} {names}");
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

    for name in &ex.unreadable {
        println!("[FAIL]  {name}  — illisible, y compris par le lecteur ZIP tolérant");
    }

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

    std::fs::create_dir_all(out_dir).with_context(|| format!("création {}", out_dir.display()))?;

    println!("Libs extraites ({}) -> {} :", ex.count(), out_dir.display());
    for l in &ex.libs {
        let bits = if l.arch.bits == Bits::B64 {
            "64-bit"
        } else {
            "32-bit"
        };
        let flag = if l.out_of_lib() {
            "  ⚠ HORS lib/ (packer)"
        } else {
            ""
        };
        // nom de sortie aplati : lib/arm64-v8a/foo.so -> lib__arm64-v8a__foo.so
        let flat = l.entry.replace('/', "__");
        let dest = out_dir.join(&flat);
        std::fs::write(&dest, &l.bytes).with_context(|| format!("écriture {}", dest.display()))?;
        println!(
            "  {:<38} {:<8} {:<7} {:>9} o  {}  -> {}{}",
            l.entry,
            l.arch.machine.label(),
            bits,
            l.bytes.len(),
            l.sha256,
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

/// Refus explicite de `--format` pour un mode dont la seule sortie est du texte.
/// Un format accepté puis ignoré produit un `.json` qui n'en est pas un, sans
/// que rien ne le signale. Ce qu'il faut faire à la place dépend du mode, d'où
/// `instead` : c'est lui qui porte l'information utile.
fn reject_format(mode: &str, format: Format, instead: &str) -> Result<()> {
    if format != Format::Text {
        bail!(
            "{mode} n'a qu'une sortie texte : --format y est sans effet, donc refusé plutôt \
             qu'ignoré. Retirer --format, ou passer --format text ; {instead}"
        );
    }
    Ok(())
}

/// Le pipeline par défaut ne sait rendre que du JSON. `--format text` n'est pas
/// refusé ici : il est indistinguable du défaut global, que clap applique avant
/// qu'on lise `cli.format`, donc le refuser rejetterait une invocation qui n'a
/// pas passé `--format` du tout. Seules les valeurs qui ne peuvent pas être ce
/// défaut sont refusées.
fn reject_non_json_format(format: Format) -> Result<()> {
    if matches!(format, Format::Both | Format::Csv) {
        bail!(
            "le pipeline par défaut ne rend que du JSON : --format both et \
             --format csv y sont sans effet, donc refusés plutôt qu'ignorés. \
             Passer --format json, ou rien ; pour une synthèse CSV d'un lot, \
             utiliser --bulk <DIR> --format csv"
        );
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
            std::fs::write(path, json).with_context(|| format!("écriture {}", path.display()))?;
            eprintln!("JSON écrit dans {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// En-tête et lignes de `--dyn-entrypoints`, partagés avec `--bundle`.
const DYN_ENTRYPOINTS_HEADER: &str = "sample\torigine\tclasse\tsink\toffset\tappelant\tdetail";

fn dyn_entrypoints_tsv(
    sample: &str,
    report: &drakkar::parser::dyn_entrypoints::DynEntrypointReport,
) -> String {
    let mut out = String::new();
    for e in &report.entrypoints {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t+{}\t{}\t\n",
            sample,
            e.provenance.as_str(),
            e.class,
            e.via,
            e.site,
            e.caller.api()
        ));
    }
    for u in &report.unresolved {
        out.push_str(&format!(
            "{}\t?\t\t{}\t+{}\t{}\t{} {} {}\n",
            sample,
            u.via,
            u.site,
            u.caller.api(),
            u.reason.as_str(),
            u.target_reg
                .map(|r| format!("v{r}"))
                .unwrap_or_else(|| "-".into()),
            u.blocking_insn.as_deref().unwrap_or("-")
        ));
    }
    out
}

/// Mode `--bundle` : `out/<sha256>/`, arborescence définie par
/// `--bundle --legend`.
fn run_bundle(input: &std::path::Path, out: &std::path::Path, cli: &Cli) -> Result<()> {
    use parser::decompile::{self, BundleError, BundleInfo};
    use parser::dyn_entrypoints::InputKind;
    use parser::{cert, dating, manifest_info};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let generated_at = cert::fmt_unix_utc(now);

    let src = decompile::open(input)?;
    let root = out.join(&src.sha256);
    if root.exists() {
        if !cli.overwrite {
            bail!(
                "{} existe déjà — --overwrite pour le remplacer",
                root.display()
            );
        }
        std::fs::remove_dir_all(&root)
            .with_context(|| format!("suppression {}", root.display()))?;
    }
    let classes_dir = root.join("classes");
    std::fs::create_dir_all(&classes_dir)
        .with_context(|| format!("création {}", classes_dir.display()))?;

    let decompiled = decompile::decompile_all(&src, &classes_dir);
    let mut errors = Vec::new();
    let apk = src.kind == InputKind::Apk;

    let manifest = if apk {
        bundle_part("manifest", &mut errors, || manifest_info::extract(input))
    } else {
        None
    };
    write_bundle_json(&root, "manifest.json", &manifest)?;
    let signing = if apk {
        bundle_part("cert", &mut errors, || cert::extract(input))
    } else {
        None
    };
    write_bundle_json(&root, "cert.json", &signing)?;
    let datation = if apk {
        bundle_part("dating", &mut errors, || dating::extract(input))
    } else {
        None
    };
    write_bundle_json(&root, "dating.json", &datation)?;

    let engine = match &cli.rules {
        Some(dir) => Engine::load(dir),
        None => Engine::load_cached(cli.refresh),
    };
    let matches = match engine {
        Ok(engine) => bundle_part("rules", &mut errors, || {
            let parsed = parser::parse_any(input)?;
            Ok(engine.run(&parsed.features, &parsed.call_graph))
        }),
        Err(e) => {
            errors.push(BundleError::new("rules", format!("{e:#}")));
            None
        }
    };
    write_bundle_json(&root, "rules.json", &matches)?;

    let mut tsv = format!("{DYN_ENTRYPOINTS_HEADER}\n");
    let dyn_report = bundle_part("dyn_entrypoints", &mut errors, || {
        parser::dyn_entrypoints::extract_any(input)
    });
    if let Some(report) = &dyn_report {
        tsv.push_str(&dyn_entrypoints_tsv(&src.sha256, report));
    }
    write_bundle_file(&root.join("dyn_entrypoints.tsv"), &tsv)?;

    let (pool, pool_errors) = decompile::string_pools(&src);
    errors.extend(pool_errors);
    let strings = serde_json::json!({
        "pool": pool,
        "static_values": decompiled.static_values,
    });
    write_bundle_json(&root, "strings.json", &strings)?;

    let citations = rule_citations(matches.as_deref().unwrap_or(&[]));
    let mut index = decompiled.classes;
    for class in &mut index {
        if let Some(c) = class.descriptor.as_deref().and_then(|d| citations.get(d)) {
            class.rules_direct = c.direct.clone();
            class.rules_path = c.path.clone();
        }
    }
    write_bundle_json(&root, "index.json", &index)?;

    let info = BundleInfo::new(&src, &decompiled.stats, generated_at);
    write_bundle_json(&root, "bundle.json", &info)?;

    let mut all_errors = decompiled.errors;
    all_errors.extend(errors);
    write_bundle_json(&root, "errors.json", &all_errors)?;

    let s = &decompiled.stats;
    eprintln!(
        "[OK]    {} — {} classes, {} méthodes (ok {}, partial {}, failed {}), {} erreur(s)",
        root.display(),
        s.classes,
        s.methods,
        s.decompile_ok,
        s.decompile_partial,
        s.decompile_failed,
        all_errors.len()
    );
    Ok(())
}

/// Une partie du bundle : en cas d'échec, `None` et une entrée d'erreur, pas
/// un abandon.
fn bundle_part<T>(
    stage: &'static str,
    errors: &mut Vec<parser::decompile::BundleError>,
    run: impl FnOnce() -> Result<T>,
) -> Option<T> {
    use parser::decompile::{panic_message, BundleError};
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            errors.push(BundleError::new(stage, format!("{e:#}")));
            None
        }
        Err(p) => {
            errors.push(BundleError::new(stage, panic_message(&*p)));
            None
        }
    }
}

fn write_bundle_json<T: serde::Serialize>(
    root: &std::path::Path,
    name: &str,
    value: &T,
) -> Result<()> {
    write_bundle_file(&root.join(name), &serde_json::to_string_pretty(value)?)
}

fn write_bundle_file(path: &std::path::Path, body: &str) -> Result<()> {
    std::fs::write(path, body).with_context(|| format!("écriture {}", path.display()))
}

/// Règles qui citent une classe, dans l'ordre de `rules.json`.
#[derive(Debug, Default)]
struct Citations {
    direct: Vec<String>,
    path: Vec<String>,
}

/// Descripteur de classe → règles qui le citent. Directe : descripteur dans
/// `evidence.value`, ou propriétaire de l'avant-dernier nœud d'un chemin (le
/// dernier est l'API, cf. `CallGraph::bfs_path`). Par chemin : propriétaire de
/// tout autre nœud.
fn rule_citations(
    matches: &[drakkar::rules::Match],
) -> std::collections::HashMap<String, Citations> {
    let mut out: std::collections::HashMap<String, Citations> = Default::default();
    for m in matches {
        let mut direct = std::collections::HashSet::new();
        let mut traversed = std::collections::HashSet::new();
        for e in &m.evidence {
            direct.extend(cited_descriptors(&e.value));
            for path in &e.paths {
                if let [.., caller, _api] = path.as_slice() {
                    direct.extend(node_owner(caller));
                }
                traversed.extend(path.iter().filter_map(|n| node_owner(n)));
            }
        }
        for d in &direct {
            let c = out.entry(d.to_string()).or_default();
            c.direct.push(m.id.clone());
        }
        for d in traversed.difference(&direct) {
            let c = out.entry(d.to_string()).or_default();
            c.path.push(m.id.clone());
        }
    }
    out
}

/// `Lowner;` d'un nœud de chemin `Lowner;->nom(desc)ret`.
fn node_owner(node: &str) -> Option<&str> {
    node.split_once("->").map(|(owner, _)| owner)
}

/// Descripteurs de classe complets (`L…;`) qui figurent dans `s`. Un `L`
/// collé à un caractère de nom (`Lx/Lcom/a;`) n'ouvre pas de descripteur.
fn cited_descriptors(s: &str) -> impl Iterator<Item = &str> {
    let bytes = s.as_bytes();
    (0..bytes.len()).filter_map(move |i| {
        if bytes[i] != b'L' || (i > 0 && is_name_byte(bytes[i - 1])) {
            return None;
        }
        let end = i + s[i..].find(';')?;
        Some(&s[i..=end])
    })
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'/') || b >= 0x80
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

    println!("\nPermissions requises ({}) :", r.uses_permissions.len());
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
        "\n  {:<16} {:<58} {:<9} PERMISSION",
        "TYPE", "CLASSE", "EXPORTED"
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
            d.api_floor
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".into()),
            d.string_count
        );
    }
    println!(
        "  plancher retenu        {}",
        r.toolchain_floor_api
            .map(|a| format!("API {a}"))
            .unwrap_or_else(|| "indisponible".into())
    );

    println!(
        "\nHorodatages de l'archive ({} entrées) :",
        r.archive.entry_count
    );
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
        println!(
            "\nVersions de bibliothèques ({}) :",
            r.library_versions.len()
        );
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
        println!(
            "\nLittéraux de date dans le code ({}) :",
            r.code_dates.len()
        );
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

    println!(
        "\nAppariement par classe (seuil proche = {:.2}) :",
        r.threshold
    );
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

    println!("\nValeurs de champs statiques (encoded_static_values, hors instructions) :");
    println!(
        "  comparées    {}   divergentes {}",
        r.static_fields_compared, r.static_fields_diverging
    );
    if r.static_fields_diverging > 0 {
        println!("               /!\\ une valeur statique divergente est INVISIBLE aux empreintes");
        println!("                   d'opcodes : les Jaccard ci-dessus ne la voient pas. Détail :");
        println!(
            "                   --diff-explain (catégorie valeur-statique) sur le même couple,"
        );
        println!("                   contre-épreuve : --diff-strings.");
    }

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

    println!(
        "\n(le détail des classes identiques est dans le JSON ; légende : --diff-dex --legend)"
    );
}

/// Ce que la passe assets émet sur stdout. Les deux formes sont disjointes :
/// l'en-tête TSV doit décrire exactement les colonnes produites.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AssetsOutput {
    /// Inventaire par asset (`--list-assets`, `--extract-assets`).
    Inventory,
    /// Empreinte d'ensemble par échantillon (`--assets-fingerprint`).
    Fingerprint,
}

/// Inventaire (`--list-assets`) ou export (`--extract-assets`) des assets.
///
/// stdout ne porte que le TSV, dont l'en-tête décrit exactement les colonnes
/// émises ; tout le reste — résumé, empreinte d'ensemble, entrées écartées,
/// échantillons illisibles — part sur stderr, pour que `| awk` et `> fichier`
/// restent utilisables.
fn run_assets(
    inputs: &[PathBuf],
    rejected: &[(PathBuf, String)],
    opts: &drakkar::parser::assets::AssetsOptions,
    out: Option<&std::path::Path>,
    bulk_mode: bool,
    mode: AssetsOutput,
) -> Result<()> {
    use drakkar::parser::assets;

    let mut index = assets::BulkIndex::default();

    // Sous filtre par hash, la sortie devient le pivot étroit : seule l'identité
    // compte quand on cherche qui porte une charge connue. La colonne `sample`
    // y est toujours présente, c'est l'axe du croisement.
    let narrow = opts.hash_filter.is_some();
    let shape = assets::TsvShape {
        sample: bulk_mode || narrow,
        written: out.is_some(),
        narrow,
    };

    // B4 : une entrée écartée pour la taille n'est jamais hachée, donc jamais
    // testée. Sans cet avertissement et le compteur final, l'absence de
    // correspondance se lirait comme l'absence de l'asset.
    if narrow && opts.max_size.is_some() {
        eprintln!(
            "[AVERT] --assets-max-size est actif avec un filtre par hash : les entrées \
             au-delà du plafond ne sont pas hachées, donc jamais testées. Leur nombre \
             est récapitulé en fin de passe."
        );
    }
    if narrow && !opts.include.is_empty() {
        eprintln!(
            "[AVERT] --assets-include restreint le jeu testé par le filtre par hash : \
             un asset hors motif ne sera pas signalé absent, il n'aura pas été examiné."
        );
    }

    let mut total_not_evaluated = 0usize;

    // Un fichier à signature ZIP dont aucun lecteur n'a tiré de manifest est
    // nommé, pas écarté en silence : sur un corpus nommé par hachage, une
    // disparition muette est indiscernable d'une absence.
    for (path, why) in rejected {
        eprintln!(
            "[FAIL]  {}  — non reconnu comme APK : {why}",
            path.display()
        );
        index.failed.push(assets::FailedSample {
            sample: stem_of(path),
            path: path.display().to_string(),
            reason: format!("non reconnu comme APK : {why}"),
        });
    }

    match mode {
        AssetsOutput::Fingerprint => println!("{}", assets::fingerprint_tsv_header()),
        AssetsOutput::Inventory => println!("{}", assets::tsv_header(shape)),
    }

    for apk in inputs {
        let sample = stem_of(apk);

        // Une archive pourrie peut faire paniquer un décodeur : on isole pour
        // qu'elle ne tue pas le lot.
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assets::collect(apk, opts)));
        let mut report = match outcome {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                eprintln!("[FAIL]  {sample} — {e:#}");
                index.failed.push(assets::FailedSample {
                    sample,
                    path: apk.display().to_string(),
                    reason: format!("{e:#}"),
                });
                continue;
            }
            Err(_) => {
                eprintln!("[PANIC] {sample} — inventaire abandonné");
                index.failed.push(assets::FailedSample {
                    sample,
                    path: apk.display().to_string(),
                    reason: "panique pendant la lecture de l'archive".into(),
                });
                continue;
            }
        };

        // En bulk, un sous-répertoire par échantillon ; en single, le DIR demandé.
        let dest = out.map(|d| {
            if bulk_mode {
                d.join(&sample)
            } else {
                d.to_path_buf()
            }
        });
        if let Some(dir) = &dest {
            match assets::write_all(&mut report, dir) {
                Ok(json) => eprintln!("[JSON]  {sample} — {}", json.display()),
                Err(e) => {
                    eprintln!("[FAIL]  {sample} — écriture : {e:#}");
                    index.failed.push(assets::FailedSample {
                        sample: sample.clone(),
                        path: apk.display().to_string(),
                        reason: format!("écriture : {e:#}"),
                    });
                    continue;
                }
            }
        }

        total_not_evaluated += report.not_evaluated;

        match mode {
            AssetsOutput::Fingerprint => {
                println!("{}", assets::fingerprint_tsv_row(&sample, &report));
            }
            AssetsOutput::Inventory => {
                for e in &report.entries {
                    println!(
                        "{}",
                        assets::tsv_row(e, shape.sample.then_some(sample.as_str()), shape)
                    );
                }
            }
        }
        for sk in &report.skipped {
            eprintln!("[SKIP]  {sample} — {} : {}", sk.entry, sk.reason);
        }

        // L'empreinte d'ensemble est l'axe de regroupement. L'absence d'assets
        // est dite en toutes lettres : sortir l'empreinte de la chaîne vide
        // ferait un faux cluster de tous les APK sans assets.
        let fp = match &report.fingerprint {
            Some(f) => format!("empreinte {f}"),
            None => format!("PAS D'EMPREINTE ({})", report.fingerprint_status),
        };
        eprintln!(
            "[OK]    {sample} — {} asset(s) retenu(s) sur {} vus ({} entrées, lecteur {}), \
             {} illisible(s), {} non évaluée(s), {fp}",
            report.count(),
            report.assets_seen,
            report.scanned,
            report.reader.as_str(),
            report.skipped.len(),
            report.not_evaluated
        );

        index.samples.push(assets::BulkSample {
            sample,
            path: apk.display().to_string(),
            apk_sha256: report.apk_sha256.clone(),
            reader: report.reader,
            assets: report.count(),
            skipped: report.skipped.len(),
            not_evaluated: report.not_evaluated,
            fingerprint: report.fingerprint.clone(),
            fingerprint_status: report.fingerprint_status.clone(),
            out_dir: dest.map(|d| d.display().to_string()),
        });
    }

    // L'index global n'a de sens que là où quelque chose est écrit : --list-assets
    // n'écrit rien, par construction.
    if bulk_mode {
        if let Some(dir) = out {
            let path = index.write(dir)?;
            eprintln!("[INDEX] {}", path.display());
        }
    }

    if narrow && total_not_evaluated > 0 {
        eprintln!(
            "[AVERT] {total_not_evaluated} entrée(s) non évaluée(s) sur l'ensemble du lot : \
             jamais hachées, donc jamais confrontées au filtre. Une absence de \
             correspondance ne vaut PAS absence de l'asset — relancer sans \
             --assets-max-size pour trancher."
        );
    }

    eprintln!(
        "[FIN]   {} échantillon(s) inventorié(s), {} en échec, {} entrée(s) non évaluée(s)",
        index.samples.len(),
        index.failed.len(),
        total_not_evaluated
    );
    Ok(())
}

/// Ce que la passe ressources émet. Les formes sont disjointes : l'en-tête TSV
/// doit décrire exactement les colonnes produites.
enum ResourceOutput {
    /// `--resource` et/ou `--resource-id` : résolution ciblée.
    Lookup {
        names: Vec<String>,
        ids: Vec<String>,
    },
    /// `--resources [TYPE…]` : dump, filtrable par type.
    Dump(Vec<String>),
    /// `--resource-xref` : une ligne par usage depuis le code.
    Xref,
    /// `--resource-orphans` : entrées qu'aucune constante du DEX ne cite.
    Orphans,
}

/// Lecture de `resources.arsc`, résolutions et jointure vers le DEX.
///
/// stdout ne porte que le TSV (ou le JSON) ; résumés, anomalies de parsing,
/// correspondances manquantes et échantillons illisibles partent sur stderr,
/// pour que `| awk` et `> fichier` restent utilisables.
fn run_resources(
    inputs: &[PathBuf],
    rejected: &[(PathBuf, String)],
    mode: &ResourceOutput,
    bulk_mode: bool,
    format: Format,
    json_out: Option<&std::path::Path>,
) -> Result<()> {
    use drakkar::parser::{arsc, resource_xref};

    let needs_xref = matches!(mode, ResourceOutput::Xref | ResourceOutput::Orphans);
    let mut payloads: Vec<serde_json::Value> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut emitted = 0usize;

    if format.wants_text() {
        match mode {
            ResourceOutput::Xref => println!(
                "sample\tclasse\tmethode\toffset\tid\ttype\tnom\tvaleur\torigine\tconsommateur"
            ),
            _ => println!("sample\ttype\tnom\tid\tvaleur"),
        }
    }

    // Un fichier à signature ZIP dont aucun lecteur n'a tiré de manifest est
    // nommé, pas écarté en silence.
    for (path, why) in rejected {
        eprintln!(
            "[FAIL]  {}  — non reconnu comme APK : {why}",
            path.display()
        );
        failures.push(format!(
            "{} : non reconnu comme APK : {why}",
            path.display()
        ));
    }

    for apk in inputs {
        let sample = stem_of(apk);

        // Une table trafiquée peut faire paniquer un décodeur : on isole pour
        // qu'un échantillon ne tue pas le lot.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let table = arsc::extract(apk)?;
            let xref = if needs_xref {
                Some(resource_xref::scan(apk, &table)?)
            } else {
                None
            };
            Ok::<_, anyhow::Error>((table, xref))
        }));
        let (table, xref) = match outcome {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                eprintln!("[FAIL]  {sample} — {e:#}");
                failures.push(format!("{sample} : {e:#}"));
                continue;
            }
            Err(_) => {
                eprintln!("[PANIC] {sample} — lecture des ressources abandonnée");
                failures.push(format!(
                    "{sample} : panique pendant la lecture des ressources"
                ));
                continue;
            }
        };

        for a in &table.anomalies {
            eprintln!("[NOTE]  {sample} — {a}");
        }
        let packages: Vec<String> = table
            .packages
            .iter()
            .map(|p| {
                format!(
                    "{:#04x}={}",
                    p.id,
                    if p.name.is_empty() {
                        "?"
                    } else {
                        p.name.as_str()
                    }
                )
            })
            .collect();

        if let Some(xref) = &xref {
            let st = &xref.stats;
            eprintln!(
                "[XREF]  {sample} — entiers {} -> candidats {} -> retenus {} | rejetes {} \
                 ({:.1}% des candidats, {} valeurs distinctes) | sget {} (sur {} champs R \
                 indexes) | defs_R {} | corrobores {} ({:.1}%) -> faux positifs residuels \
                 <= {:.1}%",
                st.integers,
                st.candidates,
                st.matched,
                st.rejected,
                st.rejection_rate(),
                st.distinct_rejected,
                st.via_static_field,
                st.static_fields_indexed,
                st.r_class_defs,
                st.corroborated,
                st.corroboration_rate(),
                st.residual_fp_bound()
            );
        }

        // Sélection des entrées à émettre, selon le mode.
        let mut selected: Vec<&arsc::ResourceEntry> = Vec::new();
        match mode {
            ResourceOutput::Lookup { names, ids } => {
                let mut seen = std::collections::HashSet::new();
                for name in names {
                    let hits = table.by_name(name);
                    if hits.is_empty() {
                        eprintln!("[MISS]  {sample} — nom absent de la table : {name}");
                    }
                    for e in hits {
                        if seen.insert(e.id) {
                            selected.push(e);
                        }
                    }
                }
                for spec in ids {
                    let candidates = arsc::parse_id_candidates(spec);
                    match candidates.iter().find_map(|id| table.by_id(*id)) {
                        Some(e) => {
                            if seen.insert(e.id) {
                                selected.push(e);
                            }
                        }
                        None => eprintln!(
                            "[MISS]  {sample} — identifiant absent de la table : {spec} \
                             (lu comme {})",
                            candidates
                                .iter()
                                .map(|v| format!("{v:#010x}"))
                                .collect::<Vec<_>>()
                                .join(" ou ")
                        ),
                    }
                }
            }
            ResourceOutput::Dump(types) => {
                let wanted: Vec<String> = types.iter().map(|t| t.to_lowercase()).collect();
                selected = table
                    .entries
                    .iter()
                    .filter(|e| wanted.is_empty() || wanted.contains(&e.type_name.to_lowercase()))
                    .collect();
                if !wanted.is_empty() && selected.is_empty() {
                    eprintln!(
                        "[MISS]  {sample} — aucun type parmi {} ; types presents : {}",
                        wanted.join(", "),
                        table.type_names().join(", ")
                    );
                }
            }
            ResourceOutput::Orphans => {
                if let Some(x) = &xref {
                    selected = resource_xref::orphans(&table, x);
                }
            }
            ResourceOutput::Xref => {}
        }

        if format.wants_text() {
            match (mode, &xref) {
                (ResourceOutput::Xref, Some(x)) => {
                    for u in &x.uses {
                        println!(
                            "{}\t{}\t{}\t+{}\t{}\t{}\t{}\t{}\t{}\t{}",
                            sample,
                            u.class,
                            u.method,
                            u.site,
                            u.id_hex(),
                            u.type_name,
                            u.name,
                            u.value_tsv(),
                            u.origin.as_str(),
                            u.consumer.as_deref().unwrap_or("")
                        );
                    }
                }
                _ => {
                    for e in &selected {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            sample,
                            e.type_name,
                            e.name,
                            e.id_hex(),
                            e.value_tsv()
                        );
                    }
                }
            }
        }

        if format.wants_json() {
            let mut payload = serde_json::json!({
                "sample": sample,
                "path": apk.display().to_string(),
                "packages": table.packages,
                "entries_total": table.entries.len(),
                "global_strings": table.global_strings,
                "anomalies": table.anomalies,
            });
            match (mode, &xref) {
                (ResourceOutput::Xref, Some(x)) => {
                    payload["stats"] = serde_json::to_value(&x.stats)?;
                    payload["uses"] = serde_json::to_value(&x.uses)?;
                }
                (ResourceOutput::Orphans, Some(x)) => {
                    payload["stats"] = serde_json::to_value(&x.stats)?;
                    payload["orphans"] = serde_json::to_value(&selected)?;
                }
                _ => payload["entries"] = serde_json::to_value(&selected)?,
            }
            payloads.push(payload);
        }

        let lines = match (mode, &xref) {
            (ResourceOutput::Xref, Some(x)) => x.uses.len(),
            _ => selected.len(),
        };
        emitted += lines;
        eprintln!(
            "[OK]    {sample} — {lines} ligne(s) sur {} entree(s), package(s) {}, \
             {} chaine(s) au pool global{}",
            table.entries.len(),
            packages.join(" "),
            table.global_strings,
            match mode {
                ResourceOutput::Orphans => format!(
                    ", soit {:.1}% de la table non referencee depuis le code",
                    if table.entries.is_empty() {
                        0.0
                    } else {
                        100.0 * lines as f64 / table.entries.len() as f64
                    }
                ),
                _ => String::new(),
            }
        );
    }

    if format.wants_json() {
        // En single, l'objet seul : `| jq .entries` doit marcher sans indexer
        // un tableau d'un élément.
        if bulk_mode {
            emit_json(&payloads, json_out)?;
        } else if let Some(p) = payloads.first() {
            emit_json(p, json_out)?;
        }
    }

    if matches!(mode, ResourceOutput::Orphans) {
        eprintln!(
            "[AVERT] « orpheline » veut dire NON REFERENCEE DEPUIS LE CODE, pas « inutilisee » : \
             une ressource citee par un layout, un style, un theme ou le manifeste sort ici. \
             Voir --resource-orphans --legend pour l'angle mort des APK non minifies."
        );
    }

    eprintln!(
        "[FIN]   {} echantillon(s) candidat(s), {} en echec, {emitted} ligne(s) emise(s)",
        inputs.len() + rejected.len(),
        failures.len()
    );

    // En single, un echec est l'echec de la commande : code de retour non nul.
    if !bulk_mode {
        if let Some(why) = failures.first() {
            bail!("{why}");
        }
    }
    Ok(())
}

/// Nom de base d'un échantillon, sans extension. Les corpus nommés par hachage
/// n'en ont pas, d'où le repli.
fn stem_of(p: &std::path::Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into())
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
    println!(
        "Entrées  : {} retenue(s) sur {} dans l'archive",
        ex.count(),
        ex.scanned
    );
    for name in &ex.unreadable {
        println!("[FAIL]   {name}  — illisible, y compris par le lecteur ZIP tolérant");
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // --- #9 : `--format both` exige une destination fichier ---

    #[test]
    fn both_without_json_out_is_refused() {
        assert!(check_json_dest(Format::Both, None).is_err());
    }

    #[test]
    fn both_with_json_out_is_accepted() {
        assert!(check_json_dest(Format::Both, Some(Path::new("/tmp/report.json"))).is_ok());
    }

    #[test]
    fn the_other_formats_need_no_destination() {
        for format in [Format::Text, Format::Json, Format::Csv] {
            assert!(check_json_dest(format, None).is_ok(), "{format:?}");
        }
    }

    // --- #10, #12 : un mode sans JSON refuse `--format` au lieu de l'ignorer ---

    #[test]
    fn a_text_only_mode_accepts_only_text() {
        assert!(reject_format("--disasm", Format::Text, "voir --diff-dex").is_ok());
        for format in [Format::Json, Format::Both, Format::Csv] {
            assert!(
                reject_format("--disasm", format, "voir --diff-dex").is_err(),
                "{format:?}"
            );
        }
    }

    #[test]
    fn the_refusal_names_the_mode_and_what_to_use_instead() {
        let message = reject_format("--disasm", Format::Json, "utiliser --diff-explain")
            .unwrap_err()
            .to_string();
        assert!(message.contains("--disasm"), "{message}");
        assert!(message.contains("--format text"), "{message}");
        assert!(message.contains("utiliser --diff-explain"), "{message}");
    }

    // --- #13 : le pipeline par défaut refuse ce qu'il ne sait pas rendre ---

    #[test]
    fn the_default_pipeline_refuses_both_and_csv() {
        assert!(reject_non_json_format(Format::Both).is_err());
        assert!(reject_non_json_format(Format::Csv).is_err());
    }

    /// `text` doit passer : il est indistinguable du défaut global, donc le
    /// refuser rejetterait `drakkar sample.apk`, qui n'a pas passé --format.
    #[test]
    fn the_default_pipeline_still_accepts_the_global_default() {
        assert!(reject_non_json_format(Format::Text).is_ok());
        assert!(reject_non_json_format(Format::Json).is_ok());
    }

    // --- --bundle : une preuve cite une classe par son descripteur entier ---

    #[test]
    fn a_descriptor_is_cited_only_as_a_whole_token() {
        let cited: Vec<&str> = cited_descriptors("Lcom/a/B;->run").collect();
        assert_eq!(cited, ["Lcom/a/B;"]);
        let cited: Vec<&str> = cited_descriptors("(Lcom/a/B;[Lx/Y;)V").collect();
        assert_eq!(cited, ["Lcom/a/B;", "Lx/Y;"]);
        assert_eq!(cited_descriptors("Lx/Lcom/a/B;").count(), 1);
    }

    #[test]
    fn the_immediate_caller_is_direct_and_the_rest_of_the_path_is_not() {
        let m = drakkar::rules::Match {
            id: "R1".into(),
            name: String::new(),
            tactic: String::new(),
            evidence: vec![drakkar::rules::Evidence {
                kind: "api".into(),
                value: "Landroid/telephony/SmsManager;->sendTextMessage".into(),
                reachable: Some(true),
                score: None,
                depth: Some(2),
                fanin: Some(1),
                paths: vec![vec![
                    "Lcom/a/Main;->onCreate(Landroid/os/Bundle;)V".into(),
                    "Lcom/a/Sms;->send(Ljava/lang/String;)V".into(),
                    "Landroid/telephony/SmsManager;->sendTextMessage(LLLLL)V".into(),
                ]],
            }],
        };
        let c = rule_citations(&[m]);
        assert_eq!(c["Lcom/a/Sms;"].direct, ["R1"]);
        assert!(c["Lcom/a/Sms;"].path.is_empty());
        assert_eq!(c["Lcom/a/Main;"].path, ["R1"]);
        assert!(c["Lcom/a/Main;"].direct.is_empty());
        assert_eq!(c["Landroid/telephony/SmsManager;"].direct, ["R1"]);
        assert!(c["Landroid/telephony/SmsManager;"].path.is_empty());
        assert!(!c.contains_key("Landroid/os/Bundle;"));
    }
}
