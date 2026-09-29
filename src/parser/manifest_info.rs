//! Extraction **complète** du `AndroidManifest.xml` (AXML binaire) d'un APK vers
//! un modèle sérialisable (JSON) : permissions déclarées et requises, attributs
//! de `<application>`, tous les composants (activities / services / receivers /
//! providers) avec leurs intent-filters, et une vue dérivée des **points
//! d'entrée** effectifs de l'application.
//!
//! Ce module est **distinct** de [`crate::parser::manifest`] : ce dernier ne
//! remplit que les quelques champs du `ApkFeatures` consommés par le moteur de
//! règles MITRE. Ici on vise l'inventaire exhaustif, utilisable seul
//! (`drakkar --manifest app.apk`) sans charger le catalogue.
//!
//! Toutes les étiquettes et catégories produites sont définies dans [`legend`]
//! (légende autonome).

use crate::parser::axml::{self, Element};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// Modèle
// ─────────────────────────────────────────────────────────────────────────────

/// Rapport complet du manifest d'un APK.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestReport {
    /// Nom de paquet déclaré (`<manifest package=…>`).
    pub package: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    /// `android:installLocation` — internalOnly / auto / preferExternal.
    pub install_location: Option<String>,
    /// `android:sharedUserId` — partage d'UID entre paquets signés par la même clé.
    pub shared_user_id: Option<String>,
    pub sdk: SdkInfo,
    /// Permissions demandées par l'app (`<uses-permission>`).
    pub uses_permissions: Vec<UsesPermission>,
    /// Permissions **définies** par l'app (`<permission>`), avec `protectionLevel`.
    pub declared_permissions: Vec<DeclaredPermission>,
    pub uses_features: Vec<UsesFeature>,
    /// Paquets/intents visibles déclarés dans `<queries>` (package visibility, API 30+).
    pub queries: Vec<String>,
    pub application: ApplicationInfo,
    pub components: Components,
    /// Vue dérivée : par où le code de l'app peut démarrer. Voir [`legend`].
    pub entrypoints: Vec<Entrypoint>,
    /// Observations notables (surface d'attaque, indices de packer, etc.).
    pub anomalies: Vec<String>,
}

/// Niveaux d'API déclarés, plus les marqueurs de chaîne de build injectés dans
/// le manifest par AAPT/AGP.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SdkInfo {
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
    /// `android:compileSdkVersion` — injecté par AGP >= 3.0 (2017). Absent des
    /// builds plus anciens ou non-Gradle : donnée manquante, pas zéro.
    pub compile_sdk: Option<u32>,
    /// `android:compileSdkVersionCodename` — nom de version de la plateforme
    /// compilée (ex. "9", "11"), injecté par la même passe qu'AGP.
    pub compile_sdk_codename: Option<String>,
    /// `platformBuildVersionCode` — écrit par les AAPT antérieurs à AGP 3.
    /// Complémentaire de `compile_sdk` : les deux coexistent rarement.
    pub platform_build_version_code: Option<String>,
    pub platform_build_version_name: Option<String>,
}

/// Une entrée `<uses-permission>` / `<uses-permission-sdk-23>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsesPermission {
    pub name: String,
    /// `true` si l'élément est `<uses-permission-sdk-23>` (demandée à l'exécution ≥ 23).
    pub sdk23_only: bool,
    /// `android:maxSdkVersion` — permission ignorée au-delà de ce niveau.
    pub max_sdk_version: Option<u32>,
}

/// Une permission **définie** par l'application (`<permission>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclaredPermission {
    pub name: String,
    /// normal | dangerous | signature | signatureOrSystem (+ flags).
    pub protection_level: Option<String>,
    pub group: Option<String>,
}

/// Une entrée `<uses-feature>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsesFeature {
    pub name: Option<String>,
    pub required: Option<bool>,
    pub gl_es_version: Option<String>,
}

/// Attributs de `<application>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplicationInfo {
    /// FQCN de la classe `Application` custom — premier code exécuté du process.
    pub name: Option<String>,
    /// `android:appComponentFactory` — hook d'instanciation (API 28+), très
    /// utilisé par les packers pour détourner le chargement des composants.
    pub app_component_factory: Option<String>,
    pub allow_backup: Option<bool>,
    pub debuggable: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
    /// `android:extractNativeLibs` — `false` = .so chargés depuis l'APK aligné.
    pub extract_native_libs: Option<bool>,
    /// `android:hasCode` — `false` + libs natives = code hors DEX (packer/stub).
    pub has_code: Option<bool>,
    pub persistent: Option<bool>,
    pub large_heap: Option<bool>,
    pub process: Option<String>,
    pub task_affinity: Option<String>,
    pub uses_libraries: Vec<String>,
    pub meta_data: Vec<MetaData>,
}

/// Composants regroupés par type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Components {
    pub activities: Vec<Component>,
    pub activity_aliases: Vec<Component>,
    pub services: Vec<Component>,
    pub receivers: Vec<Component>,
    pub providers: Vec<Component>,
}

impl Components {
    /// Itère sur tous les composants, tous types confondus.
    pub fn iter_all(&self) -> impl Iterator<Item = &Component> {
        self.activities
            .iter()
            .chain(self.activity_aliases.iter())
            .chain(self.services.iter())
            .chain(self.receivers.iter())
            .chain(self.providers.iter())
    }

    pub fn total(&self) -> usize {
        self.activities.len()
            + self.activity_aliases.len()
            + self.services.len()
            + self.receivers.len()
            + self.providers.len()
    }
}

/// Type de composant Android.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentKind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    pub fn label(&self) -> &'static str {
        match self {
            ComponentKind::Activity => "activity",
            ComponentKind::ActivityAlias => "activity-alias",
            ComponentKind::Service => "service",
            ComponentKind::Receiver => "receiver",
            ComponentKind::Provider => "provider",
        }
    }
}

/// Un composant déclaré dans `<application>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub kind: ComponentKind,
    /// FQCN résolu (les noms relatifs `.Foo` sont préfixés par le package).
    pub name: String,
    /// Descripteur Dalvik correspondant (`Lcom/foo/Bar;`) — pivot vers le DEX.
    pub descriptor: String,
    /// `android:exported` tel qu'écrit dans le manifest (`None` = absent).
    pub exported_declared: Option<bool>,
    /// Valeur **effective** après application des règles de défaut Android.
    /// Voir [`legend`] pour les règles retenues.
    pub exported_effective: bool,
    pub enabled: Option<bool>,
    /// Permission exigée de l'appelant pour atteindre ce composant.
    pub permission: Option<String>,
    pub process: Option<String>,
    pub direct_boot_aware: Option<bool>,
    /// `android:authorities` (providers uniquement).
    pub authorities: Option<String>,
    /// `android:grantUriPermissions` (providers uniquement).
    pub grant_uri_permissions: Option<bool>,
    /// `android:targetActivity` (activity-alias uniquement).
    pub target_activity: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<MetaData>,
}

/// Un `<intent-filter>` d'un composant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<IntentData>,
    pub priority: Option<i64>,
}

/// Un `<data>` d'intent-filter (deeplinks, App Links).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentData {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub path_prefix: Option<String>,
    pub path_pattern: Option<String>,
    pub mime_type: Option<String>,
}

/// Un `<meta-data>` (clé/valeur ou référence de ressource).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaData {
    pub name: String,
    pub value: Option<String>,
    pub resource: Option<String>,
}

/// Nature du déclenchement d'un point d'entrée. Voir [`legend`].
///
/// Les valeurs sérialisées sont identiques aux étiquettes rendues en console
/// (`kebab-case`), pour que le JSON et le tableau soient grep-compatibles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryTrigger {
    /// Classe `Application` custom : exécutée avant tout composant.
    ApplicationClass,
    /// `appComponentFactory` : hook d'instanciation antérieur à `Application`.
    ComponentFactory,
    /// Icône du lanceur (`category.LAUNCHER`).
    Launcher,
    /// Broadcast système déclenchant le process sans action utilisateur
    /// (BOOT_COMPLETED, USER_PRESENT, SMS_RECEIVED…).
    SystemBroadcast,
    /// Service d'accessibilité — lecture d'écran et injection d'événements.
    AccessibilityService,
    /// Écoute des notifications (`NotificationListenerService`).
    NotificationListener,
    /// Clavier logiciel (`InputMethodService`) — capture de frappe légitime.
    InputMethod,
    /// Administrateur d'appareil (`DeviceAdminReceiver`).
    DeviceAdmin,
    /// Service de synchronisation / job planifié (`BIND_JOB_SERVICE`).
    ScheduledJob,
    /// Deeplink : `action.VIEW` + `<data>` avec scheme.
    Deeplink,
    /// ContentProvider exporté (surface IPC atteignable par une autre app).
    ExportedProvider,
    /// Composant exporté sans permission — atteignable par n'importe quelle app.
    ExportedNoPermission,
}

impl EntryTrigger {
    pub fn label(&self) -> &'static str {
        match self {
            EntryTrigger::ApplicationClass => "application-class",
            EntryTrigger::ComponentFactory => "component-factory",
            EntryTrigger::Launcher => "launcher",
            EntryTrigger::SystemBroadcast => "system-broadcast",
            EntryTrigger::AccessibilityService => "accessibility-service",
            EntryTrigger::NotificationListener => "notification-listener",
            EntryTrigger::InputMethod => "input-method",
            EntryTrigger::DeviceAdmin => "device-admin",
            EntryTrigger::ScheduledJob => "scheduled-job",
            EntryTrigger::Deeplink => "deeplink",
            EntryTrigger::ExportedProvider => "exported-provider",
            EntryTrigger::ExportedNoPermission => "exported-no-permission",
        }
    }
}

/// Un point d'entrée effectif de l'application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoint {
    /// FQCN du composant / de la classe concernée.
    pub component: String,
    /// Descripteur Dalvik (`Lcom/foo/Bar;`) — pivot direct vers le CFG.
    pub descriptor: String,
    /// Type de composant, `None` pour les entrées non-composant
    /// (classe `Application`, `appComponentFactory`).
    pub kind: Option<ComponentKind>,
    pub trigger: EntryTrigger,
    /// Détail lisible : action de broadcast, scheme du deeplink, etc.
    pub detail: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Broadcasts système considérés comme déclencheurs autonomes
// ─────────────────────────────────────────────────────────────────────────────

/// Actions de broadcast qui réveillent le process sans interaction utilisateur.
/// Chaque entrée : (action, description courte pour le rapport).
const AUTOSTART_ACTIONS: &[(&str, &str)] = &[
    (
        "android.intent.action.BOOT_COMPLETED",
        "démarrage de l'appareil",
    ),
    (
        "android.intent.action.LOCKED_BOOT_COMPLETED",
        "démarrage avant déverrouillage",
    ),
    (
        "android.intent.action.QUICKBOOT_POWERON",
        "démarrage rapide (OEM)",
    ),
    (
        "com.htc.intent.action.QUICKBOOT_POWERON",
        "démarrage rapide (HTC)",
    ),
    (
        "android.intent.action.MY_PACKAGE_REPLACED",
        "mise à jour de l'app elle-même",
    ),
    (
        "android.intent.action.PACKAGE_REPLACED",
        "mise à jour d'un paquet tiers",
    ),
    (
        "android.intent.action.PACKAGE_ADDED",
        "installation d'un paquet",
    ),
    (
        "android.intent.action.PACKAGE_REMOVED",
        "désinstallation d'un paquet",
    ),
    (
        "android.intent.action.USER_PRESENT",
        "déverrouillage de l'écran",
    ),
    ("android.intent.action.SCREEN_ON", "allumage de l'écran"),
    ("android.intent.action.SCREEN_OFF", "extinction de l'écran"),
    (
        "android.intent.action.BOOT_COMPLETED_LEGACY",
        "démarrage (variante)",
    ),
    ("android.provider.Telephony.SMS_RECEIVED", "réception SMS"),
    (
        "android.provider.Telephony.SMS_DELIVER",
        "SMS livré (app SMS par défaut)",
    ),
    (
        "android.provider.Telephony.WAP_PUSH_RECEIVED",
        "WAP push / MMS",
    ),
    (
        "android.intent.action.PHONE_STATE",
        "changement d'état d'appel",
    ),
    ("android.intent.action.NEW_OUTGOING_CALL", "appel sortant"),
    (
        "android.net.conn.CONNECTIVITY_CHANGE",
        "changement de connectivité",
    ),
    ("android.net.wifi.STATE_CHANGE", "changement d'état Wi-Fi"),
    (
        "android.intent.action.ACTION_POWER_CONNECTED",
        "branchement secteur",
    ),
    (
        "android.intent.action.ACTION_POWER_DISCONNECTED",
        "débranchement secteur",
    ),
    ("android.intent.action.BATTERY_LOW", "batterie faible"),
    ("android.intent.action.TIME_SET", "changement d'heure"),
    (
        "android.intent.action.TIMEZONE_CHANGED",
        "changement de fuseau",
    ),
    (
        "android.intent.action.MEDIA_MOUNTED",
        "montage de stockage externe",
    ),
    ("android.intent.action.DREAMING_STOPPED", "sortie de veille"),
    (
        "android.app.action.DEVICE_ADMIN_ENABLED",
        "activation admin d'appareil",
    ),
];

/// Actions de binding de services système sensibles.
const BIND_ACTIONS: &[(&str, EntryTrigger)] = &[
    (
        "android.accessibilityservice.AccessibilityService",
        EntryTrigger::AccessibilityService,
    ),
    (
        "android.service.notification.NotificationListenerService",
        EntryTrigger::NotificationListener,
    ),
    ("android.view.InputMethod", EntryTrigger::InputMethod),
    ("android.app.job.JobService", EntryTrigger::ScheduledJob),
    (
        "android.service.dreams.DreamService",
        EntryTrigger::ScheduledJob,
    ),
];

/// Permissions de binding équivalentes (portées par `android:permission`).
const BIND_PERMISSIONS: &[(&str, EntryTrigger)] = &[
    (
        "BIND_ACCESSIBILITY_SERVICE",
        EntryTrigger::AccessibilityService,
    ),
    (
        "BIND_NOTIFICATION_LISTENER_SERVICE",
        EntryTrigger::NotificationListener,
    ),
    ("BIND_INPUT_METHOD", EntryTrigger::InputMethod),
    ("BIND_JOB_SERVICE", EntryTrigger::ScheduledJob),
    ("BIND_DEVICE_ADMIN", EntryTrigger::DeviceAdmin),
];

// ─────────────────────────────────────────────────────────────────────────────
// Point d'entrée du module
// ─────────────────────────────────────────────────────────────────────────────

/// Anomalie signalant que le rapport vient du décodeur AXML de repli. Définie
/// dans [`legend`].
const ANOMALY_TOLERANT_AXML: &str =
    "manifest décodé par le repli AXML tolérant — inventaire potentiellement partiel";

/// Parse le `AndroidManifest.xml` d'un APK et produit le rapport complet.
pub fn extract(apk_path: &Path) -> Result<ManifestReport> {
    let raw = read_manifest_bytes(apk_path)?;
    let decoded = axml::decode(&raw).map_err(|e| anyhow!("décodage AXML: {e}"))?;
    if decoded.root.get_tag() != "manifest" {
        return Err(anyhow!(
            "racine inattendue: <{}> au lieu de <manifest>",
            decoded.root.get_tag()
        ));
    }
    let mut report = build(&decoded.root);
    if decoded.tolerant {
        report.anomalies.push(ANOMALY_TOLERANT_AXML.into());
    }
    Ok(report)
}

/// Extrait les octets de l'entrée `AndroidManifest.xml` de l'archive APK.
///
/// Même repli que `parser::manifest` : le crate `zip` ne contrôle le drapeau de
/// chiffrement et la méthode de compression qu'à la lecture de l'entrée.
fn read_manifest_bytes(apk_path: &Path) -> Result<Vec<u8>> {
    let file = std::fs::File::open(apk_path)
        .with_context(|| format!("ouverture {}", apk_path.display()))?;

    let nominal = (|| -> Result<Vec<u8>> {
        let mut zip = zip::ZipArchive::new(file).context("lecture de l'APK comme zip")?;
        let mut entry = zip
            .by_name("AndroidManifest.xml")
            .context("AndroidManifest.xml absent de l'APK")?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        Ok(buf)
    })();

    match nominal {
        Ok(buf) => Ok(buf),
        Err(e) => {
            tracing::warn!(
                apk = %apk_path.display(),
                error = %e,
                "manifest illisible par le crate zip, repli sur le lecteur tolérant"
            );
            super::apkzip::TolerantZip::open(apk_path)?
                .read_by_name("AndroidManifest.xml")
                .context("AndroidManifest.xml illisible, y compris par le lecteur tolérant")
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction du rapport
// ─────────────────────────────────────────────────────────────────────────────

fn build(root: &Element) -> ManifestReport {
    let mut r = ManifestReport {
        package: root.attr("package").unwrap_or_default(),
        version_code: root.attr("versionCode"),
        version_name: root.attr("versionName"),
        install_location: root.attr("installLocation"),
        shared_user_id: root.attr("sharedUserId"),
        ..Default::default()
    };
    r.sdk.compile_sdk = root.attr_u32("compileSdkVersion");
    r.sdk.compile_sdk_codename = root.attr("compileSdkVersionCodename");
    r.sdk.platform_build_version_code = root.attr("platformBuildVersionCode");
    r.sdk.platform_build_version_name = root.attr("platformBuildVersionName");

    let pkg = r.package.clone();

    for child in child_elements(root) {
        match child.get_tag() {
            "uses-sdk" => {
                r.sdk.min_sdk = child.attr_u32("minSdkVersion");
                r.sdk.target_sdk = child.attr_u32("targetSdkVersion");
                r.sdk.max_sdk = child.attr_u32("maxSdkVersion");
            }
            "uses-permission" | "uses-permission-sdk-23" => {
                if let Some(name) = child.attr("name") {
                    r.uses_permissions.push(UsesPermission {
                        name,
                        sdk23_only: child.get_tag() == "uses-permission-sdk-23",
                        max_sdk_version: child.attr_u32("maxSdkVersion"),
                    });
                }
            }
            "permission" => {
                if let Some(name) = child.attr("name") {
                    r.declared_permissions.push(DeclaredPermission {
                        name,
                        protection_level: child.attr("protectionLevel"),
                        group: child.attr("permissionGroup"),
                    });
                }
            }
            "uses-feature" => r.uses_features.push(UsesFeature {
                name: child.attr("name"),
                required: child.attr_bool("required"),
                gl_es_version: child.attr("glEsVersion"),
            }),
            "queries" => collect_queries(child, &mut r.queries),
            "application" => parse_application(child, &pkg, &mut r),
            _ => {}
        }
    }

    r.entrypoints = derive_entrypoints(&r);
    r.anomalies = derive_anomalies(&r);
    r
}

/// Aplatit le contenu de `<queries>` en descripteurs lisibles.
fn collect_queries(elem: &Element, out: &mut Vec<String>) {
    for child in child_elements(elem) {
        match child.get_tag() {
            "package" => {
                if let Some(n) = child.attr("name") {
                    out.push(format!("package:{n}"));
                }
            }
            "provider" => {
                if let Some(a) = child.attr("authorities") {
                    out.push(format!("provider:{a}"));
                }
            }
            "intent" => {
                let mut actions = Vec::new();
                collect_tag_names(child, "action", &mut actions);
                for a in actions {
                    out.push(format!("intent:{a}"));
                }
            }
            _ => {}
        }
    }
}

fn parse_application(app: &Element, pkg: &str, r: &mut ManifestReport) {
    r.application = ApplicationInfo {
        name: app.attr("name").map(|n| resolve_fqcn(&n, pkg)),
        app_component_factory: app
            .attr("appComponentFactory")
            .map(|n| resolve_fqcn(&n, pkg)),
        allow_backup: app.attr_bool("allowBackup"),
        debuggable: app.attr_bool("debuggable"),
        uses_cleartext_traffic: app.attr_bool("usesCleartextTraffic"),
        network_security_config: app.attr("networkSecurityConfig"),
        extract_native_libs: app.attr_bool("extractNativeLibs"),
        has_code: app.attr_bool("hasCode"),
        persistent: app.attr_bool("persistent"),
        large_heap: app.attr_bool("largeHeap"),
        process: app.attr("process"),
        task_affinity: app.attr("taskAffinity"),
        uses_libraries: Vec::new(),
        meta_data: Vec::new(),
    };

    let min_sdk = r.sdk.min_sdk.unwrap_or(1);

    for child in child_elements(app) {
        match child.get_tag() {
            "activity" => r.components.activities.push(parse_component(
                child,
                ComponentKind::Activity,
                pkg,
                min_sdk,
            )),
            "activity-alias" => r.components.activity_aliases.push(parse_component(
                child,
                ComponentKind::ActivityAlias,
                pkg,
                min_sdk,
            )),
            "service" => r.components.services.push(parse_component(
                child,
                ComponentKind::Service,
                pkg,
                min_sdk,
            )),
            "receiver" => r.components.receivers.push(parse_component(
                child,
                ComponentKind::Receiver,
                pkg,
                min_sdk,
            )),
            "provider" => r.components.providers.push(parse_component(
                child,
                ComponentKind::Provider,
                pkg,
                min_sdk,
            )),
            "meta-data" => {
                if let Some(md) = parse_meta_data(child) {
                    r.application.meta_data.push(md);
                }
            }
            "uses-library" => {
                if let Some(n) = child.attr("name") {
                    r.application.uses_libraries.push(n);
                }
            }
            _ => {}
        }
    }
}

fn parse_component(elem: &Element, kind: ComponentKind, pkg: &str, min_sdk: u32) -> Component {
    let raw_name = elem.attr("name").unwrap_or_default();
    let name = resolve_fqcn(&raw_name, pkg);
    let descriptor = to_descriptor(&name);

    let mut intent_filters = Vec::new();
    let mut meta_data = Vec::new();
    for child in child_elements(elem) {
        match child.get_tag() {
            "intent-filter" => intent_filters.push(parse_intent_filter(child)),
            "meta-data" => {
                if let Some(md) = parse_meta_data(child) {
                    meta_data.push(md);
                }
            }
            _ => {}
        }
    }

    let exported_declared = elem.attr_bool("exported");
    // Règles de défaut Android (cf. legend) :
    //  - provider : exporté par défaut si minSdkVersion < 17 ;
    //  - autres   : exporté par défaut si au moins un <intent-filter> est présent.
    let exported_effective = exported_declared.unwrap_or(match kind {
        ComponentKind::Provider => min_sdk < 17,
        _ => !intent_filters.is_empty(),
    });

    Component {
        kind,
        name,
        descriptor,
        exported_declared,
        exported_effective,
        enabled: elem.attr_bool("enabled"),
        permission: elem.attr("permission"),
        process: elem.attr("process"),
        direct_boot_aware: elem.attr_bool("directBootAware"),
        authorities: elem.attr("authorities"),
        grant_uri_permissions: elem.attr_bool("grantUriPermissions"),
        target_activity: elem.attr("targetActivity").map(|n| resolve_fqcn(&n, pkg)),
        intent_filters,
        meta_data,
    }
}

fn parse_intent_filter(elem: &Element) -> IntentFilter {
    let mut f = IntentFilter {
        priority: elem.attr("priority").and_then(|p| p.parse::<i64>().ok()),
        ..Default::default()
    };
    for child in child_elements(elem) {
        match child.get_tag() {
            "action" => {
                if let Some(n) = child.attr("name") {
                    f.actions.push(n);
                }
            }
            "category" => {
                if let Some(n) = child.attr("name") {
                    f.categories.push(n);
                }
            }
            "data" => f.data.push(IntentData {
                scheme: child.attr("scheme"),
                host: child.attr("host"),
                port: child.attr("port"),
                path: child.attr("path"),
                path_prefix: child.attr("pathPrefix"),
                path_pattern: child.attr("pathPattern"),
                mime_type: child.attr("mimeType"),
            }),
            _ => {}
        }
    }
    f
}

fn parse_meta_data(elem: &Element) -> Option<MetaData> {
    let name = elem.attr("name")?;
    Some(MetaData {
        name,
        value: elem.attr("value"),
        resource: elem.attr("resource"),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Dérivation : points d'entrée
// ─────────────────────────────────────────────────────────────────────────────

fn derive_entrypoints(r: &ManifestReport) -> Vec<Entrypoint> {
    let mut out = Vec::new();

    if let Some(factory) = &r.application.app_component_factory {
        out.push(Entrypoint {
            component: factory.clone(),
            descriptor: to_descriptor(factory),
            kind: None,
            trigger: EntryTrigger::ComponentFactory,
            detail: "instancie les composants avant Application.onCreate()".into(),
        });
    }
    if let Some(app_class) = &r.application.name {
        out.push(Entrypoint {
            component: app_class.clone(),
            descriptor: to_descriptor(app_class),
            kind: None,
            trigger: EntryTrigger::ApplicationClass,
            detail: "attachBaseContext() / onCreate() du process".into(),
        });
    }

    for c in r.components.iter_all() {
        let mut triggers: Vec<(EntryTrigger, String)> = Vec::new();

        for f in &c.intent_filters {
            if f.categories
                .iter()
                .any(|cat| cat == "android.intent.category.LAUNCHER")
            {
                triggers.push((EntryTrigger::Launcher, "icône du lanceur".into()));
            }
            for a in &f.actions {
                if let Some((_, desc)) = AUTOSTART_ACTIONS.iter().find(|(act, _)| act == a) {
                    triggers.push((EntryTrigger::SystemBroadcast, format!("{a} ({desc})")));
                }
                if let Some((_, t)) = BIND_ACTIONS.iter().find(|(act, _)| act == a) {
                    triggers.push((*t, a.clone()));
                }
                if a == "android.intent.action.VIEW" {
                    for d in &f.data {
                        if let Some(scheme) = &d.scheme {
                            let host = d.host.clone().unwrap_or_else(|| "*".into());
                            triggers.push((EntryTrigger::Deeplink, format!("{scheme}://{host}")));
                        }
                    }
                }
            }
        }

        if let Some(perm) = &c.permission {
            if let Some((_, t)) = BIND_PERMISSIONS.iter().find(|(p, _)| perm.contains(*p)) {
                triggers.push((*t, perm.clone()));
            }
        }

        if c.kind == ComponentKind::Provider && c.exported_effective {
            let auth = c.authorities.clone().unwrap_or_else(|| "?".into());
            triggers.push((
                EntryTrigger::ExportedProvider,
                format!("authorities={auth}"),
            ));
        }

        if c.exported_effective && c.permission.is_none() && triggers.is_empty() {
            triggers.push((
                EntryTrigger::ExportedNoPermission,
                format!("{} exporté sans permission", c.kind.label()),
            ));
        }

        // Dédoublonnage. Pour les bindings de services système, un seul point
        // d'entrée par composant : l'action d'intent-filter et l'attribut
        // android:permission décrivent le même mécanisme. Pour les broadcasts
        // et les deeplinks, chaque action / scheme est un déclencheur distinct.
        let mut seen: Vec<(EntryTrigger, String)> = Vec::new();
        triggers.retain(|(t, d)| {
            let key = match t {
                EntryTrigger::SystemBroadcast | EntryTrigger::Deeplink => (*t, d.clone()),
                _ => (*t, String::new()),
            };
            if seen.contains(&key) {
                false
            } else {
                seen.push(key);
                true
            }
        });

        for (trigger, detail) in triggers {
            out.push(Entrypoint {
                component: c.name.clone(),
                descriptor: c.descriptor.clone(),
                kind: Some(c.kind),
                trigger,
                detail,
            });
        }
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Dérivation : anomalies
// ─────────────────────────────────────────────────────────────────────────────

fn derive_anomalies(r: &ManifestReport) -> Vec<String> {
    let mut a = Vec::new();

    if r.application.debuggable == Some(true) {
        a.push("application:debuggable=true — débogage JDWP autorisé en production".into());
    }
    if r.application.allow_backup.unwrap_or(true) {
        a.push("allowBackup non désactivé — données extractibles via adb backup".into());
    }
    if r.application.uses_cleartext_traffic == Some(true) {
        a.push("usesCleartextTraffic=true — trafic HTTP en clair autorisé".into());
    }
    if r.application.has_code == Some(false) {
        a.push(
            "hasCode=false — le code exécuté n'est pas dans les DEX (packer/stub natif ?)".into(),
        );
    }
    if r.application.app_component_factory.is_some() {
        a.push("appComponentFactory présent — hook d'instanciation (packer probable)".into());
    }
    if r.application.persistent == Some(true) {
        a.push("persistent=true — process maintenu vivant par le système".into());
    }
    if r.uses_permissions
        .iter()
        .any(|p| p.name.ends_with("QUERY_ALL_PACKAGES"))
    {
        a.push("QUERY_ALL_PACKAGES — énumération complète des apps installées".into());
    }
    if r.uses_permissions
        .iter()
        .any(|p| p.name.ends_with("REQUEST_INSTALL_PACKAGES"))
    {
        a.push("REQUEST_INSTALL_PACKAGES — installation d'APK tiers possible".into());
    }
    if r.uses_permissions
        .iter()
        .any(|p| p.name.ends_with("SYSTEM_ALERT_WINDOW"))
    {
        a.push("SYSTEM_ALERT_WINDOW — overlay au-dessus des autres apps".into());
    }

    let launcher_count = r
        .entrypoints
        .iter()
        .filter(|e| e.trigger == EntryTrigger::Launcher)
        .count();
    if launcher_count == 0 {
        a.push(
            "aucune activité LAUNCHER — application sans icône (comportement furtif typique)"
                .into(),
        );
    }

    let exposed = r
        .components
        .iter_all()
        .filter(|c| c.exported_effective && c.permission.is_none())
        .count();
    if exposed > 0 {
        a.push(format!(
            "{exposed} composant(s) exporté(s) sans permission — atteignables par toute app"
        ));
    }

    if r.shared_user_id.is_some() {
        a.push("sharedUserId déclaré — partage d'UID avec les paquets de même signature".into());
    }

    a
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers AXML
// ─────────────────────────────────────────────────────────────────────────────

fn child_elements(elem: &Element) -> impl Iterator<Item = &Element> {
    elem.get_children().iter()
}

/// Collecte récursivement les `android:name` des éléments portant `tag`.
fn collect_tag_names(elem: &Element, tag: &str, out: &mut Vec<String>) {
    for child in child_elements(elem) {
        if child.get_tag() == tag {
            if let Some(n) = child.attr("name") {
                out.push(n);
            }
        }
        collect_tag_names(child, tag, out);
    }
}

/// Résout un nom de classe relatif (`.Foo` ou `Foo`) en FQCN.
fn resolve_fqcn(name: &str, package: &str) -> String {
    if let Some(stripped) = name.strip_prefix('.') {
        format!("{package}.{stripped}")
    } else if name.contains('.') {
        name.to_string()
    } else if name.is_empty() {
        String::new()
    } else {
        format!("{package}.{name}")
    }
}

/// FQCN -> descripteur Dalvik `Lcom/foo/Bar;`.
fn to_descriptor(fqcn: &str) -> String {
    if fqcn.is_empty() {
        return String::new();
    }
    format!("L{};", fqcn.replace('.', "/"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Légende
// ─────────────────────────────────────────────────────────────────────────────

/// Légende autonome : définit chaque catégorie et chaque règle de dérivation
/// employée dans [`ManifestReport`]. Affichée en tête du rendu console.
pub fn legend() -> String {
    let mut s = String::new();
    s.push_str("Légende — rapport manifest\n");
    s.push_str("  exported_declared   : valeur littérale de android:exported dans le manifest\n");
    s.push_str("                        (null = attribut absent)\n");
    s.push_str("  exported_effective  : valeur après application des défauts Android —\n");
    s.push_str("                        provider : exporté si minSdkVersion < 17 ;\n");
    s.push_str("                        autres   : exporté si >= 1 <intent-filter> présent\n");
    s.push_str("  descriptor          : descripteur Dalvik du composant (Lcom/foo/Bar;),\n");
    s.push_str("                        clé de jointure avec le CFG issu du DEX\n");
    s.push_str("\n  Points d'entrée (entrypoints.trigger) :\n");
    s.push_str("  application-class      classe Application custom — 1er code du process\n");
    s.push_str("  component-factory      appComponentFactory — hook antérieur à Application\n");
    s.push_str("  launcher               activité avec category.LAUNCHER (icône visible)\n");
    s.push_str("  system-broadcast       receiver réveillé par un broadcast système\n");
    s.push_str("                         (BOOT_COMPLETED, USER_PRESENT, SMS_RECEIVED…)\n");
    s.push_str("  accessibility-service  AccessibilityService — lecture d'écran / injection\n");
    s.push_str("  notification-listener  NotificationListenerService — lecture des notifs\n");
    s.push_str("  input-method           InputMethodService — clavier, capture de frappe\n");
    s.push_str("  device-admin           DeviceAdminReceiver — verrouillage / effacement\n");
    s.push_str("  scheduled-job          JobService / DreamService — exécution planifiée\n");
    s.push_str("  deeplink               action.VIEW + <data scheme=…> — invocable par URL\n");
    s.push_str("  exported-provider      ContentProvider exporté — surface IPC de données\n");
    s.push_str("  exported-no-permission composant exporté sans android:permission\n");
    s.push_str("\n  Provenance du décodage (anomalies) :\n");
    s.push_str("  « repli AXML tolérant » : axmldecoder a refusé le manifest (chunk de type\n");
    s.push_str("                        inconnu, offset de string pool hors bornes) et le\n");
    s.push_str("                        décodeur tolérant a pris le relais. Les champs\n");
    s.push_str("                        illisibles sont absents plutôt que faux, mais\n");
    s.push_str("                        l'inventaire peut être incomplet — un composant\n");
    s.push_str("                        manquant n'est pas un composant absent.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqcn_relatif() {
        assert_eq!(resolve_fqcn(".Foo", "com.a.b"), "com.a.b.Foo");
        assert_eq!(resolve_fqcn("Foo", "com.a.b"), "com.a.b.Foo");
        assert_eq!(resolve_fqcn("com.x.Foo", "com.a.b"), "com.x.Foo");
    }

    #[test]
    fn descripteur_dalvik() {
        assert_eq!(to_descriptor("com.a.b.Foo"), "Lcom/a/b/Foo;");
        assert_eq!(to_descriptor(""), "");
    }
}
