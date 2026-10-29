//! `--capabilities` : sites du code applicatif qui touchent une capacité
//! sensible, relevés dans le désassemblage de `--disasm`. Table, sélection des
//! instructions et préfixes de bibliothèques repris de
//! `hybridse-eval/scripts/capability_sweep.py`.
//!
//! Les alternatives des expressions du script sont dépliées en motifs
//! littéraux : à une position donnée, le premier motif de la table l'emporte,
//! comme l'alternance de `re`, et le motif retenu est le plus à gauche.

use crate::parser::disasm::{self, DisasmOptions, DisasmReport};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Préfixes de descripteur exclus d'office : bibliothèques, pas l'application.
pub const LIBRARY_PREFIXES: &[&str] = &[
    "Landroid/",
    "Landroidx/",
    "Lkotlin",
    "Lcom/google/",
    "Lokhttp3/",
    "Lokio/",
    "Lorg/",
    "Ljava",
    "Lretrofit2/",
    "Lio/reactivex",
    "Lcom/squareup/",
    "Lcom/tencent/mmkv",
    "Ltop/canyie/pine",
    "Lcom/bumptech",
    "Lcom/facebook",
    "Ldagger",
    "Lcom/fasterxml",
    "Lcom/revenuecat",
    "Lcom/github",
    "Lio/socket",
];

/// Catégorie → motifs, cherchés comme sous-chaînes dans l'opérande résolue.
pub const CATEGORIES: &[(&str, &[&str])] = &[
    (
        "accessibility_actions",
        &[
            "AccessibilityService;->performGlobalAction",
            "AccessibilityService;->dispatchGesture",
            "AccessibilityService;->getRootInActiveWindow",
            "AccessibilityService;->takeScreenshot",
            "AccessibilityNodeInfo;->performAction",
            "GestureDescription$Builder;-><init>",
        ],
    ),
    (
        "accessibility_events",
        &[
            "AccessibilityEvent;->getText",
            "AccessibilityEvent;->getEventType",
            "AccessibilityEvent;->getPackageName",
            "AccessibilityEvent;->getSource",
        ],
    ),
    (
        "overlay",
        &[
            "WindowManager;->addView",
            "TYPE_APPLICATION_OVERLAY",
            "Settings;->canDrawOverlays",
        ],
    ),
    (
        "sms",
        &[
            "SmsManager;->send",
            "content://sms",
            "Telephony$Sms",
            "SmsMessage;->createFromPdu",
        ],
    ),
    (
        "calls",
        &[
            "content://call_log",
            "CallLog$Calls",
            "TelecomManager;->",
            "TelephonyManager;->getLine1Number",
            "TelephonyManager;->getSimSerialNumber",
            "TelephonyManager;->getSubscriberId",
            "TelephonyManager;->getDeviceId",
        ],
    ),
    ("contacts", &["ContactsContract", "content://contacts"]),
    (
        "screen_capture",
        &[
            "MediaProjection;->createVirtualDisplay",
            "MediaProjectionManager;->createScreenCaptureIntent",
            "ImageReader;->newInstance",
            "ImageReader;->acquireLatestImage",
        ],
    ),
    (
        "camera",
        &[
            "Landroid/hardware/camera2/",
            "Landroid/hardware/Camera;->open",
        ],
    ),
    (
        "audio",
        &["AudioRecord;->", "MediaRecorder;->setAudioSource"],
    ),
    (
        "location",
        &[
            "LocationManager;->requestLocationUpdates",
            "LocationManager;->getLastKnownLocation",
            "FusedLocationProviderClient",
        ],
    ),
    (
        "clipboard",
        &[
            "ClipboardManager;->getPrimaryClip",
            "ClipboardManager;->setPrimaryClip",
            "ClipboardManager;->addPrimaryClipChangedListener",
        ],
    ),
    (
        "notifications",
        &[
            "NotificationListenerService;->getActiveNotifications",
            "NotificationListenerService;->cancelNotification",
            "StatusBarNotification;->getNotification",
        ],
    ),
    (
        "installed_apps",
        &[
            "PackageManager;->getInstalledPackages",
            "PackageManager;->getInstalledApplications",
            "PackageManager;->getLaunchIntentForPackage",
        ],
    ),
    (
        "package_install",
        &[
            "PackageInstaller;->createSession",
            "PackageInstaller$Session;->commit",
            "ACTION_INSTALL_PACKAGE",
            "application/vnd.android.package-archive",
        ],
    ),
    (
        "device_admin",
        &[
            "DevicePolicyManager;->lockNow",
            "DevicePolicyManager;->wipeData",
            "DevicePolicyManager;->resetPassword",
            "ACTION_ADD_DEVICE_ADMIN",
        ],
    ),
    ("exec", &["Runtime;->exec", "ProcessBuilder;->start"]),
    (
        "dex_load",
        &[
            "DexClassLoader;-><init>",
            "InMemoryDexClassLoader;-><init>",
            "PathClassLoader;-><init>",
        ],
    ),
    (
        "websocket",
        &[
            "OkHttpClient;->newWebSocket",
            "WebSocketClient;-><init>",
            "WebSocket;->send",
        ],
    ),
    (
        "socket",
        &["Ljava/net/Socket;-><init>", "SocketChannel;->open"],
    ),
    (
        "webview_js",
        &[
            "WebView;->addJavascriptInterface",
            "WebView;->evaluateJavascript",
        ],
    ),
    (
        "files",
        &[
            "Environment;->getExternalStorageDirectory",
            "MediaStore$Images",
            "MediaStore$Files",
        ],
    ),
    (
        "wake_boot",
        &[
            "PowerManager;->newWakeLock",
            "BOOT_COMPLETED",
            "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
        ],
    ),
    (
        "hide_icon",
        &["PackageManager;->setComponentEnabledSetting"],
    ),
    (
        "keyguard",
        &["KeyguardManager;->", "DevicePolicyManager;->lockNow"],
    ),
];

/// Catégorie → motif reconnu → sites `Lclasse;->méthode`, triés.
pub type Capabilities = BTreeMap<&'static str, BTreeMap<&'static str, BTreeSet<String>>>;

pub struct CapabilityReport {
    pub capabilities: Capabilities,
    /// Classes sélectionnées par les motifs, avant exclusion.
    pub selected: usize,
    /// Parmi elles, classes exclues comme bibliothèque.
    pub excluded: usize,
}

/// APK ou DEX brut, même sélection de classes que `--disasm`.
pub fn run(input: &Path, patterns: &[String], exclude: &[String]) -> Result<CapabilityReport> {
    let options = DisasmOptions {
        patterns: patterns.to_vec(),
        normalize: Vec::new(),
    };
    let report = disasm::run(input, &options)?;
    Ok(scan(&report, exclude))
}

pub fn scan(report: &DisasmReport, exclude: &[String]) -> CapabilityReport {
    let mut out = CapabilityReport {
        capabilities: Capabilities::new(),
        selected: report.classes.len(),
        excluded: 0,
    };
    for class in &report.classes {
        if is_library(&class.descriptor, exclude) {
            out.excluded += 1;
            continue;
        }
        for method in &class.methods {
            let site = format!("{}->{}", class.descriptor, method.name);
            for insn in &method.insns {
                if !is_site(&insn.mnemonic) {
                    continue;
                }
                let Some(text) = &insn.resolved else {
                    continue;
                };
                for &(category, patterns) in CATEGORIES {
                    if let Some(api) = first_match(text, patterns) {
                        let apis = out.capabilities.entry(category).or_default();
                        apis.entry(api).or_default().insert(site.clone());
                    }
                }
            }
        }
    }
    out
}

fn is_library(descriptor: &str, exclude: &[String]) -> bool {
    LIBRARY_PREFIXES.iter().any(|p| descriptor.starts_with(p))
        || exclude.iter().any(|p| descriptor.starts_with(p.as_str()))
}

fn is_site(mnemonic: &str) -> bool {
    ["invoke", "const-string", "sget"]
        .iter()
        .any(|m| mnemonic.starts_with(m))
}

/// Motif le plus à gauche dans `text` ; à égalité, le premier de la table.
pub fn first_match(text: &str, patterns: &[&'static str]) -> Option<&'static str> {
    let mut best: Option<(usize, &'static str)> = None;
    for &pattern in patterns {
        if let Some(at) = text.find(pattern) {
            if best.is_none_or(|(pos, _)| at < pos) {
                best = Some((at, pattern));
            }
        }
    }
    best.map(|(_, pattern)| pattern)
}

/// Une ligne par catégorie, dans l'ordre de la table.
pub fn render(r: &CapabilityReport) -> String {
    let mut s = String::new();
    for (category, _) in CATEGORIES {
        let Some(apis) = r.capabilities.get(category) else {
            s.push_str(&format!("{category:<22} -\n"));
            continue;
        };
        let sites: BTreeSet<&String> = apis.values().flatten().collect();
        let names: Vec<&str> = apis.keys().copied().collect();
        let examples: Vec<&str> = sites.iter().take(3).map(|x| x.as_str()).collect();
        s.push_str(&format!(
            "{category:<22} {} site(s)  api : {}  ex : {}\n",
            sites.len(),
            names.join(", "),
            examples.join(", ")
        ));
    }
    s
}

/// Légende (`--capabilities --legend`).
pub fn legend() -> String {
    let mut out = String::from(
        "\
== Balayage des capacités (--capabilities) — légende ==

CE QUE C'EST : pour chaque catégorie de la table ci-dessous, les sites du code
APPLICATIF dont l'opérande résolue contient un motif de la catégorie. Repris de
hybridse-eval/scripts/capability_sweep.py, appliqué au désassemblage de --disasm.

⚠️ Un site relevé n'est PAS une preuve d'atteignabilité ni d'exécution : c'est une
instruction présente dans le bytecode. Code mort, branche jamais prise, bibliothèque
mal classée en application : tout y passe. --probe et --orphan-audit disent ce qui
est atteignable.

Sélection :
  --capabilities [MOTIF…]   Mêmes classes que --disasm : sous-chaîne du descripteur
                            Dalvik, insensible à la casse, répétable ; sans motif,
                            toutes. APK ou DEX brut, reconnu au contenu.
  Code applicatif = classe dont le descripteur ne commence par aucun préfixe de la
  liste BIBLIOTHÈQUES ci-dessous, ni par un --capabilities-exclude <PREFIXE>
  (répétable). Comparaison sensible à la casse ; Lkotlin et Ljava couvrent aussi
  Lkotlinx et Ljavax.
  Instructions lues : invoke-*, const-string, const-string/jumbo, sget* ; leur
  opérande résolue (Lowner;->méthode(), \"chaîne\", Lowner;->champ:Type) est
  comparée aux motifs comme sous-chaîne, sensible à la casse. Sur une instruction,
  une catégorie retient le motif trouvé le plus à gauche, le premier de la table à
  égalité ; plusieurs catégories peuvent retenir la même instruction.

Sortie texte, une ligne par catégorie, dans l'ordre de la table :
  <catégorie>  <N> site(s)  api : <motifs vus>  ex : <3 premiers sites>
  « - » : aucun site. N compte les sites distincts, un site = Lclasse;->méthode
  (surcharges confondues).
Sortie JSON (--format json) : {catégorie: {motif: [Lclasse;->méthode, …]}}, triés ;
une catégorie sans site est absente.

Motifs littéraux : les alternatives du script sont dépliées ; un « . » du script
(application/vnd.android.package-archive) est lu comme un point.
",
    );
    out.push_str("\nCATÉGORIES (motifs exacts)\n");
    for (category, patterns) in CATEGORIES {
        out.push_str(&format!("  {category}\n"));
        for pattern in *patterns {
            out.push_str(&format!("      {pattern}\n"));
        }
    }
    out.push_str(&format!(
        "\nBIBLIOTHÈQUES (préfixes exclus d'office)\n  {}\n",
        LIBRARY_PREFIXES.join(" ")
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::disasm::{ClassDisasm, Insn, MethodDisasm};

    fn insn(mnemonic: &str, resolved: &str) -> Insn {
        Insn {
            offset: 0,
            mnemonic: mnemonic.to_string(),
            operands: String::new(),
            resolved: Some(resolved.to_string()),
        }
    }

    fn class(descriptor: &str, method: &str, insns: Vec<Insn>) -> ClassDisasm {
        ClassDisasm {
            descriptor: descriptor.to_string(),
            statics: Vec::new(),
            methods: vec![MethodDisasm {
                name: method.to_string(),
                params: Vec::new(),
                registers_size: 4,
                ins_size: 1,
                fingerprint: 0,
                insns,
            }],
            codeless: 0,
        }
    }

    fn report() -> DisasmReport {
        let sms = "Landroid/telephony/SmsManager;->sendTextMessage()";
        DisasmReport {
            input: String::new(),
            classes: vec![
                class(
                    "Lcom/evil/A;",
                    "run",
                    vec![
                        insn("invoke-virtual", sms),
                        insn("const-string", "\"content://sms/inbox\""),
                        insn(
                            "sget",
                            "Landroid/view/WindowManager$LayoutParams;->TYPE_APPLICATION_OVERLAY:I",
                        ),
                        insn("new-instance", "Ldalvik/system/DexClassLoader;"),
                        insn(
                            "invoke-direct",
                            "Ldalvik/system/InMemoryDexClassLoader;-><init>()",
                        ),
                    ],
                ),
                class("Landroidx/core/B;", "f", vec![insn("invoke-virtual", sms)]),
                class("Lcom/sdk/C;", "g", vec![insn("invoke-virtual", sms)]),
            ],
            scanned: 3,
        }
    }

    #[test]
    fn sites_come_from_application_code_only() {
        let r = scan(&report(), &["Lcom/sdk/".to_string()]);
        assert_eq!((r.selected, r.excluded), (3, 2));
        let sms = &r.capabilities["sms"];
        let site = BTreeSet::from(["Lcom/evil/A;->run".to_string()]);
        assert_eq!(sms["SmsManager;->send"], site);
        assert_eq!(sms["content://sms"], site);
        assert_eq!(r.capabilities["overlay"]["TYPE_APPLICATION_OVERLAY"], site);
        let dex = &r.capabilities["dex_load"];
        assert_eq!(
            dex.keys().copied().collect::<Vec<_>>(),
            ["InMemoryDexClassLoader;-><init>"]
        );
        assert!(!r.capabilities.contains_key("exec"));
    }

    #[test]
    fn the_leftmost_pattern_wins_like_the_script() {
        let dex_load = CATEGORIES.iter().find(|(c, _)| *c == "dex_load").unwrap().1;
        let text = "Ldalvik/system/InMemoryDexClassLoader;-><init>()";
        assert_eq!(
            first_match(text, dex_load),
            Some("InMemoryDexClassLoader;-><init>")
        );
        let keyguard = CATEGORIES.iter().find(|(c, _)| *c == "keyguard").unwrap().1;
        let lock = "Landroid/app/admin/DevicePolicyManager;->lockNow()";
        assert_eq!(
            first_match(lock, keyguard),
            Some("DevicePolicyManager;->lockNow")
        );
        assert_eq!(first_match("Lx;->y()", keyguard), None);
    }

    #[test]
    fn text_has_one_line_per_category() {
        let r = scan(&report(), &["Lcom/sdk/".to_string()]);
        let text = render(&r);
        assert_eq!(text.lines().count(), CATEGORIES.len());
        let sms = text.lines().find(|l| l.starts_with("sms ")).unwrap();
        assert!(sms.contains("1 site(s)"), "{sms}");
        assert!(sms.contains("ex : Lcom/evil/A;->run"), "{sms}");
        assert!(text
            .lines()
            .any(|l| l.starts_with("exec ") && l.ends_with('-')));
    }

    #[test]
    fn legend_defines_every_category_and_pattern() {
        let legend = legend();
        for (category, patterns) in CATEGORIES {
            assert!(legend.contains(category), "{category}");
            for pattern in *patterns {
                assert!(legend.contains(pattern), "{pattern}");
            }
        }
        for prefix in LIBRARY_PREFIXES {
            assert!(legend.contains(prefix), "{prefix}");
        }
        assert!(legend.contains("--capabilities-exclude"));
        assert!(legend.contains("PAS une preuve d'atteignabilité"));
    }
}
