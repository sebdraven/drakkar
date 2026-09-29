//! Points d'entrée DYNAMIQUES : composants Android atteints autrement que par
//! une déclaration au manifest.
//!
//! POURQUOI CE MODULE
//! ------------------
//! `CallGraph::entrypoints()` ne retient que les callbacks de cycle de vie dont
//! la classe figure dans les composants déclarés au manifest. Un receiver
//! enregistré à l'exécution par `registerReceiver`, ou une activité lancée par
//! `new Intent(ctx, X.class)`, n'est donc JAMAIS un point d'entrée — et tout ce
//! qu'il atteint est vu comme non atteignable.
//!
//! Deux impasses concrètes du corpus stalkerware viennent de là :
//!   - `com.cocospy.receivers.SMSReceiver` : classe complète, non déclarée au
//!     manifest, aucune référence trouvable — impossible de trancher entre
//!     « enregistrée dynamiquement » et « code mort ».
//!   - `com.ws.sc.monitor.MonitorCameraActivity` / `Camera2Activity` : lancées
//!     par une commande serveur, mais leur lanceur n'a jamais été localisé.
//!
//! CE QUE FAIT CE MODULE
//! ---------------------
//! Il rejoue le flot d'instructions de chaque méthode et, pour chaque appel à un
//! « sink » de composant (`registerReceiver`, `startActivity`, `Intent.<init>`,
//! `Class.forName`, …), remonte au littéral qui a alimenté l'argument :
//!   - `const-class vX, type@N`   -> descripteur de classe (cas majoritaire)
//!   - `const-string vX, string@N` -> nom de classe en clair (`Class.forName`)
//!
//! Le résultat s'ajoute à la liste des composants passée à
//! `CallGraph::entrypoints()`. Aucune autre logique n'est à modifier :
//! `reachability()` fonctionne alors sans changement sur ces classes.
//!
//! SUR-APPROXIMATION ASSUMÉE
//! -------------------------
//! On ne fait PAS de suivi de registre. On prend le littéral le plus proche en
//! amont, dans une fenêtre bornée (`MAX_LOOKBACK`). C'est volontairement
//! sur-approximant, dans le même esprit que `CallGraph::node()` qui fusionne les
//! surcharges sur `api()`. Conséquence : un faux positif possible quand un
//! `const-class` sans rapport précède immédiatement un sink. Le champ `via` et
//! le call site permettent de trancher à la main.
//!
//! CE QUE ÇA NE COUVRE PAS
//! -----------------------
//!   - classe passée par un champ, un tableau ou un paramètre (pas de littéral) ;
//!   - `ComponentName` construit à partir de deux `const-string` (partiellement
//!     couvert : on remonte la string la plus proche) ;
//!   - réflexion sur nom construit par concaténation.
//!
//! Ces cas ressortent en `unresolved` plutôt que d'être silencieusement perdus.

use crate::model::MethodRef;
use crate::parser::dex_facade::DexBin;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Fenêtre de remontée, en nombre d'instructions, entre le littéral et le sink.
/// 16 couvre très largement les séquences réelles (`new-instance`, `const-class`,
/// `invoke-direct <init>`), sans ratisser la moitié de la méthode.
const MAX_LOOKBACK: usize = 16;

/// Méthodes dont un argument désigne un composant Android.
/// Matching par nom de méthode seul (le récepteur varie : Context, Activity,
/// ContextWrapper, Intent…), cohérent avec le matching `class->name` du reste.
const COMPONENT_SINKS: &[&str] = &[
    // Receivers enregistrés à l'exécution.
    "registerReceiver",
    // Activités et services lancés explicitement.
    "startActivity",
    "startActivityForResult",
    "startService",
    "startForegroundService",
    "bindService",
    // Construction d'Intent explicite : new Intent(ctx, X.class).
    "<init>",
    "setClass",
    "setClassName",
    "setComponent",
    // Réflexion.
    "forName",
];

/// D'où vient la classe résolue. Toutes ne se valent pas : une seule est
/// approximative, et il faut pouvoir la distinguer à la lecture.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Provenance {
    /// `new-instance` : l'objet est construit sur place. Exact.
    NewInstance,
    /// `const-class` : la classe est un littéral. Exact.
    ConstClass,
    /// `const-string` : nom de classe textuel (réflexion). Exact si la chaîne
    /// est bien un nom de classe — vérifié par `looks_like_class_name`.
    ConstString,
    /// ⚠️ Type DÉCLARÉ d'un champ (`iget-object` / `sget-object`). Peut être une
    /// super-classe ou une interface (`Landroid/content/BroadcastReceiver;`)
    /// plutôt que la classe concrète. À lire comme une borne supérieure.
    FieldType,
    /// Classe CONCRÈTE assignée au champ, retrouvée en suivant les `iput-object`
    /// ailleurs dans le DEX jusqu'au `new-instance` source. Exact.
    FieldAssign,
    /// L'argument est **`this`** : la méthode s'enregistre elle-même. Résolu vers
    /// la classe de l'appelant. Exact — motif classique d'un receiver doté d'une
    /// méthode `start()` qui fait `context.registerReceiver(this, filter)`.
    ThisSelf,
    /// ⚠️ `android:onClick="foo"` dans un layout : le lien n'existe pas dans le
    /// bytecode. La classe est celle qui DÉCLARE une méthode `foo(View)` — sans
    /// resources.arsc on ne sait pas quelle Activity gonfle quel layout, donc
    /// toutes les déclarantes sont retenues (cf. `ui_callbacks`).
    XmlOnClick,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NewInstance => "new",
            Self::ConstClass => "class",
            Self::ConstString => "string",
            Self::FieldType => "field~",
            Self::FieldAssign => "field=",
            Self::ThisSelf => "this",
            Self::XmlOnClick => "xml",
        }
    }
}

/// Un point d'entrée découvert dynamiquement.
#[derive(Debug, Clone)]
pub struct DynEntrypoint {
    /// Descripteur Dalvik de la classe désignée, ex. `Lcom/x/SMSReceiver;`.
    pub class: String,
    /// Sink par lequel la classe est atteinte (`registerReceiver`, …).
    pub via: String,
    /// Méthode où se trouve le call site.
    pub caller: MethodRef,
    /// Offset du call site dans le caller.
    pub site: u64,
    /// D'où vient la classe — conditionne la confiance à lui accorder.
    pub provenance: Provenance,
}

/// Sinks rencontrés sans littéral résolvable en amont. Documente le trou au lieu
/// de le laisser béant — même esprit que le marqueur `unsupported` des règles.
/// Pourquoi un sink n'a pas été résolu. Un trou nommé vaut mieux qu'un trou muet :
/// c'est ce qui dira si l'approche mérite d'être poussée ou si elle plafonne.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnresolvedReason {
    /// Le registre cible n'est écrit NULLE PART dans la méthode : il vient donc
    /// d'un paramètre, ou c'est `this`. Cas majoritaire attendu pour
    /// `registerReceiver` (un receiver qui s'enregistre lui-même).
    Parameter,
    /// Le registre est alimenté depuis un champ (`iget-object` / `sget-object`).
    Field,
    /// Le registre reçoit le résultat d'un appel.
    CallResult,
    /// Écriture d'un type non traité.
    Other,
    /// Aucun index d'argument connu pour ce sink (recherche de proximité vaine).
    NoStrategy,
    /// ⚠️ PAS un échec : le call site ne peut structurellement PAS porter de
    /// littéral de classe. Trois cas — la surcharge appelée n'a pas assez
    /// d'arguments pour celui qu'on vise (`new Intent()`, `new Intent(String)`
    /// contre `new Intent(Context, Class)`) ; le registre visé est alimenté par
    /// une chaîne qui n'est pas un nom de classe (on a atterri sur une action ou
    /// une Uri) ; ou le sink reçoit un Intent déjà construit (`startActivity`),
    /// auquel cas l'information est au `<init>`, pas ici.
    /// **Ces cas ne sont PAS remontés** — les compter en échec noyait le signal.
    NotApplicable,
}

impl UnresolvedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parameter => "param-or-this",
            Self::Field => "field",
            Self::CallResult => "call-result",
            Self::Other => "other",
            Self::NoStrategy => "no-strategy",
            Self::NotApplicable => "n/a",
        }
    }
}

/// Motif d'échec d'une remontée : raison, registre visé, et **mnémonique de
/// l'instruction qui a bloqué**. Ce dernier est l'information qui manquait :
/// sans lui, `Other` est un fourre-tout et on ne sait pas si le rappel plafonne
/// ou s'il manque un cas fréquent et facile à traiter.
type Blocked = (UnresolvedReason, Option<u32>, Option<String>);

#[derive(Debug, Clone)]
pub struct UnresolvedSink {
    pub via: String,
    pub caller: MethodRef,
    pub site: u64,
    pub reason: UnresolvedReason,
    /// Registre cible, quand il est connu. `this` ou paramètre non distingués.
    pub target_reg: Option<u32>,
    /// Mnémonique de l'instruction qui écrit le registre cible sans qu'on sache
    /// en tirer une classe. C'est LUI qui dit quoi implémenter ensuite.
    pub blocking_insn: Option<String>,
    /// Chaîne brute des opérandes de l'invoke, telle que dex-bytecode la rend.
    pub raw_operands: String,
}

#[derive(Debug, Default)]
pub struct DynEntrypointReport {
    pub entrypoints: Vec<DynEntrypoint>,
    pub unresolved: Vec<UnresolvedSink>,
}

impl DynEntrypointReport {
    /// Liste dédoublonnée des descripteurs de classe, prête à être concaténée aux
    /// composants du manifest avant l'appel à `CallGraph::entrypoints()`.
    pub fn classes(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entrypoints.iter().map(|e| e.class.clone()).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Index champ -> classe CONCRÈTE qui lui est assignée.
///
/// Clé : l'index `field@N`. Valeur : `Some(descripteur)` si toutes les
/// assignations trouvées pointent vers la même classe, `None` si elles
/// divergent (champ réutilisé pour plusieurs types — ambigu, on ne conclut pas).
///
/// POURQUOI : le type DÉCLARÉ d'un champ de receiver est presque toujours
/// `Landroid/content/BroadcastReceiver;`, donc inutile. La classe concrète
/// n'apparaît qu'au `new-instance` qui alimente le `iput-object`, souvent dans
/// une autre méthode de la même classe.
pub type FieldAssignments = HashMap<u64, Option<String>>;

/// Passe 1 : indexe les assignations de champs par leur classe concrète.
///
/// Coût : une seconde passe de décodage sur tout le DEX. Assumé — c'est le seul
/// moyen d'obtenir la classe concrète d'un receiver détenu en champ.
pub(crate) fn index_field_assignments(dex: &DexBin) -> FieldAssignments {
    let mut map: FieldAssignments = HashMap::new();

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(_) => continue,
        };
        for method in &class.methods {
            let code = match &method.code {
                Some(c) => c,
                None => continue,
            };
            let instructions = match dex_bytecode::decode_all(code.insns, 0) {
                Ok(i) => i,
                Err(_) => continue,
            };

            for (i, ins) in instructions.iter().enumerate() {
                let m = ins.mnemonic();
                if !(m.starts_with("iput-object") || m.starts_with("sput-object")) {
                    continue;
                }
                let field_id = match operand_index(ins, "field@") {
                    Some(f) => f,
                    None => continue,
                };
                // `iput-object vSrc, vObj, field@N` / `sput-object vSrc, field@N`
                // -> la valeur assignée est le PREMIER registre.
                let src = match registers(ins).first().copied() {
                    Some(r) => r,
                    None => continue,
                };

                if let Some(concrete) = backtrack_new_instance(dex, &instructions[..i], src) {
                    match map.get(&field_id) {
                        // Déjà vu avec une AUTRE classe -> ambigu, on invalide.
                        Some(Some(prev)) if *prev != concrete => {
                            map.insert(field_id, None);
                        }
                        Some(None) => {} // déjà invalidé
                        _ => {
                            map.insert(field_id, Some(concrete));
                        }
                    }
                }
            }
        }
    }

    tracing::debug!(fields = map.len(), "field assignments indexed");
    map
}

/// Remonte au `new-instance` (ou `const-class`) qui alimente `target`, en
/// traçant les `move-object`. Utilisé par la passe 1, où l'on ne cherche que la
/// classe concrète d'une valeur assignée.
pub(crate) fn backtrack_new_instance(
    dex: &DexBin,
    window: &[dex_bytecode::Instruction],
    target: u32,
) -> Option<String> {
    let mut target = target;
    for ins in window.iter().rev() {
        // Une instruction qui n'écrit pas ne peut pas être la source : on la
        // TRAVERSE. C'est ce qui permet de franchir l'`invoke-direct <init>`
        // posé entre le `new-instance` et le `iput-object`.
        if !writes_register(ins) || dest_register(ins) != Some(target) {
            continue;
        }
        let m = ins.mnemonic();
        if m.starts_with("move-object") && !m.starts_with("move-result-object") {
            if let Some(&src) = registers(ins).get(1) {
                target = src;
            }
            continue;
        }
        if m.starts_with("new-instance") || m.starts_with("const-class") {
            let idx = operand_index(ins, "type@")?;
            return Some(dex.typ(idx as u32)?.to_string());
        }
        // Écriture d'une autre nature : on ne remonte pas plus loin.
        return None;
    }
    None
}

/// Scanne le DEX et renvoie les points d'entrée dynamiques.
pub fn extract(path: &Path) -> Result<DynEntrypointReport> {
    let dex = DexBin::open(path)?;

    let mut report = DynEntrypointReport::default();

    // Passe 1 : classe concrète assignée à chaque champ.
    let assignments = index_field_assignments(&dex);

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable class");
                continue;
            }
        };
        let class_name = class.descriptor.to_string();

        for method in &class.methods {
            let code = match &method.code {
                Some(c) => c,
                None => continue,
            };
            let caller = MethodRef {
                class: class_name.clone(),
                name: method.name.to_string(),
                descriptor: String::new(),
            };

            let instructions = match dex_bytecode::decode_all(code.insns, 0) {
                Ok(i) => i,
                Err(e) => {
                    tracing::debug!(method = %caller.api(), error = %e, "decode failed");
                    continue;
                }
            };

            // Registre portant `this`. En Dalvik les paramètres occupent les
            // registres HAUTS `[registers_size - ins_size, registers_size)` et
            // `this` est le premier d'entre eux. `ACC_STATIC` dit s'il y en a un.
            let this_reg = this_register(method.is_static, code.registers_size, code.ins_size);

            scan_method(
                &dex,
                &instructions,
                &caller,
                this_reg,
                &assignments,
                &mut report,
            );
        }
    }

    tracing::info!(
        entrypoints = report.entrypoints.len(),
        unresolved = report.unresolved.len(),
        "dynamic entrypoints extracted"
    );
    Ok(report)
}

/// Parcours d'une méthode : à chaque sink, remonte au littéral le plus proche.
fn scan_method(
    dex: &DexBin,
    instructions: &[dex_bytecode::Instruction],
    caller: &MethodRef,
    this_reg: Option<u32>,
    assignments: &FieldAssignments,
    report: &mut DynEntrypointReport,
) {
    for (i, ins) in instructions.iter().enumerate() {
        if !ins.mnemonic().starts_with("invoke-") {
            continue;
        }
        let via = match sink_name(dex, ins) {
            Some(v) => v,
            None => continue,
        };

        // Suivi de registre : la fenêtre courte n'a de sens que pour la recherche
        // de proximité. Dès qu'on suit un registre précis, on remonte TOUTE la
        // méthode — il n'y a plus de risque de confusion, et une écriture peut
        // être loin (allocation en début de méthode, usage à la fin).
        let spec = strategy_for(&via);
        let window: &[dex_bytecode::Instruction] = if spec.arg_reg.is_some() {
            &instructions[..i]
        } else {
            &instructions[i.saturating_sub(MAX_LOOKBACK)..i]
        };

        match backtrack_literal(
            dex,
            window,
            ins,
            &spec,
            assignments,
            this_reg,
            &caller.class,
        ) {
            Ok((class, provenance)) => report.entrypoints.push(DynEntrypoint {
                class,
                via,
                caller: caller.clone(),
                site: ins.offset as u64,
                provenance,
            }),
            Err((reason, target_reg, blocking_insn)) => {
                // Un call site qui ne peut pas porter de littéral de classe n'est
                // pas un échec de l'outil : on ne le remonte pas du tout.
                if reason != UnresolvedReason::NotApplicable {
                    report.unresolved.push(UnresolvedSink {
                        via,
                        caller: caller.clone(),
                        site: ins.offset as u64,
                        reason,
                        target_reg,
                        blocking_insn,
                        raw_operands: ins.operands().to_string(),
                    });
                }
            }
        }
    }
}

/// Si l'invoke cible un sink de composant, renvoie son nom de méthode.
fn sink_name(dex: &DexBin, ins: &dex_bytecode::Instruction) -> Option<String> {
    let idx = operand_index(ins, "method@")?;
    let item = dex.method_item(idx as u32)?;
    let name = item.name.to_string();

    if COMPONENT_SINKS.contains(&name.as_str()) {
        // `<init>` est trop générique seul : ne le retenir que pour Intent.
        if name == "<init>" && item.class != "Landroid/content/Intent;" {
            return None;
        }
        Some(name)
    } else {
        None
    }
}

/// Instruction porteuse du littéral recherché, selon le sink.
#[derive(Copy, Clone, PartialEq)]
enum LiteralKind {
    /// `new-instance vX, type@N` — l'objet lui-même est construit sur place.
    /// C'est le cas de `registerReceiver` : le receiver est un objet, pas une
    /// classe. Chercher un `const-class` ici ramène le filtre, pas le receiver.
    NewInstance,
    /// `const-class vX, type@N` — la classe est passée comme littéral.
    ConstClass,
    /// `const-string vX, string@N` — nom de classe en clair (réflexion).
    ConstString,
}

/// Où chercher le littéral, et dans QUEL registre.
///
/// `arg_reg` est l'index du registre pertinent dans la liste d'opérandes de
/// l'invoke. Pour un `invoke-virtual`, l'index 0 est l'objet receveur (le
/// `Context`), donc le premier argument est à l'index 1. Pour un `invoke-static`
/// il n'y a pas de receveur : l'argument 0 est à l'index 0.
///
/// Sans cet index, toute heuristique de proximité échoue : il y a toujours un
/// objet construit plus près de l'appel que celui qu'on cherche. Sur
/// `registerReceiver(receiver, filter)`, le `new-instance` le plus proche est
/// systématiquement l'`IntentFilter`.
struct SinkSpec {
    kinds: &'static [LiteralKind],
    arg_reg: Option<usize>,
}

fn strategy_for(sink: &str) -> SinkSpec {
    match sink {
        // registerReceiver(BroadcastReceiver, IntentFilter) sur un Context.
        // {vContext, vReceiver, vFilter} -> le receiver est à l'index 1.
        "registerReceiver" => SinkSpec {
            kinds: &[LiteralKind::NewInstance],
            arg_reg: Some(1),
        },
        // Class.forName(String) : statique, l'argument 0 est à l'index 0.
        "forName" => SinkSpec {
            kinds: &[LiteralKind::ConstString],
            arg_reg: Some(0),
        },
        // new Intent(Context, Class) : invoke-direct {vIntent, vCtx, vClass}.
        // setClass(Context, Class) : invoke-virtual {vIntent, vCtx, vClass}.
        "<init>" | "setClass" => SinkSpec {
            kinds: &[LiteralKind::ConstClass],
            arg_reg: Some(2),
        },
        // setClassName(Context, String) : même position, littéral textuel.
        "setClassName" => SinkSpec {
            kinds: &[LiteralKind::ConstString],
            arg_reg: Some(2),
        },
        // Les autres (startActivity, startService, bindService, setComponent)
        // reçoivent un Intent déjà construit : pas de littéral de classe au call
        // site. On garde une recherche de proximité, faible et assumée comme
        // telle — c'est `<init>` qui porte l'information utile pour ces cas.
        _ => SinkSpec {
            kinds: &[LiteralKind::ConstClass],
            arg_reg: None,
        },
    }
}

/// Extrait la liste des registres `vN` d'une instruction, dans l'ordre.
/// Les marqueurs `type@`, `method@`, `string@` ne contiennent pas de `v` suivi
/// de chiffres, ils ne polluent donc pas l'extraction.
pub(crate) fn registers(ins: &dex_bytecode::Instruction) -> Vec<u32> {
    let ops = ins.operands();
    let bytes: Vec<char> = ops.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 'v' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut n = 0u32;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                n = n * 10 + bytes[i].to_digit(10).unwrap_or(0);
                i += 1;
            }
            out.push(n);
        } else {
            i += 1;
        }
    }
    out
}

/// Registre portant `this`, ou `None` si la méthode est statique.
///
/// Les paramètres occupent les registres hauts `[regs - ins, regs)` et `this`
/// est le premier. `ins_size == 0` sur une méthode d'instance est malformé :
/// on refuse plutôt que de rendre un registre hors plage.
pub(crate) fn this_register(is_static: bool, registers_size: u16, ins_size: u16) -> Option<u32> {
    if is_static || ins_size == 0 || registers_size < ins_size {
        return None;
    }
    Some((registers_size - ins_size) as u32)
}

/// Registre de destination d'une instruction d'écriture : le premier `vN`.
/// ⚠️ N'a de sens QUE si `writes_register(ins)` est vrai.
pub(crate) fn dest_register(ins: &dex_bytecode::Instruction) -> Option<u32> {
    registers(ins).first().copied()
}

/// L'instruction DÉFINIT-elle un registre ?
///
/// Le premier `vN` n'est une destination que pour les instructions qui écrivent.
/// Pour un **`invoke-*`** c'est l'objet appelé (ou le 1er argument), pour un
/// **`iput`/`sput`/`aput`** c'est la valeur stockée, pour un **`if-*`** un
/// opérande de comparaison. Les confondre casse toute remontee de registre :
/// on croit voir une écriture là où il n'y en a pas, et on s'arrête une
/// instruction trop tôt — typiquement sur l'`invoke-direct <init>` qui suit
/// immédiatement le `new-instance` recherché.
///
/// Liste en négatif : plus courte et plus sûre que d'énumérer tout ce qui écrit.
pub(crate) fn writes_register(ins: &dex_bytecode::Instruction) -> bool {
    let m = ins.mnemonic();
    !(m.starts_with("invoke-")
        || m.starts_with("iput")
        || m.starts_with("sput")
        || m.starts_with("aput")
        || m.starts_with("if-")
        || m.starts_with("goto")
        || m.starts_with("return")
        || m.starts_with("throw")
        || m.starts_with("monitor-")
        || m.starts_with("nop")
        || m.starts_with("check-cast")
        || m.starts_with("packed-switch")
        || m.starts_with("sparse-switch")
        || m.starts_with("fill-array-data"))
}

/// Remonte à la recherche du littéral attendu.
///
/// Si `arg_reg` est fourni, on suit le REGISTRE : dernière écriture dans ce
/// registre, en traçant les `move-object`. Sinon, proximité simple.
///
/// `Ok((descripteur, provenance))` ou `Err((raison, registre, mnémonique bloquant))`.
fn backtrack_literal(
    dex: &DexBin,
    window: &[dex_bytecode::Instruction],
    invoke: &dex_bytecode::Instruction,
    spec: &SinkSpec,
    assignments: &FieldAssignments,
    this_reg: Option<u32>,
    caller_class: &str,
) -> Result<(String, Provenance), Blocked> {
    let mut target = match spec.arg_reg {
        Some(idx) => match registers(invoke).get(idx) {
            Some(&r) => Some(r),
            None => {
                // Moins de registres que l'argument visé : ce n'est PAS la
                // surcharge qu'on cible. `new Intent()` et `new Intent(String)`
                // ne portent aucune classe — les compter en échec fabriquait
                // 712 faux négatifs sur `cocospy_galaxy`, soit 41 % du total.
                return Err((UnresolvedReason::NotApplicable, None, None));
            }
        },
        None => None,
    };

    for ins in window.iter().rev() {
        let m = ins.mnemonic();

        if let Some(t) = target {
            // Idem : traverser tout ce qui n'écrit pas de registre.
            if !writes_register(ins) {
                continue;
            }
            match dest_register(ins) {
                Some(d) if d == t => {}
                _ => continue,
            }
            if m.starts_with("move-object") || m.starts_with("move-result-object") {
                if m.starts_with("move-result-object") {
                    return Err((UnresolvedReason::CallResult, target, Some(m.to_string())));
                }
                if let Some(&src) = registers(ins).get(1) {
                    target = Some(src);
                }
                continue;
            }
            if m.starts_with("iget-object") || m.starts_with("sget-object") {
                if let Some(idx) = operand_index(ins, "field@") {
                    // 1) Classe CONCRÈTE assignée ailleurs dans le DEX — exact.
                    if let Some(Some(concrete)) = assignments.get(&idx) {
                        return Ok((concrete.clone(), Provenance::FieldAssign));
                    }
                    // 2) Repli : type DÉCLARÉ du champ — souvent abstrait, donc
                    //    marqué `field~` pour ne jamais être pris pour un fait.
                    if let Some(item) = dex.field_item(idx as u32) {
                        return Ok((item.typ.to_string(), Provenance::FieldType));
                    }
                }
                return Err((UnresolvedReason::Field, target, Some(m.to_string())));
            }
        }

        if let Some(found) = literal_of(dex, ins, spec.kinds) {
            return Ok(found);
        }

        if target.is_some() {
            // Un `const-string` qui n'est pas un nom de classe signifie qu'on a
            // atterri sur un argument textuel (action d'Intent, Uri) : mauvaise
            // surcharge, pas échec de remontée.
            // Idem `const/4` : c'est un `null` ou un petit entier — jamais une
            // classe. Typiquement `new Intent(action, null)` ou un argument
            // numérique atteint par une surcharge qu'on ne visait pas.
            if m.starts_with("const-string") || m.starts_with("const/4") {
                return Err((UnresolvedReason::NotApplicable, target, None));
            }
            // Le vrai seau : le mnémonique exact permet de décider quoi traiter.
            return Err((UnresolvedReason::Other, target, Some(m.to_string())));
        }
    }

    // Aucune écriture du registre dans toute la méthode : c'est un paramètre,
    // ou `this`. Les paramètres occupent les registres HAUTS en Dalvik.
    match target {
        // `this` : la méthode s'enregistre elle-même. La classe de l'appelant
        // EST la réponse — motif `Receiver.start() { ctx.registerReceiver(this, f) }`.
        Some(t) if Some(t) == this_reg => Ok((caller_class.to_string(), Provenance::ThisSelf)),
        // Un autre paramètre : il faudrait remonter aux appelants (interprocédural).
        Some(_) => Err((UnresolvedReason::Parameter, target, None)),
        // Sink sans index d'argument (`startActivity`, `startService`…) : il
        // reçoit un Intent déjà construit. L'information est au `<init>`, pas
        // ici — ce n'est pas un échec.
        None => Err((UnresolvedReason::NotApplicable, None, None)),
    }
}

/// Lit le littéral porté par une instruction, si son type est accepté.
fn literal_of(
    dex: &DexBin,
    ins: &dex_bytecode::Instruction,
    kinds: &[LiteralKind],
) -> Option<(String, Provenance)> {
    let m = ins.mnemonic();

    if kinds.contains(&LiteralKind::NewInstance) && m.starts_with("new-instance") {
        let idx = operand_index(ins, "type@")?;
        let t = dex.typ(idx as u32)?.to_string();
        return Some((t, Provenance::NewInstance));
    }
    if kinds.contains(&LiteralKind::ConstClass) && m.starts_with("const-class") {
        let idx = operand_index(ins, "type@")?;
        let t = dex.typ(idx as u32)?.to_string();
        return Some((t, Provenance::ConstClass));
    }
    if kinds.contains(&LiteralKind::ConstString) && m.starts_with("const-string") {
        let idx = operand_index(ins, "string@")?;
        let s = dex.string(idx as u32)?.to_string();
        if looks_like_class_name(&s) {
            return Some((to_descriptor(&s), Provenance::ConstString));
        }
    }
    None
}

/// Extrait l'entier d'un opérande textuel de la forme `<tag>N`.
/// dex-bytecode formate les opérandes en texte ; même approche que
/// `parser::dex::invoke_method_index`. L'amont n'expose toujours pas d'accès
/// structuré à l'index.
pub(crate) fn operand_index(ins: &dex_bytecode::Instruction, tag: &str) -> Option<u64> {
    let ops = ins.operands();
    let pos = ops.find(tag)? + tag.len();
    let digits: String = ops[pos..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Heuristique : `com.x.Y` ressemble à un nom de classe, `hello world` non.
/// Rejette aussi les actions d'intent, dont le dernier segment est en capitales
/// (`android.intent.action.SCREEN_OFF`) — une classe ne se nomme pas ainsi.
fn looks_like_class_name(s: &str) -> bool {
    if !(s.contains('.')
        && !s.contains(' ')
        && !s.contains('/')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '$')
        && s.split('.').count() >= 2)
    {
        return false;
    }
    let last = s.rsplit('.').next().unwrap_or_default();
    let has_lower = last.chars().any(|c| c.is_ascii_lowercase());
    let starts_upper = last.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    starts_upper && has_lower
}

/// `com.x.Y` -> `Lcom/x/Y;`
fn to_descriptor(dotted: &str) -> String {
    format!("L{};", dotted.replace('.', "/"))
}

/// Variante prenant un APK : dézippe les `classes*.dex` dans un tempdir et
/// agrège le rapport sur l'ensemble des DEX. Passe par
/// `parser::extract_dex_files` pour hériter du repli `TolerantZip` sur les
/// archives trafiquées.
pub fn extract_from_apk(apk: &Path) -> Result<DynEntrypointReport> {
    let tmp = tempfile::tempdir().context("create tempdir")?;
    let dex_files = crate::parser::extract_dex_files(apk, tmp.path())?;

    let mut merged = DynEntrypointReport::default();

    for dex in &dex_files {
        let r = extract(dex).with_context(|| format!("scan {}", dex.display()))?;
        merged.entrypoints.extend(r.entrypoints);
        merged.unresolved.extend(r.unresolved);
    }

    Ok(merged)
}

/// Nature du fichier d'entrée, reconnue au **contenu** et jamais à l'extension —
/// les corpus nommés par hash n'en ont pas, et les DEX déballés portent des noms
/// arbitraires (`mem_<adresse>_<taille>.dex`, `classes_unpacked.dex`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// Archive zip contenant un `AndroidManifest.xml`.
    Apk,
    /// DEX brut : magic `dex\n` suivi de la version (`035`, `037`, `038`, `039`).
    Dex,
}

/// Renifle la nature d'un fichier sur ses premiers octets.
pub fn sniff(path: &Path) -> Option<InputKind> {
    use std::io::Read;

    let mut f = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return None;
    }
    match &magic {
        b"PK\x03\x04" => Some(InputKind::Apk),
        b"dex\n" => Some(InputKind::Dex),
        _ => None,
    }
}

/// Point d'entrée unique : accepte un **APK** ou un **DEX brut**, et route.
///
/// C'est ce qui rend le pan packé du corpus analysable : sur un échantillon sous
/// Jiagu ou SecNeo, l'archive ne contient pas le vrai DEX, mais celui-ci existe
/// une fois déballé (`classes_unpacked.dex`, dumps mémoire Frida). Il suffit de
/// le passer directement.
pub fn extract_any(path: &Path) -> Result<DynEntrypointReport> {
    match sniff(path) {
        Some(InputKind::Apk) => extract_from_apk(path),
        Some(InputKind::Dex) => extract(path),
        None => anyhow::bail!(
            "{} n'est ni un APK (PK\\x03\\x04) ni un DEX (dex\\n) — reconnu au contenu, \
             l'extension n'entre pas en compte",
            path.display()
        ),
    }
}

/// Collecte les entrées analysables d'un répertoire : APK **et** DEX bruts.
///
/// Distinct de `bulk::collect_apks`, qui n'accepte que des APK — ici on veut
/// aussi pouvoir balayer un répertoire de DEX déballés.
pub fn collect_inputs(dir: &Path, recursive: bool) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    if recursive {
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if p.is_file() && sniff(p).is_some() {
                out.push(p.to_path_buf());
            }
        }
    } else {
        for entry in std::fs::read_dir(dir)? {
            let p = entry?.path();
            if p.is_file() && sniff(&p).is_some() {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_conversion() {
        assert_eq!(
            to_descriptor("com.cocospy.receivers.SMSReceiver"),
            "Lcom/cocospy/receivers/SMSReceiver;"
        );
    }

    #[test]
    fn this_register_suit_acc_static() {
        // Méthode d'instance `void f(Object)` : regs=4, ins=2 -> this en v2.
        assert_eq!(this_register(false, 4, 2), Some(2));
        // Même forme, mais statique : pas de `this`.
        assert_eq!(this_register(true, 4, 2), None);
        // `ins_size == 0` sur une méthode d'instance est malformé.
        assert_eq!(this_register(false, 4, 0), None);
        // `ins_size > registers_size` est malformé.
        assert_eq!(this_register(false, 2, 4), None);
        // Méthode d'instance sans paramètre : regs=1, ins=1 -> this en v0.
        assert_eq!(this_register(false, 1, 1), Some(0));
    }

    #[test]
    fn class_name_heuristic() {
        assert!(looks_like_class_name("com.cocospy.receivers.SMSReceiver"));
        assert!(!looks_like_class_name("android.intent.action.SCREEN_OFF"));
        assert!(!looks_like_class_name(
            "android.provider.Telephony.SMS_RECEIVED"
        ));
        assert!(!looks_like_class_name("com.cocospy.filldb.finish"));
        assert!(!looks_like_class_name("hello world"));
        assert!(!looks_like_class_name("plugin.apk"));
    }
}
