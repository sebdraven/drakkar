//! Jointure DEX -> `resources.arsc` : quelle classe, quelle méthode référence
//! quelle ressource.
//!
//! # Le problème
//!
//! Un identifiant croisé dans le code (`0x7f110228`) ne dit rien tout seul. La
//! table des ressources sait le nommer et lui donner sa valeur ; il manque le
//! lien entre les deux, c'est-à-dire le balayage du bytecode.
//!
//! # Ce qui est lu
//!
//! Trois porteurs d'identifiant, et seulement eux :
//!
//!   - `const vAA, #+BBBBBBBB` (0x14) et `const/high16 vAA, #+BBBB0000` (0x15).
//!     C'est sous cette forme que R8 inline les champs de `R` ;
//!   - les `fill-array-data-payload`, qui portent les tableaux d'identifiants
//!     (`R.styleable.*`). Pas de registre, pas de contexte d'appel : ces
//!     usages ne sont jamais corroborés (voir plus bas) ;
//!   - les `sget` sur un champ de `R`, pour les APK non minifiés — voir plus bas.
//!
//! Dans les deux premiers cas la valeur est relue dans les OCTETS de
//! l'instruction, pas dans le texte d'opérande formaté par `dex-bytecode` : le
//! rendu d'un littéral n'est pas un format documenté et changerait sans préavis.
//!
//! # Le piège : tous ces entiers ne sont pas des ressources
//!
//! Beaucoup de constantes de la forme `0x7f……` sont des offsets, des masques ou
//! des constantes quelconques. Le filtre retenu est celui de l'énoncé : ne
//! garder que les valeurs qui existent RÉELLEMENT dans la table parsée, et
//! restreindre les candidats aux octets de poids fort des packages réellement
//! présents (un `0x0104…` du framework n'est donc pas candidat).
//!
//! Ce filtre ne peut pas être exact : un masque qui tombe pile sur un
//! identifiant valide passe. D'où la colonne `consommateur`, qui ne filtre RIEN
//! mais mesure : la constante est-elle passée, dans les [`WINDOW`] instructions
//! qui suivent et avant réécriture de son registre, à une API qui prend un
//! identifiant de ressource ([`RESOURCE_APIS`]) ? Un usage corroboré est un vrai
//! positif ; les autres sont indéterminés. [`XrefStats`] porte les trois
//! comptes, ce qui donne un encadrement du taux de faux positifs plutôt qu'une
//! affirmation.
//!
//! # Le second canal : les champs de la classe R
//!
//! Sur un APK NON minifié, le code ne porte pas de littéral : il fait
//! `sget v0, Lcom/x/R$string;->foo:I`, et la valeur du champ vit dans
//! `encoded_static_values` du `class_def_item` — invisible à tout balayage
//! d'instructions (c'est l'angle mort que CLAUDE.md signale pour les
//! `static final String` de `diff_dex` et `diff_explain`).
//!
//! D'où la première passe : les champs statiques entiers de valeur initiale dans
//! la plage d'un package sont indexés par (classe, nom), et chaque `sget` qui
//! les lit devient un usage ([`UseOrigin::StaticField`]). Sans elle,
//! `--resource-xref` ne rendrait presque rien sur ces binaires et
//! `--resource-orphans` les déclarerait tous orphelins.
//!
//! Symétriquement, une constante littérale trouvée DANS une classe `R` n'est pas
//! un usage : c'est la table qui se recopie elle-même (les `R` non finales sont
//! initialisées par `<clinit>`). Ces constantes sont comptées à part
//! ([`XrefStats::r_class_defs`]) et n'entrent ni dans les candidats, ni dans les
//! usages — sinon aucune ressource ne serait jamais orpheline.
//!
//! # Ce qui reste hors de portée
//!
//! Un identifiant calculé à l'exécution (`getIdentifier("nom", …)`), ou passé
//! de méthode en méthode avant d'être consommé. Le premier est indétectable par
//! construction ; le second sort quand même, mais sans corroboration.

use super::arsc::{ResourceEntry, ResourceTable};
use super::disasm::{resolve, Operand};
use super::dex_facade::{DexBin, DexValue};
use super::dyn_entrypoints::{dest_register, registers, writes_register};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// `const vAA, #+BBBBBBBB`.
const OP_CONST: u8 = 0x14;
/// `const/high16 vAA, #+BBBB0000`.
const OP_CONST_HIGH16: u8 = 0x15;

const PAYLOAD_MNEMONIC: &str = "fill-array-data-payload";

/// Instructions examinées après une constante pour retrouver son consommateur.
/// Au-delà, la valeur a presque toujours transité par un champ ou un appel
/// intermédiaire, et la corroboration intra-méthode ne dit plus rien.
pub const WINDOW: usize = 8;

/// Méthodes qui prennent un identifiant de ressource en argument. La
/// comparaison porte sur le NOM seul, sans la classe : `Resources.getString`,
/// `Context.getString`, `ContextCompat.getColor` et les wrappers de bibliothèque
/// doivent tous compter. Liste de corroboration, jamais de filtrage.
pub const RESOURCE_APIS: &[&str] = &[
    "findViewById",
    "requireViewById",
    "getBoolean",
    "getColor",
    "getColorStateList",
    "getDimension",
    "getDimensionPixelOffset",
    "getDimensionPixelSize",
    "getDrawable",
    "getFont",
    "getIntArray",
    "getInteger",
    "getLayout",
    "getQuantityString",
    "getQuantityText",
    "getString",
    "getStringArray",
    "getText",
    "getTextArray",
    "getXml",
    "inflate",
    "openRawResource",
    "openRawResourceFd",
    "setBackgroundResource",
    "setContentView",
    "setIcon",
    "setImageResource",
    "setMessage",
    "setNegativeButton",
    "setNeutralButton",
    "setPositiveButton",
    "setSmallIcon",
    "setText",
    "setTheme",
    "setTitle",
];

/// Par quoi la constante est portée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UseOrigin {
    /// `const` / `const/high16`.
    Const,
    /// Élément d'un `fill-array-data-payload` (tableau d'identifiants).
    ArrayPayload,
    /// `sget` sur un champ statique entier de la classe `R`, dont la valeur
    /// vient d'`encoded_static_values`.
    StaticField,
}

impl UseOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Const => "const",
            Self::ArrayPayload => "tableau",
            Self::StaticField => "sget",
        }
    }

    /// Vrai pour les origines qui lisent un LITTÉRAL dans le flux
    /// d'instructions — les seules soumises au filtrage par plage, donc les
    /// seules à alimenter les compteurs de bruit.
    fn is_literal(self) -> bool {
        matches!(self, Self::Const | Self::ArrayPayload)
    }
}

/// Un usage : une constante du DEX qui désigne une entrée de la table.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceUse {
    pub class: String,
    pub method: String,
    /// Offset de l'instruction dans le code de la méthode.
    pub site: u64,
    #[serde(serialize_with = "crate::parser::arsc::as_hex")]
    pub id: u32,
    #[serde(rename = "type")]
    pub type_name: String,
    pub name: String,
    pub value: Option<String>,
    pub origin: UseOrigin,
    /// API consommatrice trouvée dans la fenêtre, `None` si aucune.
    pub consumer: Option<String>,
}

impl ResourceUse {
    pub fn id_hex(&self) -> String {
        format!("{:#010x}", self.id)
    }

    pub fn value_tsv(&self) -> String {
        match &self.value {
            Some(v) => v.replace(['\n', '\r', '\t'], " "),
            None => String::new(),
        }
    }
}

/// Ce que le balayage a vu, et ce qu'il a écarté. Sert à encadrer le taux de
/// faux positifs : voir [`legend`].
#[derive(Debug, Default, Clone, Serialize)]
pub struct XrefStats {
    pub dex_files: usize,
    pub classes: usize,
    pub methods: usize,
    /// Constantes entières lues, toutes valeurs confondues.
    pub integers: usize,
    /// Celles dont l'octet de poids fort est un package de la table.
    pub candidates: usize,
    /// Candidates qui désignent une entrée réelle. `uses.len()` vaut
    /// `matched + via_static_field`.
    pub matched: usize,
    /// Candidates SANS entrée correspondante : du bruit, démontré comme tel.
    pub rejected: usize,
    /// Valeurs distinctes parmi les rejetées.
    pub distinct_rejected: usize,
    /// Usages passés par un `sget` sur un champ de `R`. Hors du filtrage par
    /// plage : la valeur vient de la table des champs, pas d'un littéral.
    pub via_static_field: usize,
    /// Champs statiques entiers indexés dans la plage d'un package.
    pub static_fields_indexed: usize,
    /// Constantes de la plage trouvées DANS une classe `R` : la table qui se
    /// recopie, pas un usage. Ni candidates, ni retenues.
    pub r_class_defs: usize,
    /// Usages retenus ET passés à une API consommatrice dans la fenêtre.
    pub corroborated: usize,
    /// Identifiants distincts effectivement référencés.
    pub distinct_ids: usize,
    /// Méthodes dont le bytecode n'a pas pu être décodé.
    pub decode_failures: usize,
}

impl XrefStats {
    /// Part des candidates écartées par la jointure, en pourcentage. C'est la
    /// mesure du bruit que le filtre retire.
    pub fn rejection_rate(&self) -> f64 {
        if self.candidates == 0 {
            return 0.0;
        }
        100.0 * self.rejected as f64 / self.candidates as f64
    }

    /// Lignes émises : les deux canaux réunis.
    pub fn total_uses(&self) -> usize {
        self.matched + self.via_static_field
    }

    /// Part des usages corroborés par une API consommatrice.
    pub fn corroboration_rate(&self) -> f64 {
        if self.total_uses() == 0 {
            return 0.0;
        }
        100.0 * self.corroborated as f64 / self.total_uses() as f64
    }

    /// MAJORANT du taux de faux positifs résiduel : la part des usages
    /// qu'aucune API consommatrice ne confirme. Ce n'est pas une estimation du
    /// taux réel — un usage non corroboré peut parfaitement être authentique.
    pub fn residual_fp_bound(&self) -> f64 {
        if self.total_uses() == 0 {
            return 0.0;
        }
        100.0 - self.corroboration_rate()
    }
}

#[derive(Debug, Default, Serialize)]
pub struct XrefReport {
    pub uses: Vec<ResourceUse>,
    pub stats: XrefStats,
    #[serde(skip)]
    used: HashSet<u32>,
}

impl XrefReport {
    /// Identifiants référencés au moins une fois depuis le code.
    pub fn used_ids(&self) -> &HashSet<u32> {
        &self.used
    }
}

/// Ressources qu'AUCUNE constante du DEX ne référence.
///
/// « Orpheline » veut dire « non référencée DEPUIS LE CODE ». Une ressource
/// citée par un layout, par un style ou par le manifeste est orpheline ici tout
/// en étant parfaitement utilisée.
pub fn orphans<'a>(table: &'a ResourceTable, report: &XrefReport) -> Vec<&'a ResourceEntry> {
    table
        .entries
        .iter()
        .filter(|e| !report.used.contains(&e.id))
        .collect()
}

/// Balaye les `classes*.dex` d'un APK et joint les constantes contre `table`.
pub fn scan(apk: &Path, table: &ResourceTable) -> Result<XrefReport> {
    let tmp = tempfile::tempdir().context("create tempdir")?;
    let dex_files = crate::parser::extract_dex_files(apk, tmp.path())?;

    let mut report = XrefReport::default();
    let mut rejected: HashSet<u32> = HashSet::new();

    for path in &dex_files {
        report.stats.dex_files += 1;
        if let Err(e) = scan_dex(path, table, &mut report, &mut rejected) {
            tracing::warn!(dex = %path.display(), error = %e, "DEX ignoré");
        }
    }

    report.stats.matched = report.uses.len() - report.stats.via_static_field;
    report.stats.distinct_rejected = rejected.len();
    report.stats.distinct_ids = report.used.len();
    report.stats.corroborated = report
        .uses
        .iter()
        .filter(|u| u.consumer.is_some())
        .count();

    tracing::info!(
        uses = report.uses.len(),
        candidates = report.stats.candidates,
        rejected = report.stats.rejected,
        corroborated = report.stats.corroborated,
        "xref ressources"
    );
    Ok(report)
}

fn scan_dex(
    path: &Path,
    table: &ResourceTable,
    report: &mut XrefReport,
    rejected: &mut HashSet<u32>,
) -> Result<()> {
    let dex = DexBin::open(path)?;

    // Passe 1 : valeur des champs statiques entiers, par (classe, nom). C'est
    // le seul moyen d'atteindre `encoded_static_values`, où vivent les
    // identifiants des APK non minifiés. Seconde passe de décodage sur tout le
    // DEX, même coût assumé que dans `ui_callbacks`.
    let statics = index_static_ints(&dex, table);
    report.stats.static_fields_indexed += statics.len();

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(_) => continue,
        };
        report.stats.classes += 1;
        let class_name = class.descriptor.to_string();
        let in_r_class = is_r_class(&class_name);

        for method in &class.methods {
            let Some(code) = &method.code else { continue };
            report.stats.methods += 1;

            let bytes = code.insns;
            let instructions = match dex_bytecode::decode_all(bytes, 0) {
                Ok(i) => i,
                Err(_) => {
                    report.stats.decode_failures += 1;
                    continue;
                }
            };
            let method_name = method.name.to_string();

            for (i, ins) in instructions.iter().enumerate() {
                let mnemonic = ins.mnemonic();

                if mnemonic == PAYLOAD_MNEMONIC {
                    for value in payload_ints(bytes, ins.offset as usize) {
                        record(
                            table,
                            report,
                            rejected,
                            Site {
                                class: &class_name,
                                method: &method_name,
                                offset: ins.offset as u64,
                                in_r_class,
                            },
                            value,
                            UseOrigin::ArrayPayload,
                            None,
                        );
                    }
                    continue;
                }

                // `sget` sur un champ de R : la valeur ne figure nulle part dans
                // le flux d'instructions, elle vient de la passe 1.
                if mnemonic.starts_with("sget") {
                    let Some(Operand::Field(owner, name, _)) = resolve(&dex, ins) else {
                        continue;
                    };
                    let Some(value) = statics.get(&(owner, name)).copied() else {
                        continue;
                    };
                    let consumer = dest_register(ins)
                        .and_then(|reg| find_consumer(&dex, &instructions, i, reg));
                    record(
                        table,
                        report,
                        rejected,
                        Site {
                            class: &class_name,
                            method: &method_name,
                            offset: ins.offset as u64,
                            in_r_class,
                        },
                        value,
                        UseOrigin::StaticField,
                        consumer,
                    );
                    continue;
                }

                let Some(value) = const_literal(bytes, ins.opcode(), ins.offset as usize) else {
                    continue;
                };
                let consumer = dest_register(ins)
                    .and_then(|reg| find_consumer(&dex, &instructions, i, reg));
                record(
                    table,
                    report,
                    rejected,
                    Site {
                        class: &class_name,
                        method: &method_name,
                        offset: ins.offset as u64,
                        in_r_class,
                    },
                    value,
                    UseOrigin::Const,
                    consumer,
                );
            }
        }
    }
    Ok(())
}

/// Où la constante a été lue.
struct Site<'a> {
    class: &'a str,
    method: &'a str,
    offset: u64,
    /// La classe est une classe `R` : ce qu'on y lit est la définition de la
    /// table, pas un usage.
    in_r_class: bool,
}

/// Compte la constante, puis ne retient que celles qui désignent une entrée.
fn record(
    table: &ResourceTable,
    report: &mut XrefReport,
    rejected: &mut HashSet<u32>,
    site: Site<'_>,
    value: u32,
    origin: UseOrigin,
    consumer: Option<String>,
) {
    let literal = origin.is_literal();
    if literal {
        report.stats.integers += 1;
        if !table.in_package_range(value) {
            return;
        }
        if site.in_r_class {
            report.stats.r_class_defs += 1;
            return;
        }
        report.stats.candidates += 1;
    } else if site.in_r_class {
        return;
    }

    let Some(entry) = table.by_id(value) else {
        if literal {
            report.stats.rejected += 1;
            rejected.insert(value);
        }
        return;
    };
    if !literal {
        report.stats.via_static_field += 1;
    }

    report.used.insert(value);
    report.uses.push(ResourceUse {
        class: site.class.to_string(),
        method: site.method.to_string(),
        site: site.offset,
        id: entry.id,
        type_name: entry.type_name.clone(),
        name: entry.name.clone(),
        value: entry.value.clone(),
        origin,
        consumer,
    });
}

/// Valeur initiale des champs statiques entiers, par (classe, nom du champ).
///
/// Restreinte à la plage des packages de la table : un `static final int`
/// quelconque n'a rien à faire dans l'index, et sa présence ferait passer pour
/// une ressource le premier `sget` venu.
fn index_static_ints(
    dex: &DexBin,
    table: &ResourceTable,
) -> HashMap<(String, String), u32> {
    let mut out = HashMap::new();
    for class in dex.classes() {
        let Ok(class) = class else { continue };
        // Un class_data illisible saute la classe, il ne tue pas le balayage.
        let Ok(fields) = dex.static_fields(&class) else { continue };
        let owner = class.descriptor.to_string();
        for field in fields {
            let Some(DexValue::Int(v)) = field.value else {
                continue;
            };
            let value = v as u32;
            if table.in_package_range(value) {
                out.insert((owner.clone(), field.name), value);
            }
        }
    }
    out
}

/// Vrai pour `Lcom/x/R;` et `Lcom/x/R$string;` — les classes générées par aapt
/// qui portent les identifiants, et où une constante n'est pas un usage.
fn is_r_class(descriptor: &str) -> bool {
    let body = descriptor.trim_start_matches('L').trim_end_matches(';');
    let last = body.rsplit('/').next().unwrap_or_default();
    last == "R" || last.starts_with("R$")
}

/// Littéral d'un `const` / `const/high16`, relu dans les octets.
fn const_literal(bytes: &[u8], opcode: u8, at: usize) -> Option<u32> {
    match opcode {
        OP_CONST => u32_at(bytes, at + 2),
        OP_CONST_HIGH16 => u16_at(bytes, at + 2).map(|v| (v as u32) << 16),
        _ => None,
    }
}

/// Éléments 32 bits d'un `fill-array-data-payload`. Les autres largeurs
/// d'élément (1, 2, 8 octets) ne peuvent pas porter d'identifiant.
fn payload_ints(bytes: &[u8], at: usize) -> Vec<u32> {
    let width = u16_at(bytes, at + 2).unwrap_or(0);
    if width != 4 {
        return Vec::new();
    }
    let count = u32_at(bytes, at + 4).unwrap_or(0) as usize;
    (0..count)
        .filter_map(|i| u32_at(bytes, at + 8 + i * 4))
        .collect()
}

/// Cherche, dans la fenêtre qui suit, un appel qui consomme le registre
/// `reg` et dont le nom figure dans [`RESOURCE_APIS`]. S'arrête dès que le
/// registre est réécrit : au-delà, la constante n'y est plus.
fn find_consumer(
    dex: &DexBin,
    instructions: &[dex_bytecode::Instruction],
    from: usize,
    reg: u32,
) -> Option<String> {
    for ins in instructions.iter().skip(from + 1).take(WINDOW) {
        let m = ins.mnemonic();
        if m.starts_with("invoke-") {
            if passes_register(ins, reg) {
                if let Some(Operand::Method(owner, name)) = resolve(dex, ins) {
                    if RESOURCE_APIS.contains(&name.as_str()) {
                        return Some(format!("{owner}->{name}"));
                    }
                }
            }
            continue;
        }
        if writes_register(ins) && dest_register(ins) == Some(reg) {
            return None;
        }
    }
    None
}

/// Le registre figure-t-il parmi les arguments de l'appel ? Les formes
/// `/range` n'énumèrent que leurs bornes.
fn passes_register(ins: &dex_bytecode::Instruction, reg: u32) -> bool {
    let regs = registers(ins);
    if ins.mnemonic().ends_with("/range") {
        return match (regs.first(), regs.last()) {
            (Some(lo), Some(hi)) => (*lo..=*hi).contains(&reg),
            _ => false,
        };
    }
    regs.contains(&reg)
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let b: [u8; 2] = d.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(b))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let b: [u8; 4] = d.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

pub fn legend() -> &'static str {
    "\
Jointure DEX -> ressources (--resource-xref, --resource-orphans)

classe               Descripteur Dalvik de la classe qui porte la constante.
methode              Nom de la méthode. Le descripteur n'est pas rendu : deux surcharges de même
                     nom ne se distinguent que par l'offset.
offset               Offset de l'instruction dans le code de la méthode.
id / type / nom /    Entrée de la table désignée par la constante. Mêmes définitions que
valeur               --resources (voir --resources --legend).
origine              const     la valeur est un littéral d'instruction (const, const/high16).
                     tableau   élément d'un fill-array-data-payload (R.styleable.*). Sans
                               registre ni contexte d'appel : jamais corroboré.
                     sget      lecture d'un champ statique de la classe R, dont la valeur vit
                               dans encoded_static_values — hors de toute instruction. C'est
                               la forme des APK NON minifiés.
consommateur         API qui reçoit la constante dans les 8 instructions suivantes, avant que son
                     registre ne soit réécrit : getString, findViewById, setContentView, inflate,
                     getDrawable, setText… La comparaison porte sur le NOM de méthode seul, pour
                     attraper aussi les wrappers (ContextCompat.getColor, AppCompatResources…).
                     Vide = aucune trouvée. Cette colonne ne FILTRE rien, elle MESURE.

Comment lire le taux de faux positifs — le résumé de fin de passe ([XREF] sur stderr) :
  entiers            constantes entières LITTÉRALES lues (const, const/high16, tableaux), toutes
                     valeurs confondues. Les sget n'y figurent pas : leur valeur ne vient pas du
                     flux d'instructions.
  candidats          celles dont l'octet de poids fort est un package RÉELLEMENT présent dans la
                     table. Un 0x0104…, ressource du framework, n'est pas candidat.
  retenus            candidats qui désignent une entrée existante.
  rejetes            candidats sans entrée correspondante. Ce sont des offsets, des masques, des
                     constantes quelconques : la preuve, par construction, que la plage seule ne
                     suffit pas. Le pourcentage annoncé est la part de bruit que le filtre retire.
  sget               usages passés par un champ de R (second canal, hors filtrage par plage :
                     la valeur vient de la table des champs, pas d'un littéral).
  defs_R             constantes de la plage trouvées DANS une classe R : la table qui se recopie
                     elle-même, pas un usage. Ni candidates, ni retenues — sans quoi aucune
                     ressource ne serait jamais orpheline.
  corrobores         usages dont la constante part vers une API consommatrice.
Lignes émises = retenus + sget ; c'est le dénominateur du taux de corroboration.
Encadrement : les corroborés sont des vrais positifs ; les usages non corroborés sont
INDÉTERMINÉS (la valeur peut transiter par un champ, un tableau ou un appel hors fenêtre).
Le taux de faux positifs résiduel est donc MAJORÉ par (lignes - corroborés) / lignes. Ce n'est
pas une estimation du taux réel, c'est sa borne supérieure.

Reste hors de portée : un identifiant calculé à l'exécution (getIdentifier(\"nom\", …)) est
indétectable par construction. Une constante passée de méthode en méthode sort quand même, mais
sans corroboration.

--resource-orphans : ressources qu'aucune constante du DEX ne référence. « Orpheline » veut dire
NON RÉFÉRENCÉE DEPUIS LE CODE, jamais « inutilisée » : une ressource citée par un layout, par un
style, par un thème ou par le manifeste est orpheline ici tout en étant parfaitement utilisée.
S'y ajoutent les usages par nom (getIdentifier), indétectables par construction. La liste est un
point de départ d'enquête, pas un verdict de code mort."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn litteral_const_relu_dans_les_octets() {
        // const v0, 0x7f110228
        let mut b = vec![OP_CONST, 0x00];
        b.extend_from_slice(&0x7f11_0228u32.to_le_bytes());
        assert_eq!(const_literal(&b, OP_CONST, 0), Some(0x7f11_0228));
    }

    #[test]
    fn litteral_high16_est_decale() {
        // const/high16 v0, 0x7f110000
        let mut b = vec![OP_CONST_HIGH16, 0x00];
        b.extend_from_slice(&0x7f11u16.to_le_bytes());
        assert_eq!(const_literal(&b, OP_CONST_HIGH16, 0), Some(0x7f11_0000));
    }

    #[test]
    fn instruction_tronquee_ne_panique_pas() {
        assert_eq!(const_literal(&[OP_CONST, 0x00, 0x28], OP_CONST, 0), None);
        assert_eq!(const_literal(&[], OP_CONST, 0), None);
        assert!(payload_ints(&[0x00, 0x03], 0).is_empty());
    }

    #[test]
    fn payload_rend_les_entiers_32_bits() {
        let mut b = vec![0x00, 0x03];
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&0x7f11_0228u32.to_le_bytes());
        b.extend_from_slice(&0x7f11_0229u32.to_le_bytes());
        assert_eq!(payload_ints(&b, 0), vec![0x7f11_0228, 0x7f11_0229]);
    }

    #[test]
    fn payload_d_une_autre_largeur_est_ignore() {
        let mut b = vec![0x00, 0x03];
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(&[1, 2, 3, 4]);
        assert!(payload_ints(&b, 0).is_empty());
    }

    #[test]
    fn classes_R_reconnues() {
        assert!(is_r_class("Lcom/parental/control/kidgy/R;"));
        assert!(is_r_class("Lcom/parental/control/kidgy/R$string;"));
        assert!(is_r_class("Landroidx/appcompat/R$attr;"));
        assert!(!is_r_class("Lcom/parental/control/kidgy/Random;"));
        assert!(!is_r_class("Lcom/parental/control/kidgy/MainActivity;"));
        assert!(is_r_class("LR$string;"));
    }

    #[test]
    fn taux_sur_lot_vide() {
        let s = XrefStats::default();
        assert_eq!(s.rejection_rate(), 0.0);
        assert_eq!(s.corroboration_rate(), 0.0);
    }
}
