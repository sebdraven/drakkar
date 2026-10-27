//! Désassembleur LISIBLE d'une ou plusieurs classes d'un DEX (ou APK).
//!
//! POURQUOI CE MODULE
//! ------------------
//! `--diff-dex` répond à « ces deux binaires sont-ils le même code ? » par un
//! chiffre, mais il est structurellement AVEUGLE aux opérandes : son empreinte
//! ne hache que `ins.mnemonic()`. Deux classes qui ne diffèrent que par une
//! chaîne littérale ou par la méthode appelée ont donc la MÊME empreinte — un
//! changement d'hôte C2 passerait à 1.0.
//!
//! Quand le diff désigne une classe divergente, il faut donc pouvoir la LIRE, et
//! la lire avec ses opérandes résolues. C'est ce que fait ce module.
//!
//! CE QUE C'EST, ET CE QUE CE N'EST PAS
//! ------------------------------------
//! C'est un **désassembleur** : une instruction Dalvik par ligne, avec les
//! `type@` / `string@` / `method@` / `field@` résolus en clair contre les pools
//! du DEX. Format proche du smali, sans en être.
//!
//! Ce n'est **PAS un décompilateur**. Aucune reconstruction de flot de contrôle
//! (boucles, `try`/`catch`, `switch` compactés), aucune inférence de types sur
//! registres, aucune remontée en Java. Pour ça, JADX — ce module ne cherche pas
//! à le remplacer.
//!
//! EMPREINTE DE MÉTHODE
//! --------------------
//! Chaque méthode porte l'empreinte d'opcodes calculée **exactement comme dans
//! `diff_dex.rs`** (hachage de la séquence de mnémoniques seuls). C'est ce qui
//! permet d'apparier les méthodes entre deux sorties et de désigner CELLE qui
//! diverge, avant de la lire ligne à ligne.
//!
//! ⚠️ `DefaultHasher` (SipHash à clés nulles) est stable pour une même version
//! de rustc et un même binaire, ce qui suffit à comparer deux exécutions
//! successives. **Ne pas persister ces valeurs ni les publier comme IOC.**

use crate::parser::dex_facade::DexBin;
use anyhow::{bail, Context, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Paramètres du désassemblage.
#[derive(Default)]
pub struct DisasmOptions {
    /// Motifs de sélection des classes. Comparaison par **sous-chaîne** sur le
    /// descripteur Dalvik, insensible à la casse — `services/g`,
    /// `Lcom/dy/services/g;` et `SERVICES/G` sélectionnent tous la même classe.
    /// Vide = toutes les classes (à éviter sur un DEX complet).
    pub patterns: Vec<String>,
    /// Normalisation appliquée aux descripteurs et aux chaînes AVANT affichage,
    /// sous la forme `(depuis, vers)`. Sert à comparer deux lots dont le
    /// namespace diffère (`com/duiyun` ↔ `com/dy`) sans que chaque ligne
    /// diverge pour cette seule raison. N'affecte QUE l'affichage.
    pub normalize: Vec<(String, String)>,
}

/// Une instruction désassemblée.
pub struct Insn {
    pub offset: u64,
    pub mnemonic: String,
    /// Opérandes brutes, telles que dex-bytecode les rend.
    pub operands: String,
    /// Opérande résolue contre les pools du DEX, quand il y en a une.
    pub resolved: Option<String>,
}

/// Une méthode désassemblée.
pub struct MethodDisasm {
    pub name: String,
    /// Descripteurs des paramètres déclarés. Le type de retour n'est pas rendu :
    /// il n'apporte rien à la comparaison de deux corps de méthode.
    pub params: Vec<String>,
    pub registers_size: u16,
    pub ins_size: u16,
    /// Empreinte d'opcodes, identique au calcul de `diff_dex.rs`.
    pub fingerprint: u64,
    pub insns: Vec<Insn>,
}

/// Une classe désassemblée.
pub struct ClassDisasm {
    pub descriptor: String,
    pub methods: Vec<MethodDisasm>,
    /// Méthodes sans `code_item` (abstraites, natives) — comptées, pas listées.
    pub codeless: usize,
}

pub struct DisasmReport {
    pub input: String,
    pub classes: Vec<ClassDisasm>,
    /// Classes lues en tout, avant filtre. Situe la sélection.
    pub scanned: usize,
}

/// Point d'entrée : accepte un APK ou un DEX brut, reconnu au contenu.
pub fn run(input: &Path, opts: &DisasmOptions) -> Result<DisasmReport> {
    let (dex_paths, _tmp) = collect_dex_paths(input)?;

    let mut report = DisasmReport {
        input: input.display().to_string(),
        classes: Vec::new(),
        scanned: 0,
    };

    for dp in &dex_paths {
        collect_from_dex(dp, opts, &mut report)
            .with_context(|| format!("parse {}", dp.display()))?;
    }

    if report.classes.is_empty() {
        bail!(
            "aucune classe ne correspond à {:?} dans {} ({} classes lues) — le motif est \
             comparé au descripteur Dalvik, essaie `services/g` ou `Lcom/dy/`",
            opts.patterns,
            input.display(),
            report.scanned
        );
    }
    Ok(report)
}

fn collect_from_dex(path: &Path, opts: &DisasmOptions, out: &mut DisasmReport) -> Result<()> {
    let dex = DexBin::open(path)?;

    for class in dex.classes() {
        let class = match class {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "skip unreadable class");
                continue;
            }
        };
        out.scanned += 1;

        let descriptor = class.descriptor.to_string();
        if !selected(&descriptor, &opts.patterns) {
            continue;
        }

        let mut methods = Vec::new();
        let mut codeless = 0usize;

        for method in &class.methods {
            let code = match &method.code {
                Some(c) => c,
                None => {
                    codeless += 1;
                    continue;
                }
            };

            let instructions = match dex_bytecode::decode_all(code.insns, 0) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(class = %descriptor, error = %e, "decode failed");
                    continue;
                }
            };

            // Empreinte : mnémoniques seuls, dans l'ordre. MÊME calcul que
            // diff_dex::collect_from_dex — toute divergence ici casserait la
            // comparabilité des deux sorties.
            let fingerprint = {
                let mut h = DefaultHasher::new();
                for ins in &instructions {
                    ins.mnemonic().hash(&mut h);
                }
                h.finish()
            };

            let insns = instructions
                .iter()
                .map(|ins| Insn {
                    offset: ins.offset as u64,
                    mnemonic: ins.mnemonic().to_string(),
                    operands: normalize(ins.operands(), &opts.normalize),
                    resolved: annotate(&dex, ins).map(|s| normalize(&s, &opts.normalize)),
                })
                .collect();

            methods.push(MethodDisasm {
                name: method.name.to_string(),
                params: method
                    .params
                    .iter()
                    .map(|p| normalize(p, &opts.normalize))
                    .collect(),
                registers_size: code.registers_size,
                ins_size: code.ins_size,
                fingerprint,
                insns,
            });
        }

        out.classes.push(ClassDisasm {
            descriptor: normalize(&descriptor, &opts.normalize),
            methods,
            codeless,
        });
    }
    Ok(())
}

/// Le descripteur correspond-il à l'un des motifs ? Vide = tout.
pub(crate) fn selected(descriptor: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    let hay = descriptor.to_lowercase();
    patterns.iter().any(|p| hay.contains(&p.to_lowercase()))
}

/// Applique les substitutions d'affichage, dans l'ordre donné.
pub fn normalize(s: &str, subs: &[(String, String)]) -> String {
    let mut out = s.to_string();
    for (from, to) in subs {
        out = out.replace(from.as_str(), to.as_str());
    }
    out
}

/// Une opérande indexée, résolue contre les pools du DEX.
///
/// Structurée plutôt que rendue en texte : `diff_explain` a besoin de comparer
/// les composantes séparément (un champ dont seul le NOM change est du
/// remapping ProGuard ; un champ dont l'owner change est une vraie divergence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// Chaîne littérale (`const-string`).
    Str(String),
    /// Descripteur de type (`const-class`, `new-instance`, `check-cast`…).
    Type(String),
    /// Référence de méthode : owner, nom.
    Method(String, String),
    /// Référence de champ : owner, nom, type.
    Field(String, String, String),
}

impl Operand {
    /// Étiquette courte de la nature de l'opérande.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Str(_) => "chaîne",
            Self::Type(_) => "type",
            Self::Method(..) => "méthode",
            Self::Field(..) => "champ",
        }
    }

    /// Rendu lisible sur une ligne.
    pub fn render(&self) -> String {
        match self {
            Self::Str(s) => format!("\"{}\"", escape(s)),
            Self::Type(t) => t.clone(),
            Self::Method(owner, name) => format!("{owner}->{name}()"),
            Self::Field(owner, name, ty) => format!("{owner}->{name}:{ty}"),
        }
    }

    /// Applique les substitutions d'affichage à toutes les composantes.
    pub fn normalized(&self, subs: &[(String, String)]) -> Self {
        match self {
            Self::Str(s) => Self::Str(normalize(s, subs)),
            Self::Type(t) => Self::Type(normalize(t, subs)),
            Self::Method(o, n) => Self::Method(normalize(o, subs), normalize(n, subs)),
            Self::Field(o, n, t) => {
                Self::Field(normalize(o, subs), normalize(n, subs), normalize(t, subs))
            }
        }
    }
}

/// Résout l'opérande indexée d'une instruction contre les pools du DEX.
///
/// Un seul marqueur est traité par instruction : les formats Dalvik n'en portent
/// qu'un à la fois. L'ordre d'essai place `string@` en premier, cas le plus
/// fréquent et le plus informatif à la lecture.
///
/// ⚠️ **C'est le SEUL endroit du projet où les entrées de `method_ids` et de
/// `field_ids` sont traduites en opérande affichable.** Concentrer les appels
/// ici évite d'avoir à corriger la même subtilité en deux endroits.
pub fn resolve(dex: &DexBin, ins: &dex_bytecode::Instruction) -> Option<Operand> {
    if let Some(idx) = operand_index(ins, "string@") {
        return Some(Operand::Str(dex.string(idx as u32)?.to_string()));
    }

    if let Some(idx) = operand_index(ins, "method@") {
        let item = dex.method_item(idx as u32)?;
        return Some(Operand::Method(
            item.class.to_string(),
            item.name.to_string(),
        ));
    }

    if let Some(idx) = operand_index(ins, "field@") {
        let item = dex.field_item(idx as u32)?;
        return Some(Operand::Field(
            item.class.to_string(),
            item.name.to_string(),
            item.typ.to_string(),
        ));
    }

    if let Some(idx) = operand_index(ins, "type@") {
        return Some(Operand::Type(dex.typ(idx as u32)?.to_string()));
    }

    None
}

/// Rendu texte d'une opérande résolue, pour l'affichage du désassemblage.
fn annotate(dex: &DexBin, ins: &dex_bytecode::Instruction) -> Option<String> {
    resolve(dex, ins).map(|o| o.render())
}

/// Extrait l'entier d'un opérande textuel de la forme `<tag>N`.
/// Repris à l'identique de `dyn_entrypoints::operand_index` : dex-bytecode
/// formate les opérandes en texte, il n'y a pas d'accès structuré.
pub fn operand_index(ins: &dex_bytecode::Instruction, tag: &str) -> Option<u64> {
    let ops = ins.operands();
    let pos = ops.find(tag)? + tag.len();
    let digits: String = ops[pos..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Neutralise les caractères qui casseraient l'alignement d'une ligne. Les
/// caractères non-ASCII sont CONSERVÉS : les chaînes de debug du corpus sont en
/// chinois et c'est précisément ce qu'on veut voir.
pub fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .replace('"', "\\\"")
}

/// Résout l'entrée en DEX à lire. DEX brut → lui-même ; APK → ses
/// `classes*.dex` extraits dans un tempdir. Reconnaissance au contenu.
fn collect_dex_paths(input: &Path) -> Result<(Vec<PathBuf>, Option<tempfile::TempDir>)> {
    let mut magic = [0u8; 8];
    {
        let mut f =
            std::fs::File::open(input).with_context(|| format!("open {}", input.display()))?;
        let n = f.read(&mut magic)?;
        if n < 4 {
            bail!("{} trop court pour être un DEX ou un APK", input.display());
        }
    }

    if &magic[0..4] == b"dex\n" {
        return Ok((vec![input.to_path_buf()], None));
    }
    if magic[0..4] == [0x50, 0x4b, 0x03, 0x04] {
        let tmp = tempfile::tempdir().context("create tempdir")?;
        let paths = extract_dexes(input, tmp.path())?;
        if paths.is_empty() {
            bail!("aucun classes*.dex dans l'APK {}", input.display());
        }
        return Ok((paths, Some(tmp)));
    }
    bail!(
        "{} n'est ni un DEX (dex\\n) ni un APK (PK) — magic {:02x?}",
        input.display(),
        &magic[0..4]
    )
}

fn extract_dexes(apk: &Path, out_dir: &Path) -> Result<Vec<PathBuf>> {
    let file = std::fs::File::open(apk).with_context(|| format!("open {}", apk.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("read apk as zip")?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        let name = entry.name().to_string();
        if !(name.starts_with("classes") && name.ends_with(".dex")) {
            continue;
        }
        let dest = out_dir.join(name.replace('/', "__"));
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        std::fs::write(&dest, &buf)?;
        out.push(dest);
    }
    Ok(out)
}

/// Rendu texte, une instruction par ligne. Sortie conçue pour être passée à
/// `diff` : pas d'en-tête variable, pas d'horodatage, ordre stable.
pub fn render(r: &DisasmReport) -> String {
    let mut s = String::new();
    for c in &r.classes {
        s.push_str(&format!("== {} ==\n", c.descriptor));
        if c.codeless > 0 {
            s.push_str(&format!(
                "   ({} méthode(s) sans code : abstraite ou native)\n",
                c.codeless
            ));
        }
        for m in &c.methods {
            s.push_str(&format!(
                "\n  {}({})   regs={} ins={}  fp={:016x}  {} insn\n",
                m.name,
                m.params.join(", "),
                m.registers_size,
                m.ins_size,
                m.fingerprint,
                m.insns.len()
            ));
            for i in &m.insns {
                let mut line = format!("    {:04x}  {:<24} {}", i.offset, i.mnemonic, i.operands);
                if let Some(res) = &i.resolved {
                    // Colonne de résolution alignée, pour que `diff` reste lisible.
                    let pad = 60usize.saturating_sub(line.chars().count());
                    line.push_str(&" ".repeat(pad));
                    line.push_str(&format!("; {res}"));
                }
                s.push_str(&line);
                s.push('\n');
            }
        }
        s.push('\n');
    }
    s
}

/// Légende (`--disasm --legend`).
pub fn legend() -> String {
    "\
== Désassemblage (--disasm) — légende ==

CE QUE C'EST : un désassembleur Dalvik. Une instruction par ligne, avec les
opérandes indexées résolues contre les pools du DEX.

CE QUE CE N'EST PAS : un décompilateur. Pas de reconstruction de boucles, de
try/catch, de switch, ni d'inférence de types. Pour du Java : JADX.

Sélection :
  --disasm <MOTIF>       Sous-chaîne comparée au descripteur Dalvik, insensible
                         à la casse. Répétable. Ex. `services/g`, `Lcom/dy/`.
                         Sans motif : toutes les classes du DEX.
  --disasm-normalize A=B Remplace A par B dans les descripteurs et les chaînes
                         AVANT affichage. Répétable. Sert à comparer deux lots
                         de namespaces différents :
                           --disasm-normalize com/duiyun=com/dy
                         N'affecte QUE l'affichage, jamais l'empreinte.

Colonnes d'une ligne d'instruction :
  offset      Offset en unités de code, hexadécimal.
  mnémonique  Opcode Dalvik.
  opérandes   Brutes, telles que dex-bytecode les rend (vN, tag@index).
  ; ...       Opérande résolue : chaîne littérale, Type, Owner->methode(),
              ou Owner->champ:Type. Un seul marqueur par instruction.

En-tête de méthode :
  regs / ins  registers_size et ins_size du code_item.
  fp          Empreinte d'opcodes — hachage des MNÉMONIQUES SEULS, calcul
              identique à --diff-dex. Deux méthodes de même fp ont la même
              structure, MAIS peuvent différer par leurs chaînes et leurs
              cibles d'appel : c'est l'angle mort du diff, et c'est pourquoi la
              colonne de résolution existe.
              ⚠️ Valeur non stable entre versions de rustc — comparer deux
              sorties du MÊME binaire, ne jamais la publier comme IOC.

Usage typique — lire la classe que --diff-dex a désignée comme divergente :
  drakkar <A> --disasm services/g > /tmp/a.txt
  drakkar <B> --disasm services/g --disasm-normalize com/duiyun=com/dy > /tmp/b.txt
  diff /tmp/a.txt /tmp/b.txt
Les fp identiques disent quelles méthodes ont la même structure ; le diff des
lignes dit ce qui change vraiment.\
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_matching_is_case_insensitive_substring() {
        let pats = vec!["services/g".to_string()];
        assert!(selected("Lcom/dy/services/g;", &pats));
        assert!(selected("Lcom/duiyun/SERVICES/G;", &pats));
        assert!(!selected("Lcom/dy/services/h;", &pats));
        // Sans motif : tout passe.
        assert!(selected("Lanything;", &[]));
    }

    #[test]
    fn normalize_applies_in_order() {
        let subs = vec![("com/duiyun".to_string(), "com/dy".to_string())];
        assert_eq!(
            normalize("Lcom/duiyun/services/g;", &subs),
            "Lcom/dy/services/g;"
        );
        assert_eq!(normalize("rien à voir", &subs), "rien à voir");
    }

    #[test]
    fn escape_keeps_non_ascii() {
        // Les chaînes de debug du corpus sont en chinois : elles doivent passer.
        assert_eq!(escape("三星浏览器\n"), "三星浏览器\\n");
    }
}
