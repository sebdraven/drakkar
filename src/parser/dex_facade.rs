//! Façade DEX : **seul** module du projet qui connaît le crate de parsing.
//!
//! Le reste de `parser` et de `cfg` ne manipule que les types définis ici.
//! Recette : `grep -rn 'dex_parser::' src/` ne doit citer que ce fichier.
//!
//! La surface est CLOSE : elle expose ce que les neuf modules consommateurs
//! utilisent, rien de plus. Une façade plus large que son usage est aussi
//! difficile à faire évoluer que pas de façade du tout.
//!
//! # Ce que la façade compense
//!
//! **Shorty.** Le descripteur historique d'un *callee* porte ses paramètres en
//! formes courtes (`(LLI)V`), hérité du `shorty` du `proto_id_item`. Le crate
//! ne l'expose pas : [`Proto::descriptor`] le redérive des types exacts.
//! Sans ça, `MethodRef.descriptor` changerait pour tout le monde — donc le
//! CFG, les règles MITRE et la sortie JSON.
//!
//! **Pools résolus une fois.** `get_string` du crate relit le
//! `string_data_item` et alloue à chaque appel ; la résolution d'opérandes en
//! fait un par instruction. Les trois pools sont donc matérialisés à
//! l'ouverture et les accès rendent des `&str`.
//!
//! **Une seule lecture.** `DexFile::parse` recopie déjà le tampon qu'on lui
//! passe : le `Vec` de lecture est relâché derrière, le régime permanent tient
//! une copie.

use anyhow::{Context, Result};
use std::path::Path;

use dex_parser::{ClassDef, DexFile, EncodedValue, NO_INDEX};

/// Un DEX ouvert, pools résolus.
pub struct DexBin {
    dex: DexFile,
    /// `string_ids`, `None` pour une entrée illisible (hors bornes, MUTF-8
    /// invalide) — le crate rendait `Err`, les appelants l'ignoraient.
    strings: Vec<Option<String>>,
    /// `type_ids`, mêmes conventions.
    types: Vec<Option<String>>,
    protos: Vec<Option<Proto>>,
}

struct Proto {
    params: Vec<String>,
    return_type: String,
    /// Forme historique du descripteur de callee : `(` + shorty des paramètres
    /// + `)` + type de retour exact.
    descriptor: String,
}

/// Une classe définie par le DEX.
pub struct DexClass<'a> {
    pub descriptor: &'a str,
    /// `None` pour `Ljava/lang/Object;` seulement. Ne jamais propager une
    /// chaîne vide : le crate rend `""` quand `superclass_idx == NO_INDEX`.
    pub superclass: Option<&'a str>,
    /// `direct_methods` puis `virtual_methods`, dans l'ordre du DEX.
    pub methods: Vec<DexMethod<'a>>,
    class_def: ClassDef,
}

/// Une méthode définie par une classe.
pub struct DexMethod<'a> {
    pub name: &'a str,
    /// Descripteurs EXACTS des paramètres déclarés.
    pub params: &'a [String],
    pub return_type: &'a str,
    /// `ACC_STATIC` du `encoded_method`. Décide s'il y a un `this`.
    pub is_static: bool,
    /// `None` pour abstract et native.
    pub code: Option<Code<'a>>,
}

/// Le `code_item` d'une méthode.
pub struct Code<'a> {
    /// Octets bruts, tels que `dex_bytecode::decode_all` les attend.
    pub insns: &'a [u8],
    pub registers_size: u16,
    pub ins_size: u16,
}

/// Entrée de `method_ids` résolue.
pub struct MethodItem<'a> {
    pub class: &'a str,
    pub name: &'a str,
    /// Descripteur en forme historique (paramètres en shorty).
    pub descriptor: &'a str,
}

/// Entrée de `field_ids` résolue.
pub struct FieldItem<'a> {
    pub class: &'a str,
    pub name: &'a str,
    pub typ: &'a str,
}

/// Un champ statique et sa valeur initiale, quand le DEX en porte une.
pub struct StaticField {
    pub name: String,
    pub value: Option<DexValue>,
}

/// Valeur d'un `encoded_value`. Seul l'entier est distingué : c'est le seul
/// que le projet lit (identifiants de ressources).
pub enum DexValue {
    Int(i32),
    Other,
}

impl DexBin {
    /// Ouvre un `.dex` déjà matérialisé sur disque.
    pub fn open(path: &Path) -> Result<Self> {
        let buf = std::fs::read(path).with_context(|| format!("read dex {}", path.display()))?;
        let dex = DexFile::parse(&buf).with_context(|| format!("parse dex {}", path.display()))?;
        drop(buf);

        let strings = (0..dex.header.string_ids_size)
            .map(|i| dex.get_string(i).ok())
            .collect::<Vec<_>>();

        let types = (0..dex.header.type_ids_size)
            .map(|i| dex.get_type(i).ok())
            .collect::<Vec<_>>();

        let protos = (0..dex.header.proto_ids_size)
            .map(|i| {
                dex.protos
                    .get_proto(&dex.data, &dex.types, &dex.strings, i)
                    .ok()
                    .map(|(return_type, params)| Proto {
                        descriptor: format!("({}){}", shorty_params(&params), return_type),
                        params,
                        return_type,
                    })
            })
            .collect::<Vec<_>>();

        Ok(Self { dex, strings, types, protos })
    }

    /// Chaîne du pool, `None` si l'index est hors bornes ou l'entrée illisible.
    pub fn string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize)?.as_deref()
    }

    /// Descripteur de type du pool.
    pub fn typ(&self, idx: u32) -> Option<&str> {
        self.types.get(idx as usize)?.as_deref()
    }

    /// Toutes les chaînes lisibles du pool, dans l'ordre. Les entrées
    /// illisibles sont sautées, pas rendues vides.
    pub fn strings<'a>(&'a self) -> impl Iterator<Item = &'a str> + 'a {
        self.strings.iter().filter_map(|s| s.as_deref())
    }

    /// Entrée de `method_ids`.
    pub fn method_item(&self, idx: u32) -> Option<MethodItem<'_>> {
        let m = self.dex.methods.get(idx).ok()?;
        Some(MethodItem {
            class: self.typ(m.class_idx as u32)?,
            name: self.string(m.name_idx)?,
            descriptor: self
                .protos
                .get(m.proto_idx as usize)
                .and_then(|p| p.as_ref())
                .map_or("", |p| p.descriptor.as_str()),
        })
    }

    /// Entrée de `field_ids`.
    pub fn field_item(&self, idx: u32) -> Option<FieldItem<'_>> {
        let f = self.dex.fields.get(idx).ok()?;
        Some(FieldItem {
            class: self.typ(f.class_idx as u32)?,
            name: self.string(f.name_idx)?,
            typ: self.typ(f.type_idx as u32)?,
        })
    }

    /// Les classes définies par ce DEX, dans l'ordre des `class_defs`.
    ///
    /// Une classe dont une partie est illisible rend `Err` et n'est pas
    /// partiellement livrée : les appelants la comptent comme sautée.
    pub fn classes<'a>(&'a self) -> impl Iterator<Item = Result<DexClass<'a>>> + 'a {
        (0..self.dex.header.class_defs_size).map(move |i| self.class_at(i))
    }

    fn class_at<'a>(&'a self, idx: u32) -> Result<DexClass<'a>> {
        let class_def = self.dex.get_class_def(idx)?;
        let descriptor = self
            .typ(class_def.class_idx)
            .with_context(|| format!("class_defs[{idx}] : descripteur illisible"))?;
        let superclass = if class_def.superclass_idx == NO_INDEX {
            None
        } else {
            self.typ(class_def.superclass_idx)
        };

        let mut methods = Vec::new();
        if let Some(data) = self.dex.get_class_data(&class_def)? {
            for enc in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
                methods.push(self.method_at(enc.method_idx, enc.access_flags, enc.code_off)?);
            }
        }

        Ok(DexClass { descriptor, superclass, methods, class_def })
    }

    fn method_at<'a>(
        &'a self,
        method_idx: u32,
        access_flags: u32,
        code_off: u32,
    ) -> Result<DexMethod<'a>> {
        let m = self.dex.methods.get(method_idx)?;
        let name = self
            .string(m.name_idx)
            .with_context(|| format!("method_ids[{method_idx}] : nom illisible"))?;
        let proto = self.protos.get(m.proto_idx as usize).and_then(|p| p.as_ref());

        let code = if code_off == 0 {
            None
        } else {
            let item = self.dex.get_code_item(code_off)?;
            Some(Code {
                insns: item.insns_slice(&self.dex.data),
                registers_size: item.registers_size,
                ins_size: item.ins_size,
            })
        };

        Ok(DexMethod {
            name,
            params: proto.map_or(NO_PARAMS, |p| p.params.as_slice()),
            return_type: proto.map_or("", |p| p.return_type.as_str()),
            is_static: access_flags & ACC_STATIC != 0,
            code,
        })
    }

    /// Champs statiques d'une classe et leur valeur initiale.
    ///
    /// L'`encoded_array` de `static_values_off` est apparié POSITIONNELLEMENT
    /// aux `static_fields` du `class_data_item`, et il peut être plus court :
    /// les champs de queue n'ont alors pas de valeur.
    pub fn static_fields(&self, class: &DexClass<'_>) -> Result<Vec<StaticField>> {
        let Some(data) = self.dex.get_class_data(&class.class_def)? else {
            return Ok(Vec::new());
        };
        let values = self.dex.get_static_values(&class.class_def)?;

        let mut out = Vec::with_capacity(data.static_fields.len());
        for (i, enc) in data.static_fields.iter().enumerate() {
            let f = self.dex.fields.get(enc.field_idx)?;
            let Some(name) = self.string(f.name_idx) else { continue };
            out.push(StaticField {
                name: name.to_string(),
                value: values.get(i).map(|v| match v {
                    EncodedValue::Int(n) => DexValue::Int(*n),
                    _ => DexValue::Other,
                }),
            });
        }
        Ok(out)
    }
}

const ACC_STATIC: u32 = 0x8;

const NO_PARAMS: &[String] = &[];

/// Shorty des paramètres : primitifs tels quels, tout le reste — objets ET
/// tableaux — réduit à `L`.
fn shorty_params(params: &[String]) -> String {
    params
        .iter()
        .map(|p| match p.as_str() {
            "Z" | "B" | "S" | "C" | "I" | "J" | "F" | "D" => p.as_str(),
            _ => "L",
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shorty_reduit_objets_et_tableaux() {
        let params: Vec<String> = ["Ljava/lang/String;", "I", "[I", "[[Ljava/lang/Object;", "J"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(shorty_params(&params), "LILLJ");
    }

    #[test]
    fn shorty_vide_sur_methode_sans_parametre() {
        assert_eq!(shorty_params(&[]), "");
    }
}
