//! Façade DEX : **seul** module du projet qui connaît le crate de parsing.
//!
//! Le reste de `parser` et de `cfg` ne manipule que les types définis ici.
//! Recette : `grep -rn 'dex_parser::' src/` ne doit citer que ce fichier.
//!
//! La surface est CLOSE : elle expose ce que les dix modules consommateurs
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

use dex_parser::{visibility_name, AnnotationItem, ClassDef, DexFile, EncodedValue, NO_INDEX};

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
    /// Index global dans `method_ids`. C'est la clé de jointure vers les
    /// annotations de méthode et de paramètre — voir [`DexBin::annotations`].
    pub method_idx: u32,
    pub name: &'a str,
    /// Descripteurs EXACTS des paramètres déclarés.
    pub params: &'a [String],
    pub return_type: &'a str,
    /// `ACC_STATIC` du `encoded_method`. Décide s'il y a un `this`.
    pub is_static: bool,
    /// `ACC_NATIVE` du `encoded_method` : le corps est lié par JNI.
    pub is_native: bool,
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
    /// `None` quand l'`encoded_array` s'arrête avant ce champ.
    pub value: Option<DexValue>,
}

/// Une annotation, index de pool déjà résolus.
pub struct Annotation {
    /// Descripteur Dalvik du type, ex. `Lretrofit2/http/GET;`.
    pub type_name: String,
    /// `build`, `runtime` ou `system`. Seules les `runtime` sont lisibles par
    /// réflexion à l'exécution — c'est ce qu'exigent Retrofit et Gson.
    pub visibility: &'static str,
    /// Éléments nommés, dans l'ordre du DEX.
    pub elements: Vec<(String, DexValue)>,
}

impl Annotation {
    pub fn element(&self, name: &str) -> Option<&DexValue> {
        self.elements
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }
}

/// Annotations portées par un paramètre.
pub struct ParamAnnotations {
    /// Position dans [`DexMethod::params`] — `this` n'y figure pas.
    pub index: usize,
    pub annotations: Vec<Annotation>,
}

/// Annotations portées par une méthode et par ses paramètres.
pub struct MethodAnnotations {
    /// Se joint à [`DexMethod::method_idx`].
    pub method_idx: u32,
    pub annotations: Vec<Annotation>,
    /// Seuls les paramètres effectivement annotés figurent ici.
    pub params: Vec<ParamAnnotations>,
}

/// Annotations portées par un champ, nom et type déjà résolus.
pub struct FieldAnnotations {
    pub name: String,
    pub typ: String,
    pub annotations: Vec<Annotation>,
}

/// L'`annotation_directory_item` d'une classe, tous niveaux confondus.
pub struct ClassAnnotations {
    pub class: Vec<Annotation>,
    pub methods: Vec<MethodAnnotations>,
    pub fields: Vec<FieldAnnotations>,
}

impl ClassAnnotations {
    pub fn is_empty(&self) -> bool {
        self.class.is_empty() && self.methods.is_empty() && self.fields.is_empty()
    }
}

/// Valeur d'un `encoded_value`, index de pool DÉJÀ résolus.
///
/// Les largeurs entières restent distinctes : `--resource-xref` ne retient que
/// `Int`, et fondre `Long` dedans lui ferait accepter des valeurs qu'il
/// refusait jusqu'ici.
///
/// ⚠️ ANGLE MORT — `MethodType`, `MethodHandle` et `Annotation` sont réduits à
/// [`DexValue::Opaque`], de même qu'une valeur dont l'index de pool ne se
/// résout pas. Deux `Opaque` de même nature sont ÉGALES : une divergence entre
/// elles n'est pas vue. Leurs charges utiles sont des index de pool, qui ne se
/// comparent pas d'un DEX à l'autre ; les rendre comparables fabriquerait des
/// faux positifs. Faux négatif choisi contre faux positif.
#[derive(Clone, Debug, PartialEq)]
pub enum DexValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Null,
    Str(String),
    Type(String),
    /// `Lowner;->nom:Ltype;`
    Field(String),
    /// `Lowner;->nom:Ltype;`
    Enum(String),
    /// `Lowner;->nom`
    Method(String),
    Array(Vec<DexValue>),
    Opaque(&'static str),
}

impl DexValue {
    /// Applique les substitutions aux composantes textuelles, récursivement
    /// dans les tableaux. Les nombres ne sont pas touchés.
    pub fn normalized(&self, subs: &[(String, String)]) -> Self {
        match self {
            Self::Str(s) => Self::Str(subst(s, subs)),
            Self::Type(t) => Self::Type(subst(t, subs)),
            Self::Field(f) => Self::Field(subst(f, subs)),
            Self::Enum(e) => Self::Enum(subst(e, subs)),
            Self::Method(m) => Self::Method(subst(m, subs)),
            Self::Array(v) => Self::Array(v.iter().map(|x| x.normalized(subs)).collect()),
            other => other.clone(),
        }
    }
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

        Ok(Self {
            dex,
            strings,
            types,
            protos,
        })
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
            for enc in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                methods.push(self.method_at(enc.method_idx, enc.access_flags, enc.code_off)?);
            }
        }

        Ok(DexClass {
            descriptor,
            superclass,
            methods,
            class_def,
        })
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
        let proto = self
            .protos
            .get(m.proto_idx as usize)
            .and_then(|p| p.as_ref());

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
            method_idx,
            name,
            params: proto.map_or(NO_PARAMS, |p| p.params.as_slice()),
            return_type: proto.map_or("", |p| p.return_type.as_str()),
            is_static: access_flags & ACC_STATIC != 0,
            is_native: access_flags & ACC_NATIVE != 0,
            code,
        })
    }

    /// Champs statiques d'une classe et leur valeur initiale.
    ///
    /// C'est le SEUL appariement champ ↔ valeur du projet. Il est POSITIONNEL :
    /// l'`encoded_array` de `static_values_off` suit l'ordre des
    /// `static_fields` du `class_data_item` et ne porte pas de noms.
    ///
    /// ⚠️ Aucun `continue` dans la boucle des noms. Sauter un champ décalerait
    /// toutes les valeurs suivantes d'un cran : rien ne casserait, les valeurs
    /// seraient simplement attribuées aux mauvais champs.
    pub fn static_fields(&self, class: &DexClass<'_>) -> Result<Vec<StaticField>> {
        let Some(data) = self.dex.get_class_data(&class.class_def)? else {
            return Ok(Vec::new());
        };

        let mut names = Vec::with_capacity(data.static_fields.len());
        for enc in &data.static_fields {
            // Un nom illisible garde sa PLACE, avec une chaîne vide : aucun nom
            // de champ réel n'est vide, donc rien ne s'y appariera par erreur.
            let name = self
                .dex
                .fields
                .get(enc.field_idx)
                .ok()
                .and_then(|f| self.string(f.name_idx))
                .unwrap_or_default();
            names.push(name.to_string());
        }

        let values: Vec<DexValue> = self
            .dex
            .get_static_values(&class.class_def)?
            .iter()
            .map(|v| self.value_of(v))
            .collect();

        if values.len() > names.len() {
            tracing::warn!(
                class = %class.descriptor,
                fields = names.len(),
                values = values.len(),
                "encoded_static_values plus long que la liste des champs : DEX malformé, \
                 excédent ignoré"
            );
        }

        Ok(pair_statics(names, values))
    }

    /// Annotations d'une classe : niveaux classe, champ, méthode et paramètre.
    ///
    /// `get_annotations` du crate est nommée d'après le `class_def_item` qui
    /// porte l'offset, mais l'`annotation_directory_item` qu'elle rend porte
    /// les QUATRE niveaux. Les index de `method_annotations` et de
    /// `parameter_annotations` sont des index globaux de `method_ids`, déjà
    /// absolus — `ClassData::parse` accumule le `method_idx_diff` delta-encodé.
    /// Ils se joignent donc directement à [`DexMethod::method_idx`].
    pub fn annotations(&self, class: &DexClass<'_>) -> Result<ClassAnnotations> {
        let dir = self.dex.get_annotations(&class.class_def)?;

        let mut methods: Vec<MethodAnnotations> = dir
            .method_annotations
            .iter()
            .map(|(idx, set)| MethodAnnotations {
                method_idx: *idx,
                annotations: self.annotation_set(set),
                params: Vec::new(),
            })
            .collect();

        for (idx, per_param) in &dir.parameter_annotations {
            // ⚠️ Un paramètre non annoté porte un set VIDE et occupe sa place
            // dans la liste. Filtrer AVANT d'énumérer décalerait tous les
            // index suivants — même piège que `pair_statics`.
            let params: Vec<ParamAnnotations> = per_param
                .iter()
                .enumerate()
                .filter(|(_, set)| !set.is_empty())
                .map(|(index, set)| ParamAnnotations {
                    index,
                    annotations: self.annotation_set(set),
                })
                .collect();
            if params.is_empty() {
                continue;
            }
            match methods.iter_mut().find(|m| m.method_idx == *idx) {
                Some(m) => m.params = params,
                None => methods.push(MethodAnnotations {
                    method_idx: *idx,
                    annotations: Vec::new(),
                    params,
                }),
            }
        }

        let fields = dir
            .field_annotations
            .iter()
            .map(|(idx, set)| {
                let item = self.field_item(*idx);
                FieldAnnotations {
                    name: item
                        .as_ref()
                        .map_or_else(String::new, |f| f.name.to_string()),
                    typ: item
                        .as_ref()
                        .map_or_else(String::new, |f| f.typ.to_string()),
                    annotations: self.annotation_set(set),
                }
            })
            .collect();

        Ok(ClassAnnotations {
            class: self.annotation_set(&dir.class_annotations),
            methods,
            fields,
        })
    }

    fn annotation_set(&self, set: &[AnnotationItem]) -> Vec<Annotation> {
        set.iter()
            .map(|item| Annotation {
                type_name: self
                    .typ(item.annotation.type_idx)
                    .unwrap_or_default()
                    .to_string(),
                visibility: visibility_name(item.visibility),
                elements: item
                    .annotation
                    .elements
                    .iter()
                    .map(|(name_idx, v)| {
                        (
                            self.string(*name_idx).unwrap_or_default().to_string(),
                            self.value_of(v),
                        )
                    })
                    .collect(),
            })
            .collect()
    }

    fn value_of(&self, v: &EncodedValue) -> DexValue {
        match v {
            EncodedValue::Byte(n) => DexValue::Byte(*n),
            EncodedValue::Short(n) => DexValue::Short(*n),
            EncodedValue::Char(n) => DexValue::Char(*n),
            EncodedValue::Int(n) => DexValue::Int(*n),
            EncodedValue::Long(n) => DexValue::Long(*n),
            EncodedValue::Float(n) => DexValue::Float(*n),
            EncodedValue::Double(n) => DexValue::Double(*n),
            EncodedValue::Boolean(b) => DexValue::Bool(*b),
            EncodedValue::Null => DexValue::Null,
            EncodedValue::String(i) => self.string(*i).map_or(DexValue::Opaque("string?"), |s| {
                DexValue::Str(s.to_string())
            }),
            EncodedValue::Type(i) => self
                .typ(*i)
                .map_or(DexValue::Opaque("type?"), |t| DexValue::Type(t.to_string())),
            EncodedValue::Field(i) => self.field_item(*i).map_or(DexValue::Opaque("field?"), |f| {
                DexValue::Field(format!("{}->{}:{}", f.class, f.name, f.typ))
            }),
            EncodedValue::Enum(i) => self.field_item(*i).map_or(DexValue::Opaque("enum?"), |f| {
                DexValue::Enum(format!("{}->{}:{}", f.class, f.name, f.typ))
            }),
            EncodedValue::Method(i) => self
                .method_item(*i)
                .map_or(DexValue::Opaque("method?"), |m| {
                    DexValue::Method(format!("{}->{}", m.class, m.name))
                }),
            EncodedValue::Array(vs) => {
                DexValue::Array(vs.iter().map(|x| self.value_of(x)).collect())
            }
            EncodedValue::MethodType(_) => DexValue::Opaque("method-type"),
            EncodedValue::MethodHandle(_) => DexValue::Opaque("method-handle"),
            EncodedValue::Annotation(_) => DexValue::Opaque("annotation"),
        }
    }
}

/// Appariement positionnel des champs statiques et de l'`encoded_array`.
///
/// Le tableau peut s'arrêter avant la fin de la liste des champs : ceux de
/// queue n'ont alors pas de valeur. Il ne peut pas la dépasser — l'excédent
/// d'un DEX malformé est ignoré, l'appelant le signale.
fn pair_statics(names: Vec<String>, values: Vec<DexValue>) -> Vec<StaticField> {
    let mut values = values.into_iter();
    names
        .into_iter()
        .map(|name| StaticField {
            name,
            value: values.next(),
        })
        .collect()
}

/// Substitutions textuelles. Volontairement dupliqué de `disasm::normalize` :
/// la façade est la couche basse, elle ne dépend d'aucun module d'analyse.
fn subst(s: &str, subs: &[(String, String)]) -> String {
    let mut out = s.to_string();
    for (from, to) in subs {
        out = out.replace(from.as_str(), to.as_str());
    }
    out
}

const ACC_STATIC: u32 = 0x8;
const ACC_NATIVE: u32 = 0x100;

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

    fn noms(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pairage_statique_tableau_plus_court_que_les_champs() {
        // Le cas où une erreur ne se verrait pas : trois champs, une valeur.
        let out = pair_statics(
            noms(&["a", "b", "c"]),
            vec![DexValue::Str("https://i.safespy.com/api/".into())],
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].name, "a");
        assert_eq!(
            out[0].value,
            Some(DexValue::Str("https://i.safespy.com/api/".into()))
        );
        // Les champs de queue n'héritent PAS de la valeur du voisin.
        assert_eq!(out[1].value, None);
        assert_eq!(out[2].value, None);
    }

    #[test]
    fn pairage_statique_ne_decale_pas_sur_un_nom_illisible() {
        // Le champ du milieu a un nom vide (illisible) : il garde sa place.
        let out = pair_statics(
            noms(&["a", "", "c"]),
            vec![DexValue::Int(1), DexValue::Int(2), DexValue::Int(3)],
        );
        assert_eq!(out[2].name, "c");
        assert_eq!(out[2].value, Some(DexValue::Int(3)));
    }

    #[test]
    fn pairage_statique_ignore_l_excedent() {
        let out = pair_statics(noms(&["a"]), vec![DexValue::Int(1), DexValue::Int(2)]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].value, Some(DexValue::Int(1)));
    }

    #[test]
    fn normalisation_recursive_dans_les_tableaux() {
        // Deux substitutions : les descripteurs portent des `/`, les chaînes de
        // constantes portent des `.`. Une seule des deux formes ne suffit pas.
        let subs = vec![
            ("com/duiyun".to_string(), "com/dy".to_string()),
            ("com.duiyun".to_string(), "com.dy".to_string()),
        ];
        let v = DexValue::Array(vec![
            DexValue::Str("com.duiyun.account_auth_type".into()),
            DexValue::Type("Lcom/duiyun/Foo;".into()),
            DexValue::Int(7),
        ]);
        let DexValue::Array(out) = v.normalized(&subs) else {
            panic!("le tableau doit rester un tableau");
        };
        assert_eq!(out[0], DexValue::Str("com.dy.account_auth_type".into()));
        assert_eq!(out[1], DexValue::Type("Lcom/dy/Foo;".into()));
        assert_eq!(out[2], DexValue::Int(7));
    }
}
