//! Surface d'API DÉCLARÉE : ce que les annotations disent du protocole réseau.
//!
//! # Le problème
//!
//! `--strings` rend les gabarits de route au pool (`/v1/users/auth/%s/approve`)
//! mais ne dit ni quelle méthode les porte, ni le verbe HTTP, ni la forme de la
//! charge utile. Sur un client Retrofit classique c'est pire : les routes ne
//! sont PAS des littéraux de code, elles n'existent que dans les annotations —
//! et aucun balayage d'instructions ne les voit.
//!
//! # Ce qui est lu
//!
//! L'`annotation_directory_item` de chaque classe, aux trois niveaux utiles :
//!
//!   - **méthode** : `@GET` / `@POST` / `@PUT` / `@DELETE` / `@PATCH` / `@HEAD`
//!     / `@OPTIONS`, dont l'élément `value` porte le gabarit de route, et
//!     `@HTTP`, qui porte le verbe dans `method` et la route dans `path` ;
//!   - **paramètre** : `@Path` / `@Query` / `@Body` / `@Header` / `@Field` /
//!     `@Part` et leurs variantes. C'est le niveau le plus précieux :
//!     `@Path("userId")` NOMME le paramètre substitué au gabarit ;
//!   - **champ** : `@SerializedName` de Gson, donc la forme des charges utiles.
//!
//! # Ce que ce module ne fait pas
//!
//! Aucune remontée de registre, aucune fenêtre, aucune heuristique : une
//! annotation est là ou elle n'est pas. Il n'y a donc pas de taux de faux
//! positifs à encadrer ici — l'incertitude est ailleurs, dans ce qui n'est PAS
//! annoté, et c'est le bloc de statistiques qui la rend visible.
//!
//! La reconnaissance porte sur le DESCRIPTEUR COMPLET (`Lretrofit2/http/GET;`).
//! Un Retrofit repackagé sous un autre nom de paquet compte donc en `autres` —
//! visible dans les statistiques, jamais silencieux.

use super::dex_facade::{Annotation, DexBin, DexValue};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

const HTTP_PREFIX: &str = "Lretrofit2/http/";
const GSON_SERIALIZED_NAME: &str = "Lcom/google/gson/annotations/SerializedName;";

/// Verbes Retrofit dont l'élément `value` porte la route.
const VERBS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// `@HTTP(method = …, path = …)` : la forme générique, verbe compris.
const VERB_CUSTOM: &str = "HTTP";

/// Annotations de paramètre. `Body` et `Url` ne portent pas de nom.
const PARAM_KINDS: &[&str] = &[
    "Body",
    "Field",
    "FieldMap",
    "Header",
    "HeaderMap",
    "Part",
    "PartMap",
    "Path",
    "Query",
    "QueryMap",
    "QueryName",
    "Tag",
    "Url",
];

/// Annotations de méthode qui qualifient l'envoi sans porter de route.
const METHOD_EXTRAS: &[&str] = &["Headers", "FormUrlEncoded", "Multipart", "Streaming"];

/// Une annotation de paramètre reconnue.
#[derive(Debug, Clone, Serialize)]
pub struct RouteParam {
    /// Position dans les paramètres DÉCLARÉS de la méthode, `this` exclu.
    pub index: usize,
    /// `Path`, `Query`, `Body`… — nom simple de l'annotation.
    pub kind: String,
    /// Élément `value`, quand l'annotation en porte un.
    pub name: Option<String>,
    /// Descripteur Dalvik du paramètre, vide s'il n'a pas pu être apparié.
    pub typ: String,
}

/// Une méthode portant au moins une annotation Retrofit reconnue.
#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub class: String,
    pub method: String,
    /// `GET`, `POST`… ou le verbe d'un `@HTTP`. `None` si la méthode ne porte
    /// que des annotations de paramètre.
    pub verb: Option<String>,
    /// Gabarit de route. `None` quand le verbe est là sans valeur exploitable.
    pub path: Option<String>,
    pub params: Vec<RouteParam>,
    /// `FormUrlEncoded`, `Multipart`, `Headers(...)`…
    pub extras: Vec<String>,
    /// Visibilité de l'annotation porteuse du verbe.
    pub visibility: &'static str,
}

/// Un champ portant `@SerializedName`.
#[derive(Debug, Clone, Serialize)]
pub struct SerializedField {
    pub class: String,
    pub field: String,
    pub typ: String,
    pub serialized: String,
    /// Élément `alternate`, quand il est présent.
    pub alternates: Vec<String>,
}

/// Ce que le balayage a vu, et ce qu'il n'a pas reconnu.
///
/// Il n'y a pas de taux de faux positifs à encadrer : ces compteurs servent à
/// répondre à « Retrofit est-il utilisé ici ? », pas à mesurer une fiabilité.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ApiSurfaceStats {
    pub dex_files: usize,
    pub classes: usize,
    /// Classes portant un `annotation_directory_item` non vide.
    pub annotated_classes: usize,
    /// Annotations lues, tous niveaux et toutes natures confondus.
    pub annotations_seen: usize,
    pub class_level: usize,
    pub method_level: usize,
    pub param_level: usize,
    pub field_level: usize,
    /// Méthodes portant un verbe HTTP.
    pub routes: usize,
    /// Verbe présent mais sans gabarit exploitable.
    pub routes_without_path: usize,
    /// Méthodes annotées au seul niveau paramètre, sans verbe.
    pub params_only_methods: usize,
    pub params_recognized: usize,
    pub serialized_fields: usize,
    /// Annotations vues et NON reconnues — `Lkotlin/Metadata;`,
    /// `Ldalvik/annotation/*`, `@Nullable`, et un Retrofit repackagé.
    pub other_annotations: usize,
    /// `annotation_directory_item` illisible : la classe est sautée.
    pub directory_failures: usize,
    /// Annotation de méthode dont l'index ne correspond à aucune méthode du
    /// `class_data` de la classe. Le nom est alors relu dans `method_ids`.
    pub orphan_method_annotations: usize,
    /// Index de paramètre annoté au-delà des paramètres déclarés.
    pub param_index_mismatch: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct ApiSurfaceReport {
    pub routes: Vec<Route>,
    pub fields: Vec<SerializedField>,
    pub stats: ApiSurfaceStats,
}

impl ApiSurfaceReport {
    fn merge(&mut self, other: ApiSurfaceReport) {
        self.routes.extend(other.routes);
        self.fields.extend(other.fields);
        let s = &mut self.stats;
        let o = other.stats;
        s.dex_files += o.dex_files;
        s.classes += o.classes;
        s.annotated_classes += o.annotated_classes;
        s.annotations_seen += o.annotations_seen;
        s.class_level += o.class_level;
        s.method_level += o.method_level;
        s.param_level += o.param_level;
        s.field_level += o.field_level;
        s.routes += o.routes;
        s.routes_without_path += o.routes_without_path;
        s.params_only_methods += o.params_only_methods;
        s.params_recognized += o.params_recognized;
        s.serialized_fields += o.serialized_fields;
        s.other_annotations += o.other_annotations;
        s.directory_failures += o.directory_failures;
        s.orphan_method_annotations += o.orphan_method_annotations;
        s.param_index_mismatch += o.param_index_mismatch;
    }
}

/// Nom simple d'une annotation Retrofit, ou `None` si ce n'en est pas une.
fn http_name(type_name: &str) -> Option<&str> {
    type_name
        .strip_prefix(HTTP_PREFIX)?
        .strip_suffix(';')
        .filter(|n| !n.contains('/'))
}

/// Rendu d'une valeur d'annotation.
///
/// Les chaînes sortent NUES : la valeur utile d'un `@GET` est la route, pas une
/// chaîne citée. Les valeurs imbriquées (`encoded_value` de type annotation)
/// sortent `<annotation>` — la façade les réduit à [`DexValue::Opaque`].
fn render_value(v: &DexValue) -> String {
    match v {
        DexValue::Str(s) => s.clone(),
        DexValue::Type(t) => t.clone(),
        DexValue::Field(f) | DexValue::Enum(f) => f.clone(),
        DexValue::Method(m) => m.clone(),
        DexValue::Byte(n) => n.to_string(),
        DexValue::Short(n) => n.to_string(),
        DexValue::Char(n) => format!("u+{n:04x}"),
        DexValue::Int(n) => n.to_string(),
        DexValue::Long(n) => n.to_string(),
        DexValue::Float(n) => n.to_string(),
        DexValue::Double(n) => n.to_string(),
        DexValue::Bool(b) => b.to_string(),
        DexValue::Null => "null".to_string(),
        DexValue::Array(v) => v.iter().map(render_value).collect::<Vec<_>>().join(", "),
        DexValue::Opaque(k) => format!("<{k}>"),
    }
}

/// Éléments d'un tableau de chaînes, un par entrée.
fn string_list(v: &DexValue) -> Vec<String> {
    match v {
        DexValue::Array(items) => items.iter().map(render_value).collect(),
        other => vec![render_value(other)],
    }
}

/// Verbe et route portés par une annotation de méthode, si elle en porte.
fn verb_of(a: &Annotation) -> Option<(String, Option<String>)> {
    let name = http_name(&a.type_name)?;

    if name == VERB_CUSTOM {
        let verb = a.element("method").map(render_value)?;
        return Some((verb, a.element("path").map(render_value)));
    }
    if VERBS.contains(&name) {
        // Une route vide est licite (`@GET` + `@Url`) : elle n'est pas un
        // gabarit, on ne la rend pas comme tel.
        let path = a
            .element("value")
            .map(render_value)
            .filter(|p| !p.is_empty());
        return Some((name.to_string(), path));
    }
    None
}

/// Balaye un DEX et rend la surface déclarée.
pub fn scan(path: &Path) -> Result<ApiSurfaceReport> {
    let dex = DexBin::open(path)?;
    let mut report = ApiSurfaceReport {
        stats: ApiSurfaceStats {
            dex_files: 1,
            ..Default::default()
        },
        ..Default::default()
    };

    for class in dex.classes() {
        let Ok(class) = class else { continue };
        report.stats.classes += 1;

        let annotations = match dex.annotations(&class) {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(class = %class.descriptor, error = %e, "annotation_directory illisible");
                report.stats.directory_failures += 1;
                continue;
            }
        };
        if annotations.is_empty() {
            continue;
        }
        report.stats.annotated_classes += 1;

        report.stats.class_level += annotations.class.len();
        report.stats.annotations_seen += annotations.class.len();
        // Le niveau classe est dominé par `Lkotlin/Metadata;` et les
        // annotations système : rien à en tirer pour une surface d'API.
        report.stats.other_annotations += annotations.class.len();

        for fa in &annotations.fields {
            report.stats.field_level += fa.annotations.len();
            report.stats.annotations_seen += fa.annotations.len();
            for a in &fa.annotations {
                if a.type_name != GSON_SERIALIZED_NAME {
                    report.stats.other_annotations += 1;
                    continue;
                }
                let Some(serialized) = a.element("value").map(render_value) else {
                    report.stats.other_annotations += 1;
                    continue;
                };
                report.stats.serialized_fields += 1;
                report.fields.push(SerializedField {
                    class: class.descriptor.to_string(),
                    field: fa.name.clone(),
                    typ: fa.typ.clone(),
                    serialized,
                    alternates: a.element("alternate").map(string_list).unwrap_or_default(),
                });
            }
        }

        for ma in &annotations.methods {
            report.stats.method_level += ma.annotations.len();
            report.stats.annotations_seen += ma.annotations.len();

            let declared = class.methods.iter().find(|m| m.method_idx == ma.method_idx);
            if declared.is_none() {
                report.stats.orphan_method_annotations += 1;
            }
            let name = match declared {
                Some(m) => m.name.to_string(),
                None => dex
                    .method_item(ma.method_idx)
                    .map(|m| m.name.to_string())
                    .unwrap_or_default(),
            };
            let param_types: &[String] = declared.map(|m| m.params).unwrap_or(&[]);

            let mut verb = None;
            let mut path = None;
            let mut visibility = "";
            let mut extras = Vec::new();
            for a in &ma.annotations {
                if let Some((v, p)) = verb_of(a) {
                    verb = Some(v);
                    path = p;
                    visibility = a.visibility;
                    continue;
                }
                match http_name(&a.type_name) {
                    Some(n) if METHOD_EXTRAS.contains(&n) => {
                        let rendered = match a.element("value") {
                            Some(v) => format!("{n}({})", render_value(v)),
                            None => n.to_string(),
                        };
                        extras.push(rendered);
                    }
                    _ => report.stats.other_annotations += 1,
                }
            }

            let mut params = Vec::new();
            for pa in &ma.params {
                report.stats.param_level += pa.annotations.len();
                report.stats.annotations_seen += pa.annotations.len();
                for a in &pa.annotations {
                    match http_name(&a.type_name) {
                        Some(kind) if PARAM_KINDS.contains(&kind) => {
                            if pa.index >= param_types.len() {
                                report.stats.param_index_mismatch += 1;
                            }
                            report.stats.params_recognized += 1;
                            params.push(RouteParam {
                                index: pa.index,
                                kind: kind.to_string(),
                                name: a.element("value").map(render_value),
                                typ: param_types.get(pa.index).cloned().unwrap_or_default(),
                            });
                        }
                        _ => report.stats.other_annotations += 1,
                    }
                }
            }

            if verb.is_none() && params.is_empty() && extras.is_empty() {
                continue;
            }
            if verb.is_some() {
                report.stats.routes += 1;
                if path.is_none() {
                    report.stats.routes_without_path += 1;
                }
            } else {
                report.stats.params_only_methods += 1;
            }
            report.routes.push(Route {
                class: class.descriptor.to_string(),
                method: name,
                verb,
                path,
                params,
                extras,
                visibility,
            });
        }
    }

    tracing::info!(
        routes = report.routes.len(),
        fields = report.fields.len(),
        "surface d'API"
    );
    Ok(report)
}

/// Variante APK : agrège sur tous les `classes*.dex`.
pub fn scan_from_apk(apk: &Path) -> Result<ApiSurfaceReport> {
    let tmp = tempfile::tempdir().context("create tempdir")?;
    let dex_files = crate::parser::extract_dex_files(apk, tmp.path())?;

    let mut merged = ApiSurfaceReport::default();
    for dex in &dex_files {
        match scan(dex) {
            Ok(r) => merged.merge(r),
            Err(e) => tracing::warn!(dex = %dex.display(), error = %e, "DEX ignoré"),
        }
    }
    Ok(merged)
}

/// Accepte un APK ou un DEX brut, reconnu au CONTENU.
pub fn scan_any(path: &Path) -> Result<ApiSurfaceReport> {
    use super::dyn_entrypoints::{sniff, InputKind};

    match sniff(path) {
        Some(InputKind::Apk) => scan_from_apk(path),
        Some(InputKind::Dex) => scan(path),
        None => anyhow::bail!(
            "{} n'est ni un APK (PK\\x03\\x04) ni un DEX (dex\\n) — reconnu au contenu, \
             l'extension n'entre pas en compte",
            path.display()
        ),
    }
}

/// Rendu TSV d'une route : les paramètres et les qualificatifs d'envoi.
pub fn route_detail(r: &Route) -> String {
    let mut parts: Vec<String> = r
        .params
        .iter()
        .map(|p| match &p.name {
            Some(n) => format!("p{}={}({})", p.index, p.kind, n),
            None => format!("p{}={}", p.index, p.kind),
        })
        .collect();
    parts.extend(r.extras.iter().cloned());
    parts.join(" ")
}

/// Rendu TSV d'un champ sérialisé : son type, et ses noms de repli.
pub fn field_detail(f: &SerializedField) -> String {
    if f.alternates.is_empty() {
        return f.typ.clone();
    }
    format!("{} alternate={}", f.typ, f.alternates.join(","))
}

pub fn legend() -> &'static str {
    "\
Surface d'API déclarée par les annotations (--api-surface)

CE QUE CE MODE LIT, ET CE QU'IL NE LIT PAS
Il lit l'annotation_directory_item de chaque classe : les niveaux classe, champ, méthode et
paramètre. Il ne lit AUCUNE instruction. Une route construite à l'exécution, concaténée ou tirée
du pool de chaînes lui est donc invisible — c'est --strings qui la voit, sans dire quelle méthode
la porte. Les deux modes sont complémentaires, aucun ne remplace l'autre.

⚠️ UNE SORTIE VIDE NE VEUT PAS DIRE « PAS DE ROUTE ». Elle veut dire « pas Retrofit », ou
« Retrofit repackagé ». Un client écrit sur HttpURLConnection ou sur OkHttp nu ne porte aucune
annotation de route : son protocole est dans le code, pas dans les métadonnées. Lire le compteur
annotations pour savoir si le binaire est simplement dépourvu d'annotations, ou s'il en porte
beaucoup dont aucune n'est reconnue.

COLONNES
sample               Nom de fichier de l'échantillon, sans extension.
niveau               route   une méthode portant un verbe HTTP, ou des annotations de paramètre.
                     champ   un champ portant @SerializedName (Gson).
classe               Descripteur Dalvik de la classe qui déclare le membre.
membre               Nom de la méthode ou du champ. Le descripteur n'est pas rendu.
cle                  route   le verbe HTTP : GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, ou le
                             verbe porté par @HTTP(method=…). Vide si la méthode ne porte que des
                             annotations de paramètre.
                     champ   SerializedName.
valeur               route   le gabarit de route, tel que l'annotation le déclare, accolades
                             comprises (/v1/users/{userId}/approve). Vide si le verbe est là sans
                             valeur exploitable — cas de @GET suivi d'un @Url.
                     champ   le nom sérialisé, c'est-à-dire la clé telle qu'elle part sur le fil.
detail               route   les paramètres annotés, sous la forme p<N>=<Kind>(<nom>), où N est la
                             position dans les paramètres DÉCLARÉS (this exclu) ; puis les
                             qualificatifs d'envoi (FormUrlEncoded, Multipart, Streaming,
                             Headers(...)).
                     champ   le descripteur du champ, et alternate=… si Gson déclare des noms de
                             repli.

CE QUE p<N>=Path(nom) DONNE, ET POURQUOI C'EST LE PLUS UTILE
@Path(\"userId\") NOMME le paramètre substitué au gabarit. C'est la réponse structurelle à
« d'où vient ce qui remplace le {userId} », obtenue sans remontée de registre et sans heuristique.
@Query nomme un paramètre d'URL, @Body désigne le corps sérialisé (à croiser avec les lignes
champ du même type), @Header un en-tête, @Field / @Part les formes formulaire et multipart.

VISIBILITÉ, ET POURQUOI ELLE CHANGE CE QUI SURVIT
Le DEX marque chaque annotation d'une visibilité :
  runtime   lisible par réflexion à l'exécution. C'est ce qu'EXIGENT Retrofit et Gson, qui lisent
            leurs annotations au moment de construire le client. Une route Retrofit est
            nécessairement runtime.
  build     présente dans le DEX, mais invisible à la réflexion. Outils de compilation et
            d'analyse statique (@Nullable, @IntDef). Une annotation de route en build serait une
            anomalie : le client ne pourrait pas la lire.
  system    consommée par la machine virtuelle elle-même (Ldalvik/annotation/Signature,
            Throws, EnclosingClass, InnerClass, MemberClasses). Jamais une route.
La visibilité n'est pas rendue en colonne : les routes sont runtime par construction. Elle est
conservée dans la sortie JSON.

VALEURS IMBRIQUÉES
Une valeur d'annotation qui est elle-même une annotation (motif des annotations Room :
@Entity(indices = @Index(...)), @ForeignKey) sort <annotation>. La façade réduit ce cas à une
valeur opaque ; sa charge utile n'est pas perdue dans le DEX, elle n'est simplement pas rendue
ici. Retrofit et Gson n'imbriquent pas, ce rendu ne les concerne pas.

RECONNAISSANCE, ET SA LIMITE
La comparaison porte sur le DESCRIPTEUR COMPLET : Lretrofit2/http/GET;,
Lcom/google/gson/annotations/SerializedName;. Un Retrofit relocalisé sous un autre nom de paquet
par un repackager n'est donc PAS reconnu, et compte dans autres. C'est un faux négatif assumé :
reconnaître @GET au nom simple seul ramasserait n'importe quelle annotation maison du même nom.

RÉSUMÉ DE FIN DE PASSE ([API] sur stderr)
  classes            classes lues.
  annotees           classes portant un annotation_directory_item non vide.
  annotations        annotations lues, tous niveaux confondus.
  routes             méthodes portant un verbe HTTP.
  sans_gabarit       parmi elles, celles dont le verbe ne porte pas de route exploitable.
  params_seuls       méthodes annotées au seul niveau paramètre, sans verbe — typiquement une
                     surcharge d'interface, ou un @Url.
  params             annotations de paramètre reconnues.
  champs             champs portant @SerializedName.
  autres             annotations vues et non reconnues. Ce compteur est normalement ÉLEVÉ :
                     Lkotlin/Metadata; met une annotation de classe sur chaque classe Kotlin, et
                     Ldalvik/annotation/* est partout. Il ne dit rien à lui seul ; il sert à
                     distinguer « ce binaire n'a pas d'annotations » de « ce binaire en a
                     beaucoup, mais aucune que je reconnaisse » — ce second cas étant le signe
                     d'un repackaging.
  directory_ko       annotation_directory_item illisible : la classe est sautée, elle ne
                     disparaît pas en silence.
  orphelines         annotation de méthode dont l'index ne correspond à aucune méthode du
                     class_data de la classe. Le nom est alors relu dans method_ids ; la ligne
                     sort, sans les types de ses paramètres. DEX malformé.
  index_hors_plage   paramètre annoté au-delà des paramètres déclarés. La ligne sort avec un type
                     vide plutôt que d'être appariée au mauvais paramètre."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nom_simple_des_annotations_retrofit() {
        assert_eq!(http_name("Lretrofit2/http/GET;"), Some("GET"));
        assert_eq!(http_name("Lretrofit2/http/Path;"), Some("Path"));
        assert_eq!(http_name("Lcom/google/gson/annotations/SerializedName;"), None);
        assert_eq!(http_name("Lkotlin/Metadata;"), None);
        // Un paquet plus profond sous retrofit2/http n'est pas une annotation.
        assert_eq!(http_name("Lretrofit2/http/sub/GET;"), None);
    }

    fn annot(type_name: &str, elements: Vec<(&str, DexValue)>) -> Annotation {
        Annotation {
            type_name: type_name.to_string(),
            visibility: "runtime",
            elements: elements
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    #[test]
    fn verbe_et_route_depuis_value() {
        let a = annot(
            "Lretrofit2/http/GET;",
            vec![("value", DexValue::Str("/v1/users/{userId}/approve".into()))],
        );
        assert_eq!(
            verb_of(&a),
            Some(("GET".into(), Some("/v1/users/{userId}/approve".into())))
        );
    }

    #[test]
    fn http_generique_porte_son_verbe() {
        let a = annot(
            "Lretrofit2/http/HTTP;",
            vec![
                ("method", DexValue::Str("REPORT".into())),
                ("path", DexValue::Str("/v1/devices".into())),
                ("hasBody", DexValue::Bool(true)),
            ],
        );
        assert_eq!(
            verb_of(&a),
            Some(("REPORT".into(), Some("/v1/devices".into())))
        );
    }

    #[test]
    fn route_vide_n_est_pas_un_gabarit() {
        // `@GET("")` suivi d'un `@Url` : le verbe est là, la route ne l'est pas.
        let a = annot("Lretrofit2/http/GET;", vec![("value", DexValue::Str(String::new()))]);
        assert_eq!(verb_of(&a), Some(("GET".into(), None)));
    }

    #[test]
    fn annotation_de_parametre_n_est_pas_un_verbe() {
        let a = annot("Lretrofit2/http/Path;", vec![("value", DexValue::Str("userId".into()))]);
        assert_eq!(verb_of(&a), None);
    }

    #[test]
    fn valeur_imbriquee_sort_opaque() {
        assert_eq!(render_value(&DexValue::Opaque("annotation")), "<annotation>");
    }

    #[test]
    fn chaine_sort_nue_et_tableau_sort_liste() {
        assert_eq!(render_value(&DexValue::Str("/v1/x".into())), "/v1/x");
        assert_eq!(
            string_list(&DexValue::Array(vec![
                DexValue::Str("a: b".into()),
                DexValue::Str("c: d".into()),
            ])),
            vec!["a: b".to_string(), "c: d".to_string()]
        );
    }

    #[test]
    fn detail_rend_la_position_des_parametres() {
        let r = Route {
            class: "Lcom/dri/agent/data/remote/jfw/api/UserApi;".into(),
            method: "approvePasswordless".into(),
            verb: Some("POST".into()),
            path: Some("/v1/users/auth/passwordless/{token}/approve".into()),
            params: vec![
                RouteParam {
                    index: 0,
                    kind: "Path".into(),
                    name: Some("token".into()),
                    typ: "Ljava/lang/String;".into(),
                },
                RouteParam {
                    index: 1,
                    kind: "Body".into(),
                    name: None,
                    typ: "Lcom/dri/agent/data/remote/jfw/model/ApproveRequest;".into(),
                },
            ],
            extras: vec!["FormUrlEncoded".into()],
            visibility: "runtime",
        };
        assert_eq!(route_detail(&r), "p0=Path(token) p1=Body FormUrlEncoded");
    }
}
