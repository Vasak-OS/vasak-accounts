//! Escribir vCard, conservador: se parte del crudo y se toca sólo lo que cambió.
//!
//! [`apply_changes`] edita una tarjeta que ya existe, [`new_contact`] arma una
//! desde cero. Lo que el parche no nombra —una `PHOTO` en base64, una `X-` de un
//! exportador, el `VERSION`— sale byte por byte como entró.
//!
//! ── `RELATED`: nunca las dos formas a la vez ────────────────────────────────
//!
//! Hay dos maneras de escribir «la esposa de Ana es Marta», y la decisión 3 del
//! taller (`vasak-contacts#2`) es que **no se mezclan**: `RELATED` de la 4.0, y
//! el par de Apple `itemN.X-ABRELATEDNAMES` + `itemN.X-ABLabel`. La lectura
//! ([`crate::vcard`]) lee `RELATED` si la tarjeta trae alguno, y la de Apple sólo
//! si no hay ninguno. La escritura es el espejo: al fijar relaciones, se escribe
//! **en la forma que la tarjeta ya usaba** —si usaba la de Apple, se edita esa;
//! si usaba `RELATED` o es nueva, se escribe `RELATED`—, y nunca se agrega la
//! otra. Así una tarjeta de Apple editada no gana un `RELATED` duplicado que la
//! lectura tomaría en lugar de lo que la persona ve.

use super::{detect_eol, escape_text, fold, logical_lines, render, Change, Logical};
use crate::vcard::{split_property, Property};

/// Una relación para escribir: su etiqueta («spouse», «child») y a quién apunta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    pub label: String,
    pub value: String,
}

/// Lo que cambia de una tarjeta.
///
/// Cada campo es un [`Change`]: por omisión no se toca. Las relaciones se fijan
/// enteras —la lista nueva reemplaza la vieja—, en la forma que la tarjeta ya
/// usaba.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactPatch {
    /// `FN`, el nombre que se muestra.
    pub full_name: Change<String>,
    /// `ORG`.
    pub organization: Change<String>,
    /// `NOTE`.
    pub note: Change<String>,
    /// `RELATED` o el par de Apple, según lo que la tarjeta ya traía.
    pub related: Change<Vec<Relation>>,
}

impl ContactPatch {
    /// Si no cambia nada.
    pub fn is_empty(&self) -> bool {
        self.full_name == Change::Leave
            && self.organization == Change::Leave
            && self.note == Change::Leave
            && self.related == Change::Leave
    }
}

/// En qué forma están —o van a ir— las relaciones de una tarjeta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelatedForm {
    /// `RELATED` de la 4.0.
    Related,
    /// El par de Apple `X-ABRELATEDNAMES` + `X-ABLabel`.
    Apple,
}

/// Qué forma usa la tarjeta, con la misma regla que la lectura: `RELATED` si
/// trae alguno; si no, la de Apple si la trae; y si no trae ninguna, `RELATED`
/// (la 4.0), que es lo que se escribe en una tarjeta nueva.
fn related_form(properties: &[Property]) -> RelatedForm {
    let mut has_apple = false;
    for property in properties {
        match property.name.as_str() {
            "RELATED" => return RelatedForm::Related,
            "X-ABRELATEDNAMES" => has_apple = true,
            _ => {}
        }
    }
    if has_apple {
        RelatedForm::Apple
    } else {
        RelatedForm::Related
    }
}

/// La propiedad de una línea lógica, o `None` si no se entiende.
fn property_of(logical: &Logical) -> Option<Property> {
    split_property(&logical.unfolded())
}

/// El número de grupo `itemN` más alto que ya usa la tarjeta, para que los
/// grupos nuevos de una relación de Apple no pisen los de un correo.
fn max_item_group(properties: &[Property]) -> u32 {
    properties
        .iter()
        .filter_map(|p| p.group.as_deref())
        .filter_map(|group| group.strip_prefix("item")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
}

/// Edita una tarjeta que ya existe: cambia lo que el parche nombra y deja el
/// resto intacto.
///
/// Un parche vacío devuelve el crudo tal cual.
pub fn apply_changes(raw_vcard: &str, patch: &ContactPatch) -> String {
    if patch.is_empty() {
        return raw_vcard.to_string();
    }
    let eol = detect_eol(raw_vcard);
    let logicals = logical_lines(raw_vcard);
    let properties: Vec<Property> = logicals.iter().filter_map(property_of).collect();

    let editing_related = !matches!(patch.related, Change::Leave);
    // Al reescribir las relaciones se sacan **las dos formas**, no sólo la que se
    // vuelve a escribir. Si el crudo trajera `RELATED` y la forma de Apple a la
    // vez —malformado—, dejar la de Apple como «desconocida» haría que el nombre
    // viejo sobreviviera en la copia del servidor; sacarla cierra la decisión 3.
    // Los grupos de Apple cuyas líneas (`X-ABRELATEDNAMES` y su `X-ABLabel`) se
    // sacan.
    let apple_groups: Vec<String> = if editing_related {
        properties
            .iter()
            .filter(|p| p.name == "X-ABRELATEDNAMES")
            .filter_map(|p| p.group.clone())
            .collect()
    } else {
        Vec::new()
    };

    let mut out: Vec<String> = Vec::new();
    let mut done = Done::default();
    let mut flushed = false;

    for logical in &logicals {
        let property = property_of(logical);
        let name = property.as_ref().map(|p| p.name.as_str()).unwrap_or("");

        if name == "END"
            && property
                .as_ref()
                .is_some_and(|p| p.value.trim().eq_ignore_ascii_case("VCARD"))
        {
            flush(&mut out, patch, &done, &properties);
            flushed = true;
            out.extend_from_slice(&logical.physical);
            continue;
        }

        let Some(property) = property else {
            out.extend_from_slice(&logical.physical);
            continue;
        };

        match property.name.as_str() {
            "FN" => put_text(
                &mut out,
                &patch.full_name,
                &mut done.full_name,
                &property,
                logical,
            ),
            "ORG" => put_text(
                &mut out,
                &patch.organization,
                &mut done.organization,
                &property,
                logical,
            ),
            "NOTE" => put_text(&mut out, &patch.note, &mut done.note, &property, logical),
            // Al editar relaciones se sacan las dos formas; la elegida se vuelve a
            // escribir en `flush`, la otra no.
            "RELATED" if editing_related => {}
            "X-ABRELATEDNAMES" if editing_related => {}
            "X-ABLABEL"
                if editing_related
                    && property
                        .group
                        .as_ref()
                        .is_some_and(|g| apple_groups.contains(g)) => {}
            _ => out.extend_from_slice(&logical.physical),
        }
    }

    // Una tarjeta sin `END:VCARD` está mal formada, pero lo que se fijó se
    // agrega igual: perder un cambio por dos palabras que faltaron sería peor.
    if !flushed {
        flush(&mut out, patch, &done, &properties);
    }

    let mut text = out.join(eol);
    text.push_str(eol);
    text
}

/// Arma una tarjeta desde cero.
///
/// El `UID` lo da quien llama. Las relaciones van en `RELATED` (4.0): una
/// tarjeta nueva no arrastra la forma de Apple.
pub fn new_contact(uid: &str, patch: &ContactPatch) -> String {
    let eol = "\r\n";
    let mut out: Vec<String> = vec!["BEGIN:VCARD".into(), "VERSION:4.0".into()];
    out.extend(fold(&render("UID", &[], uid)));
    if let Change::Set(text) = &patch.full_name {
        out.extend(fold(&render("FN", &[], &escape_text(text))));
    }
    if let Change::Set(text) = &patch.organization {
        out.extend(fold(&render("ORG", &[], &escape_text(text))));
    }
    if let Change::Set(text) = &patch.note {
        out.extend(fold(&render("NOTE", &[], &escape_text(text))));
    }
    if let Change::Set(relations) = &patch.related {
        push_related(&mut out, relations);
    }
    out.push("END:VCARD".into());

    let mut text = out.join(eol);
    text.push_str(eol);
    text
}

/// Qué propiedades del parche ya se reescribieron, para no duplicarlas ni
/// volver a agregarlas al cerrar.
#[derive(Default)]
struct Done {
    full_name: bool,
    organization: bool,
    note: bool,
}

/// Reescribe —o saca, o deja— una propiedad de texto, conservando sus
/// parámetros. Una segunda aparición de la misma propiedad ya fijada se
/// descarta.
fn put_text(
    out: &mut Vec<String>,
    change: &Change<String>,
    done: &mut bool,
    property: &Property,
    logical: &Logical,
) {
    match change {
        Change::Leave => out.extend_from_slice(&logical.physical),
        Change::Clear => {}
        Change::Set(text) => {
            if !*done {
                *done = true;
                out.extend(fold(&render(
                    &property.name,
                    &property.params,
                    &escape_text(text),
                )));
            }
        }
    }
}

/// Al cerrar la tarjeta: agrega lo que el parche fija y no estaba, y las
/// relaciones nuevas en la forma que corresponde.
fn flush(out: &mut Vec<String>, patch: &ContactPatch, done: &Done, properties: &[Property]) {
    if let Change::Set(text) = &patch.full_name {
        if !done.full_name {
            out.extend(fold(&render("FN", &[], &escape_text(text))));
        }
    }
    if let Change::Set(text) = &patch.organization {
        if !done.organization {
            out.extend(fold(&render("ORG", &[], &escape_text(text))));
        }
    }
    if let Change::Set(text) = &patch.note {
        if !done.note {
            out.extend(fold(&render("NOTE", &[], &escape_text(text))));
        }
    }
    if let Change::Set(relations) = &patch.related {
        match related_form(properties) {
            RelatedForm::Related => push_related(out, relations),
            RelatedForm::Apple => push_apple(out, relations, max_item_group(properties)),
        }
    }
    // `Change::Clear` de las relaciones no agrega nada: las líneas viejas ya se
    // sacaron al recorrer.
}

/// Escribe las relaciones como `RELATED` (4.0). La etiqueta va como `TYPE`, y
/// una relación sin etiqueta va sin él.
fn push_related(out: &mut Vec<String>, relations: &[Relation]) {
    for relation in relations {
        let params = if relation.label.trim().is_empty() {
            Vec::new()
        } else {
            vec![format!("TYPE={}", sanitize_label(&relation.label))]
        };
        out.extend(fold(&render(
            "RELATED",
            &params,
            &escape_text(&relation.value),
        )));
    }
}

/// Escribe las relaciones en la forma de Apple, con grupos `itemN` nuevos que no
/// pisan los que ya había.
///
/// El número se cuenta en `u64` a partir de `max_item` —que sale del crudo y lo
/// controla el servidor CardDAV—. Una tarjeta con `item4294967295` haría
/// desbordar un `u32` (pánico en debug, envoltura en release que **anularía** la
/// garantía de no pisar), así que `max_item + 1 + offset` en `u64` no desborda y
/// queda siempre por encima de cualquier `itemN` que la tarjeta ya use (la
/// lectura sólo cuenta los que entran en un `u32`).
fn push_apple(out: &mut Vec<String>, relations: &[Relation], max_item: u32) {
    let base = max_item as u64;
    for (offset, relation) in relations.iter().enumerate() {
        let group = format!("item{}", base + 1 + offset as u64);
        out.extend(fold(&render(
            &format!("{group}.X-ABRELATEDNAMES"),
            &[],
            &escape_text(&relation.value),
        )));
        out.extend(fold(&render(
            &format!("{group}.X-ABLabel"),
            &[],
            &sanitize_label(&relation.label),
        )));
    }
}

/// Una etiqueta sin caracteres que partirían la línea o inyectarían un
/// parámetro: nada de controles ni dos puntos (partirían la propiedad), ni punto
/// y coma, coma, igual o comillas (un `spouse;PREF=1` metería un parámetro en la
/// línea `RELATED`).
fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | ';' | ',' | '=' | '"'))
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vcard::contact_from;

    fn set(text: &str) -> Change<String> {
        Change::Set(text.to_string())
    }

    fn relation(label: &str, value: &str) -> Relation {
        Relation {
            label: label.to_string(),
            value: value.to_string(),
        }
    }

    const CARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:abc\r\nFN:Ana Pérez\r\n\
        N:Pérez;Ana;;;\r\nEMAIL;TYPE=WORK:ana@ejemplo.com\r\nTEL;TYPE=CELL:+54 11 5555-5555\r\n\
        END:VCARD\r\n";

    /// Lo que no se toca sale igual: se edita el `FN` y el correo, el teléfono,
    /// el `N` y el `UID` vuelven idénticos.
    #[test]
    fn editar_el_nombre_deja_el_resto_intacto() {
        let out = apply_changes(
            CARD,
            &ContactPatch {
                full_name: set("Ana Gómez"),
                ..Default::default()
            },
        );
        let before = contact_from(CARD, "").unwrap();
        let after = contact_from(&out, "").unwrap();
        assert_eq!(after.display_name, "Ana Gómez");
        assert_eq!(after.uid, before.uid);
        assert_eq!(after.emails, before.emails);
        assert_eq!(after.phones, before.phones);
        assert_eq!(after.sort_name, before.sort_name);
    }

    /// **La prueba de la decisión 3: una tarjeta de Apple editada no gana un
    /// `RELATED`.** Se cambian las relaciones de una tarjeta que usa el par de
    /// Apple; tienen que quedar en esa forma y no aparecer ningún `RELATED`, que
    /// la lectura tomaría en lugar de lo que la persona ve.
    #[test]
    fn una_tarjeta_de_apple_editada_no_gana_un_related() {
        let apple = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ana\r\n\
            item1.X-ABRELATEDNAMES;type=pref:Marta Vieja\r\nitem1.X-ABLabel:_$!<Spouse>!$_\r\n\
            END:VCARD\r\n";
        let out = apply_changes(
            apple,
            &ContactPatch {
                related: Change::Set(vec![relation("spouse", "Marta Gómez")]),
                ..Default::default()
            },
        );
        assert!(
            !out.contains("RELATED:") && !out.to_uppercase().contains("\r\nRELATED;"),
            "apareció un RELATED: {out}"
        );
        assert!(out.contains("X-ABRELATEDNAMES"), "{out}");
        assert!(out.contains("Marta Gómez"));
        assert!(
            !out.contains("Marta Vieja"),
            "la relación vieja quedó: {out}"
        );

        // Y la lectura la ve una sola vez, con su etiqueta.
        let c = contact_from(&out, "").unwrap();
        assert_eq!(c.related.len(), 1);
        assert_eq!(c.related[0].value, "Marta Gómez");
        assert_eq!(c.related[0].label, "spouse");
    }

    /// Una tarjeta que usa `RELATED` se edita en `RELATED`, y no gana la forma
    /// de Apple.
    #[test]
    fn una_tarjeta_con_related_se_edita_en_related() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ana\r\n\
            RELATED;TYPE=spouse:Marta Vieja\r\nEND:VCARD\r\n";
        let out = apply_changes(
            card,
            &ContactPatch {
                related: Change::Set(vec![relation("spouse", "Marta Gómez")]),
                ..Default::default()
            },
        );
        assert!(out.contains("RELATED;TYPE=spouse:Marta Gómez"), "{out}");
        assert!(!out.contains("X-ABRELATEDNAMES"));
        assert!(!out.contains("Marta Vieja"));
        let c = contact_from(&out, "").unwrap();
        assert_eq!(c.related.len(), 1);
    }

    /// Una tarjeta nueva, o una sin relaciones, escribe `RELATED` (4.0).
    #[test]
    fn sin_relaciones_previas_se_escribe_related() {
        let out = apply_changes(
            CARD,
            &ContactPatch {
                related: Change::Set(vec![relation("child", "Juan Pérez")]),
                ..Default::default()
            },
        );
        assert!(out.contains("RELATED;TYPE=child:Juan Pérez"), "{out}");
        assert!(!out.contains("X-ABRELATEDNAMES"));
    }

    /// Los grupos `itemN` nuevos de una relación de Apple no pisan los que ya
    /// usaban los correos.
    #[test]
    fn los_grupos_de_apple_no_pisan_los_que_habia() {
        let apple = "BEGIN:VCARD\r\nFN:Ana\r\nitem1.EMAIL:ana@x.com\r\n\
            item2.X-ABRELATEDNAMES:Vieja\r\nitem2.X-ABLabel:_$!<Spouse>!$_\r\nEND:VCARD\r\n";
        let out = apply_changes(
            apple,
            &ContactPatch {
                related: Change::Set(vec![relation("spouse", "Nueva")]),
                ..Default::default()
            },
        );
        // El correo con su grupo sigue; la relación vieja se fue; la nueva usa un
        // grupo por encima de item2.
        assert!(out.contains("item1.EMAIL:ana@x.com"), "{out}");
        assert!(!out.contains("Vieja"));
        assert!(out.contains("item3.X-ABRELATEDNAMES:Nueva"), "{out}");
        let c = contact_from(&out, "").unwrap();
        assert_eq!(
            c.related,
            vec![crate::vcard::Field {
                label: "spouse".into(),
                value: "Nueva".into()
            }]
        );
    }

    /// **H2 (seguridad): un `itemN` enorme del servidor no desborda ni pisa.**
    /// `max_item` sale del crudo, que lo controla el servidor CardDAV. Con
    /// `item4294967295` (el máximo de un `u32`), contar en `u32` desbordaría
    /// —pánico en debug, envoltura en release que pondría el grupo nuevo encima
    /// de uno viejo—. Contando en `u64` no desborda y el grupo nuevo queda por
    /// encima.
    #[test]
    fn un_item_group_enorme_del_servidor_no_desborda_ni_pisa() {
        let apple = "BEGIN:VCARD\r\nFN:Ana\r\n\
            item4294967295.X-ABRELATEDNAMES:Vieja\r\nitem4294967295.X-ABLabel:_$!<Spouse>!$_\r\n\
            END:VCARD\r\n";
        // No tiene que entrar en pánico (correr esto ya lo prueba).
        let out = apply_changes(
            apple,
            &ContactPatch {
                related: Change::Set(vec![relation("spouse", "Nueva")]),
                ..Default::default()
            },
        );
        // El grupo nuevo está por encima del máximo del crudo; la vieja se fue.
        assert!(
            out.contains("item4294967296.X-ABRELATEDNAMES:Nueva"),
            "{out}"
        );
        assert!(!out.contains("Vieja"), "{out}");
        // Y no reusó el mismo grupo que ya existía: no hay dos relaciones.
        let c = contact_from(&out, "").unwrap();
        assert_eq!(c.related.len(), 1);
        assert_eq!(c.related[0].value, "Nueva");
    }

    /// **H3 (seguridad): una etiqueta con `;` no inyecta un parámetro.** Un
    /// `label = "spouse;PREF=1"` escrito crudo partiría la línea `RELATED` en
    /// `TYPE=spouse` más un parámetro `PREF=1` que la persona no puso.
    #[test]
    fn una_etiqueta_con_punto_y_coma_no_inyecta_un_parametro() {
        let out = apply_changes(
            CARD,
            &ContactPatch {
                related: Change::Set(vec![relation("spouse;PREF=1", "Marta")]),
                ..Default::default()
            },
        );
        assert!(!out.contains(";PREF"), "se inyectó un parámetro: {out}");
        assert!(!out.contains("PREF=1"), "{out}");
        // La relación se escribe igual, con la etiqueta saneada en un solo `TYPE`.
        let c = contact_from(&out, "").unwrap();
        assert_eq!(c.related.len(), 1);
        assert_eq!(c.related[0].value, "Marta");
    }

    /// **H4 (seguridad): editar relaciones no deja residuo de la otra forma.**
    /// Una tarjeta malformada con `RELATED` **y** la forma de Apple a la vez: al
    /// editar, se reescribe `RELATED` y la línea de Apple con el nombre viejo
    /// **no** queda como «desconocida» en la copia del servidor.
    #[test]
    fn editar_relaciones_no_deja_residuo_de_la_otra_forma() {
        let both = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ana\r\n\
            RELATED;TYPE=spouse:Marta Vieja\r\n\
            item1.X-ABRELATEDNAMES:Marta Apple\r\nitem1.X-ABLabel:_$!<Spouse>!$_\r\n\
            END:VCARD\r\n";
        let out = apply_changes(
            both,
            &ContactPatch {
                related: Change::Set(vec![relation("spouse", "Marta Nueva")]),
                ..Default::default()
            },
        );
        assert!(out.contains("RELATED;TYPE=spouse:Marta Nueva"), "{out}");
        assert!(
            !out.contains("X-ABRELATEDNAMES"),
            "quedó la forma de Apple: {out}"
        );
        assert!(!out.contains("Marta Apple"), "{out}");
        assert!(!out.contains("Marta Vieja"), "{out}");
        let c = contact_from(&out, "").unwrap();
        assert_eq!(c.related.len(), 1);
        assert_eq!(c.related[0].value, "Marta Nueva");
    }

    /// Las propiedades desconocidas no se pierden: una `PHOTO` y una `X-` salen
    /// tal como entraron.
    #[test]
    fn lo_desconocido_se_conserva() {
        let card = "BEGIN:VCARD\r\nFN:Vieja\r\nPHOTO;ENCODING=b:iVBORw0KGgo=\r\n\
            X-CUSTOM:algo raro\r\nEND:VCARD\r\n";
        let out = apply_changes(
            card,
            &ContactPatch {
                full_name: set("Nueva"),
                ..Default::default()
            },
        );
        assert!(out.contains("PHOTO;ENCODING=b:iVBORw0KGgo="), "{out}");
        assert!(out.contains("X-CUSTOM:algo raro"));
        assert!(out.contains("FN:Nueva"));
    }

    /// El texto se escapa como lo deshace la lectura, y al leerlo otra vez vuelve
    /// entero.
    #[test]
    fn el_texto_editado_se_escapa_y_vuelve_entero() {
        let out = apply_changes(
            CARD,
            &ContactPatch {
                note: set("Compró pan, leche; y café"),
                ..Default::default()
            },
        );
        assert!(out.contains(r"NOTE:Compró pan\, leche\; y café"), "{out}");
        assert_eq!(
            contact_from(&out, "").unwrap().notes,
            "Compró pan, leche; y café"
        );
    }

    /// Fijar lo que no estaba lo agrega; sacar lo que estaba lo quita.
    #[test]
    fn se_agrega_lo_que_falta_y_se_saca_lo_que_sobra() {
        let card = "BEGIN:VCARD\r\nFN:Ana\r\nNOTE:vieja\r\nEND:VCARD\r\n";
        let out = apply_changes(
            card,
            &ContactPatch {
                organization: set("Vasak Group"),
                note: Change::Clear,
                ..Default::default()
            },
        );
        assert!(out.contains("ORG:Vasak Group"), "{out}");
        assert!(!out.contains("NOTE"));
    }

    /// Un parche vacío no cambia nada.
    #[test]
    fn un_parche_vacio_no_cambia_nada() {
        assert_eq!(apply_changes(CARD, &ContactPatch::default()), CARD);
    }

    /// Una tarjeta nueva es válida y se lee, con sus relaciones en `RELATED`.
    #[test]
    fn una_tarjeta_nueva_es_valida_y_se_lee() {
        let out = new_contact(
            "nuevo-1",
            &ContactPatch {
                full_name: set("Juan Gómez"),
                organization: set("Vasak Group"),
                related: Change::Set(vec![relation("spouse", "Ana")]),
                ..Default::default()
            },
        );
        assert!(out.starts_with("BEGIN:VCARD\r\nVERSION:4.0\r\n"));
        assert!(out.contains("UID:nuevo-1"));
        assert!(out.contains("RELATED;TYPE=spouse:Ana"));
        assert!(!out.contains("X-ABRELATEDNAMES"));

        let c = contact_from(&out, "https://x/j.vcf").unwrap();
        assert_eq!(c.display_name, "Juan Gómez");
        assert_eq!(c.organization, "Vasak Group");
        assert_eq!(c.related.len(), 1);
    }

    /// Un valor largo se pliega a 75 octetos y al leerlo vuelve entero.
    #[test]
    fn un_valor_largo_editado_se_pliega() {
        // Sin espacio al final: la nota de vCard, a diferencia del título de
        // iCalendar, no se recorta al leerse, así que un espacio final
        // sobreviviría y haría ruido en la comparación.
        let largo = vec!["Nota larga"; 30].join(" ");
        let out = apply_changes(
            CARD,
            &ContactPatch {
                note: set(&largo),
                ..Default::default()
            },
        );
        for line in out.split("\r\n") {
            assert!(line.len() <= 75, "línea sin plegar: {line:?}");
        }
        assert_eq!(contact_from(&out, "").unwrap().notes, largo);
    }
}
