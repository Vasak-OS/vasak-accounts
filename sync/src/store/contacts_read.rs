//! Lo que leen las aplicaciones de los contactos: las libretas, las páginas de
//! la lista, la búsqueda y un contacto entero.
//!
//! Todo corre sobre una conexión de **sólo lectura** ([`super::readers`]) y
//! nada de acá escribe. Quién puede llegar hasta acá lo decide `access.rs`,
//! antes: estas funciones no saben de permisos.
//!
//! ── La paginación ───────────────────────────────────────────────────────────
//!
//! Por **cursor**, sobre `(sort_key, id)`, que tiene índice propio y otro por
//! libreta (una prueba de `migrations.rs` mira el plan). Cada página pide lo que
//! viene **después** del último que entregó, no «a partir del 200»: si entre
//! una página y la siguiente entra o se va un contacto, la siguiente no repite
//! ni saltea a ninguno de los que ya estaban. El cursor es opaco para quien lo
//! recibe —base64 de la posición— y se valida al volver: uno que no se entiende
//! es `InvalidArgs`, nunca «desde el principio».
//!
//! Una página trae como mucho [`MAX_PAGE`] contactos (0 pide
//! [`DEFAULT_PAGE`]) y [`MAX_PAGE_BYTES`] de JSON, **medido como se manda**:
//! cada fila cuenta lo que ocupa serializada, escapes incluidos. La que se
//! corta por tamaño se corta **antes** de la fila que no entra, y trae su
//! cursor apuntando ahí; nunca es un error. Una fila que sola no entra en una
//! página —el parser no deja armar una, pero la base puede tener datos de
//! antes— se saltea con un aviso en el diario, y el cursor sigue después de
//! ella: la lista nunca queda trabada. La búsqueda ordena y pagina igual que
//! la lista.
//!
//! **El final de la lista es `next_cursor == null`, no una página vacía.** Si
//! todas las filas que se miraron para una página se saltearon, la página
//! vuelve sin ninguna y **con** cursor, y la siguiente trae lo que sigue.
//!
//! Los contactos sin nada que mostrar (`display_name = ''`) se guardan —son del
//! servidor, y sin su ETag se volverían a pedir— pero **no se listan** ni se
//! devuelven.
//!
//! ── La búsqueda ─────────────────────────────────────────────────────────────
//!
//! Sobre `contacts_fts` (nombre, correos, teléfonos, organización), sin
//! acentos ni mayúsculas. **Lo que escribe la persona nunca va crudo a
//! `MATCH`**: FTS5 tiene su propio lenguaje —`OR`, `NOT`, `NEAR`, `-`,
//! comillas, paréntesis, `*`, `columna:`— y una búsqueda como `ana OR` sería un
//! error de sintaxis, o peor, otra búsqueda. Cada palabra va como una cadena
//! FTS5 entre comillas, con las comillas de adentro duplicadas, y con `*` al
//! final para que «jos» encuentre a «José»: [`fts_query`].

use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use super::{classify, StoreError};
use crate::vcard::{self, Field};

/// El tope de contactos por página.
pub const MAX_PAGE: u32 = 1000;

/// Lo que trae una página si no se pide cuánto.
pub const DEFAULT_PAGE: u32 = 100;

/// El tope de las filas de una página, en bytes de su JSON: con nombres y
/// datos en el tope de la tarjeta, mil contactos podrían ser una docena de
/// megas por el bus.
pub const MAX_PAGE_BYTES: usize = 4 * 1024 * 1024;

/// El tope de la respuesta entera de una página: sus filas, más el sobre
/// (`{"items":[…],"next_cursor":…}`) y el cursor, que no pasa de
/// [`MAX_CURSOR_BYTES`]. Con las filas medidas como se mandan, una página no
/// llega nunca: es la cuenta, no un margen.
pub const MAX_PAGE_REPLY_BYTES: usize = MAX_PAGE_BYTES + MAX_CURSOR_BYTES + 64;

/// El tope de la respuesta de un contacto entero.
///
/// **Se puede llegar**: 50 correos, 50 teléfonos y 50 relaciones de hasta
/// 4096 bytes cada valor son 600 KiB de texto, y con comillas o barras —que el
/// JSON escribe dobles— pasan el mega. Un contacto que no entra se devuelve
/// **recortado**, con `truncated: true`: se sacan del final las relaciones,
/// después los teléfonos y después los correos, hasta que entra. Nunca es un
/// error: un contacto que no se pudiera abrir nunca sería peor que uno al que
/// le faltan los últimos datos, que siguen en el servidor.
pub const MAX_CONTACT_BYTES: usize = 1024 * 1024;

/// El largo máximo de una búsqueda, en bytes.
pub const MAX_QUERY_BYTES: usize = 256;

/// Cuántas palabras puede tener una búsqueda.
pub const MAX_QUERY_TERMS: usize = 8;

/// El largo máximo de un cursor.
///
/// La clave de orden sale del nombre, que el parser corta a 4096 bytes más
/// «…»; en minúsculas crece como mucho la mitad. En el JSON del cursor, lo que
/// más crece es un carácter de control: seis bytes (`\u0001`). El parser ya
/// no los deja pasar, pero una base escrita antes puede tenerlos, así que la
/// cuenta es con ellos: 4099 × 6 más el identificador, en base64, son unos
/// 33 KiB. Con 16 KiB el cursor de una fila así no se podía volver a leer, y
/// la lista no pasaba de esa página.
pub const MAX_CURSOR_BYTES: usize = 64 * 1024;

/// Un argumento que no se puede usar. El texto es fijo y dice cuál.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidArgument(pub &'static str);

impl std::fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Dónde quedó una página: el último contacto que entregó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    sort_key: String,
    id: i64,
}

impl Cursor {
    /// El texto opaco que se le da a quien pidió la página.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(&(&self.sort_key, self.id)).unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    /// El cursor que volvió. Vacío es «desde el principio»; cualquier otra
    /// cosa que no sea uno de los nuestros es un argumento inválido.
    pub fn decode(text: &str) -> Result<Option<Self>, InvalidArgument> {
        const BAD: InvalidArgument = InvalidArgument("el cursor no es válido");
        if text.is_empty() {
            return Ok(None);
        }
        if text.len() > MAX_CURSOR_BYTES {
            return Err(BAD);
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| BAD)?;
        let (sort_key, id): (String, i64) = serde_json::from_slice(&bytes).map_err(|_| BAD)?;
        if id <= 0 {
            return Err(BAD);
        }
        Ok(Some(Self { sort_key, id }))
    }
}

/// Cuántos contactos pedir: 0 es el valor por omisión, y nada pasa de
/// [`MAX_PAGE`].
pub fn page_limit(limit: u32) -> usize {
    match limit {
        0 => DEFAULT_PAGE as usize,
        n => n.min(MAX_PAGE) as usize,
    }
}

/// Un identificador que llegó como texto: una libreta o un contacto.
pub fn parse_id(text: &str) -> Result<i64, InvalidArgument> {
    const BAD: InvalidArgument = InvalidArgument("el identificador no es válido");
    // Sólo dígitos: `parse` aceptaría un `+` adelante.
    if text.is_empty() || text.len() > 19 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    text.parse::<i64>().ok().filter(|id| *id > 0).ok_or(BAD)
}

/// Lo que escribió la persona, como consulta de FTS5 que no puede cambiar de
/// sentido.
///
/// Se parte por los espacios; cada palabra pierde los caracteres de control
/// —NUL incluido— y va entre comillas dobles, con las de adentro duplicadas, y
/// con `*` para buscar por el principio. Las palabras se juntan con espacios,
/// que en FTS5 es «y». Así `ana OR (pérez) -x NEAR "y"` busca las seis palabras
/// tal cual, sin ningún operador.
///
/// - Vacía, o sólo espacios: `InvalidArgs` —para listar está `ListContacts`—.
/// - Más de [`MAX_QUERY_BYTES`] o de [`MAX_QUERY_TERMS`] palabras:
///   `InvalidArgs`. Recortarla en silencio buscaría otra cosa.
/// - Una palabra sin ninguna letra ni número (`*`, `-`, `"`) no busca nada —el
///   tokenizador no la ve— y se descarta. Si no queda ninguna, `Ok(None)`: no
///   hay nada que buscar y la respuesta es una lista vacía.
pub fn fts_query(raw: &str) -> Result<Option<String>, InvalidArgument> {
    if raw.len() > MAX_QUERY_BYTES {
        return Err(InvalidArgument("la búsqueda es demasiado larga"));
    }
    let words: Vec<String> = raw
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|w| !w.is_empty())
        .map(|w| w.chars().filter(|c| !c.is_control()).collect())
        .collect();
    if words.is_empty() {
        return Err(InvalidArgument("la búsqueda está vacía"));
    }
    if words.len() > MAX_QUERY_TERMS {
        return Err(InvalidArgument("la búsqueda tiene demasiadas palabras"));
    }
    let terms: Vec<String> = words
        .iter()
        .filter(|w| w.chars().any(char::is_alphanumeric))
        .map(|w| format!("\"{}\"*", w.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        return Ok(None);
    }
    Ok(Some(terms.join(" ")))
}

/// Una libreta, para `ListAddressBooks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressBookItem {
    pub id: String,
    pub display_name: String,
    /// Cuántos contactos se pueden ver en ella.
    pub contacts: i64,
}

/// Un contacto en una página de la lista o de la búsqueda: lo que hace falta
/// para dibujar la fila.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContactSummary {
    pub id: String,
    pub address_book_id: String,
    pub display_name: String,
    /// El primer correo, si tiene.
    pub email: Option<String>,
    /// El primer teléfono, si tiene.
    pub phone: Option<String>,
}

/// Una página.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Con qué pedir la siguiente; `null` si no hay más. Es lo único que dice
    /// que la lista terminó: una página puede venir vacía y con cursor, si
    /// todas sus filas se saltearon.
    pub next_cursor: Option<String>,
}

/// Un contacto entero, leído de la tarjeta cruda en el momento.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContactDetail {
    pub id: String,
    pub address_book_id: String,
    pub uid: String,
    pub display_name: String,
    pub emails: Vec<Field>,
    pub phones: Vec<Field>,
    pub organization: String,
    pub notes: String,
    pub related: Vec<Field>,
    /// Si no entraba en [`MAX_CONTACT_BYTES`] y se le sacaron datos del
    /// final: relaciones, después teléfonos, después correos.
    pub truncated: bool,
}

/// Las libretas, por nombre.
pub fn list_address_books(connection: &Connection) -> Result<Vec<AddressBookItem>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT b.id, b.display_name,
                    (SELECT count(*) FROM contacts c
                      WHERE c.address_book_id = b.id AND c.display_name != '')
               FROM address_books b
              ORDER BY b.display_name, b.id",
        )
        .map_err(classify)?;
    let rows = statement
        .query_map([], |row| {
            Ok(AddressBookItem {
                id: row.get::<_, i64>(0)?.to_string(),
                display_name: row.get(1)?,
                contacts: row.get(2)?,
            })
        })
        .map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// Una página de la lista: todas las libretas, o una.
pub fn list_contacts(
    connection: &Connection,
    address_book: Option<i64>,
    after: Option<&Cursor>,
    limit: usize,
) -> Result<Page<ContactSummary>, StoreError> {
    page(connection, address_book, None, after, limit, MAX_PAGE_BYTES)
}

/// Una página de la búsqueda. `query` es lo que devolvió [`fts_query`].
pub fn search_contacts(
    connection: &Connection,
    query: &str,
    after: Option<&Cursor>,
    limit: usize,
) -> Result<Page<ContactSummary>, StoreError> {
    page(connection, None, Some(query), after, limit, MAX_PAGE_BYTES)
}

/// La consulta de las dos, armada según lo que se pidió, para que cada forma
/// use su índice.
fn page(
    connection: &Connection,
    address_book: Option<i64>,
    fts: Option<&str>,
    after: Option<&Cursor>,
    limit: usize,
    byte_cap: usize,
) -> Result<Page<ContactSummary>, StoreError> {
    let mut sql = String::from(
        "SELECT c.id, c.address_book_id, c.display_name, c.sort_key,
                (SELECT e.value FROM contact_emails e
                  WHERE e.contact_id = c.id ORDER BY e.position LIMIT 1),
                (SELECT p.value FROM contact_phones p
                  WHERE p.contact_id = c.id ORDER BY p.position LIMIT 1)
           FROM contacts c
          WHERE c.display_name != ''",
    );
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(book) = address_book {
        params.push(book.into());
        sql.push_str(&format!(" AND c.address_book_id = ?{}", params.len()));
    }
    if let Some(fts) = fts {
        params.push(fts.to_string().into());
        sql.push_str(&format!(
            " AND c.id IN (SELECT rowid FROM contacts_fts WHERE contacts_fts MATCH ?{})",
            params.len()
        ));
    }
    if let Some(after) = after {
        params.push(after.sort_key.clone().into());
        params.push(after.id.into());
        sql.push_str(&format!(
            " AND (c.sort_key, c.id) > (?{}, ?{})",
            params.len() - 1,
            params.len()
        ));
    }
    // Uno más de los pedidos, para saber si hay otra página.
    params.push(((limit + 1) as i64).into());
    sql.push_str(&format!(
        " ORDER BY c.sort_key, c.id LIMIT ?{}",
        params.len()
    ));

    let mut statement = connection.prepare(&sql).map_err(classify)?;
    let mut rows = statement
        .query(rusqlite::params_from_iter(params))
        .map_err(classify)?;

    let mut items = Vec::new();
    // La última fila que se miró, se haya entregado o salteado: de ahí sigue
    // la página siguiente.
    let mut last: Option<Cursor> = None;
    let mut bytes = 0usize;
    let mut more = false;
    let mut fetched = 0usize;
    while let Some(row) = rows.next().map_err(classify)? {
        fetched += 1;
        let summary = ContactSummary {
            id: row.get::<_, i64>(0).map_err(classify)?.to_string(),
            address_book_id: row.get::<_, i64>(1).map_err(classify)?.to_string(),
            display_name: row.get(2).map_err(classify)?,
            email: row.get(4).map_err(classify)?,
            phone: row.get(5).map_err(classify)?,
        };
        // Lo que cuesta en la respuesta: su JSON, escapes incluidos, y la coma
        // que la separa de la siguiente. Contar los bytes crudos dejaba pasar
        // una página de controles —seis bytes cada uno en el JSON— que después
        // no entraba en la respuesta.
        let size = serde_json::to_string(&summary)
            .map_or(usize::MAX, |json| json.len())
            .saturating_add(1);
        if items.len() == limit || (!items.is_empty() && bytes.saturating_add(size) > byte_cap) {
            more = true;
            break;
        }
        let position = Cursor {
            sort_key: row.get(3).map_err(classify)?,
            id: row.get(0).map_err(classify)?,
        };
        if size > byte_cap {
            // Sola no entra en ninguna página: se saltea, y la siguiente
            // empieza después de ella.
            tracing::warn!(
                "un contacto no entra en una página ({size} bytes) y no se lista; \
                 GetContact lo devuelve recortado"
            );
            last = Some(position);
            continue;
        }
        bytes += size;
        last = Some(position);
        items.push(summary);
    }
    // Se miraron todas las pedidas más una sin cortar: hubo filas salteadas,
    // y puede haber más después.
    if fetched > limit {
        more = true;
    }
    Ok(Page {
        items,
        next_cursor: if more { last.map(|c| c.encode()) } else { None },
    })
}

/// Un contacto entero, o `None` si no está o no tiene nada que mostrar.
pub fn get_contact(connection: &Connection, id: i64) -> Result<Option<ContactDetail>, StoreError> {
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT address_book_id, raw_vcard FROM contacts
              WHERE id = ?1 AND display_name != ''",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(classify)?;
    let Some((address_book_id, raw)) = row else {
        return Ok(None);
    };
    // Lo guardado es la tarjeta cruda (la decisión 3 del taller): se lee ahora.
    let Some(contact) = vcard::contact_from(&raw, "") else {
        return Ok(None);
    };
    Ok(Some(fit_contact(
        ContactDetail {
            id: id.to_string(),
            address_book_id: address_book_id.to_string(),
            uid: contact.uid,
            display_name: contact.display_name,
            emails: contact.emails,
            phones: contact.phones,
            organization: contact.organization,
            notes: contact.notes,
            related: contact.related,
            truncated: false,
        },
        MAX_CONTACT_BYTES,
    )))
}

/// Cuánto ocupa algo en JSON.
fn json_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_string(value).map_or(usize::MAX, |json| json.len())
}

/// Un contacto que entra en `cap` bytes de JSON: entero si entra, y si no,
/// sin sus últimas relaciones, después sin sus últimos teléfonos y después
/// sin sus últimos correos, con `truncated`. Lo que queda —nombre,
/// organización, nota, de a 4096 bytes— entra siempre.
fn fit_contact(mut contact: ContactDetail, cap: usize) -> ContactDetail {
    if json_len(&contact) <= cap {
        return contact;
    }
    contact.truncated = true;
    let mut size = json_len(&contact);
    for kind in 0..3 {
        let fields = match kind {
            0 => &mut contact.related,
            1 => &mut contact.phones,
            _ => &mut contact.emails,
        };
        while size > cap {
            let Some(field) = fields.pop() else { break };
            // El elemento y, si no era el único, la coma que lo separaba.
            size = size.saturating_sub(json_len(&field) + usize::from(!fields.is_empty()));
        }
    }
    contact
}

/// Lo que se contesta por el bus, en JSON, sin pasar de `cap` bytes.
pub fn to_capped_json<T: Serialize>(value: &T, cap: usize) -> Result<String, StoreError> {
    let json = serde_json::to_string(value)
        .map_err(|e| StoreError::Sqlite(format!("no se pudo serializar: {e}")))?;
    if json.len() > cap {
        return Err(StoreError::Sqlite(format!(
            "la respuesta pasaría los {cap} bytes"
        )));
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::contacts::tests::{open_store, row};
    use super::super::contacts::{ContactOp, ContactRow, StoredAddressBook};
    use super::super::paths::tests::TempDir;
    use super::super::Store;
    use super::*;

    fn book(store: &mut Store, href: &str, name: &str) -> StoredAddressBook {
        store
            .upsert_address_books(&[(href.into(), name.into())])
            .unwrap()
            .into_iter()
            .find(|b| b.href == href)
            .unwrap()
    }

    // Cajas porque así las arma `row`, y así las guarda `ContactOp::Upsert`.
    #[allow(clippy::vec_box)]
    fn add(store: &mut Store, book: &StoredAddressBook, rows: Vec<Box<ContactRow>>) {
        for chunk in rows.chunks(500) {
            let ops: Vec<ContactOp> = chunk.iter().cloned().map(ContactOp::Upsert).collect();
            store.apply_contacts(book, &ops, None, u64::MAX).unwrap();
        }
    }

    fn named(n: usize, name: &str) -> Box<ContactRow> {
        row(
            &format!("https://x/a/{n}.vcf"),
            name,
            &format!("c{n}@x.com"),
        )
    }

    /// Todas las páginas de una lista, desde el principio.
    fn all_pages(
        connection: &Connection,
        limit: usize,
        mut between: impl FnMut(usize),
    ) -> Vec<ContactSummary> {
        let mut seen = Vec::new();
        let mut cursor: Option<Cursor> = None;
        for page_number in 0.. {
            let page = list_contacts(connection, None, cursor.as_ref(), limit).unwrap();
            seen.extend(page.items);
            match page.next_cursor {
                Some(next) => cursor = Cursor::decode(&next).unwrap(),
                None => break,
            }
            between(page_number);
        }
        seen
    }

    /// El centro de la paginación: entre una página y la siguiente entra un
    /// contacto adelante del cursor y otro atrás. Ninguno de los que ya estaban
    /// se repite ni se saltea, y el de adelante aparece.
    #[test]
    fn la_paginacion_no_repite_ni_saltea_si_entra_una_fila_en_el_medio() {
        let temp = TempDir::new("pagina-medio");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            (0..30)
                .map(|n| named(n, &format!("Contacto {n:02}")))
                .collect(),
        );
        let before: Vec<String> = list_contacts(store.connection(), None, None, 1000)
            .unwrap()
            .items
            .into_iter()
            .map(|c| c.id)
            .collect();
        assert_eq!(before.len(), 30);

        // Las páginas por los lectores, y la escritura por la de siempre entre
        // la primera y la segunda, como la sincronización.
        let readers = store.readers();
        let mut seen = Vec::new();
        let mut cursor: Option<Cursor> = None;
        let mut inserted = false;
        loop {
            let after = cursor.clone();
            let page = readers
                .read(move |c| list_contacts(c, None, after.as_ref(), 10))
                .unwrap();
            seen.extend(page.items);
            let Some(next) = page.next_cursor else { break };
            cursor = Cursor::decode(&next).unwrap();
            if !inserted {
                inserted = true;
                add(
                    &mut store,
                    &b,
                    vec![
                        named(100, "Contacto 15 y medio"),
                        named(101, "Contacto 05 y medio"),
                    ],
                );
            }
        }

        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for c in &seen {
            *counts.entry(c.display_name.clone()).or_default() += 1;
        }
        assert!(counts.values().all(|n| *n == 1), "sin repetidos");
        let seen_ids: Vec<&String> = seen.iter().map(|c| &c.id).collect();
        for id in &before {
            assert!(
                seen_ids.contains(&id),
                "sin huecos entre los que ya estaban"
            );
        }
        assert!(counts.contains_key("Contacto 15 y medio"));
        assert!(
            !counts.contains_key("Contacto 05 y medio"),
            "el que entró atrás del cursor no aparece en las páginas que siguen"
        );
        assert_eq!(seen.len(), 31);
    }

    /// Nombres iguales tienen la misma clave de orden: el `id` los desempata, y
    /// cortar la página en el medio de un empate no pierde a ninguno.
    #[test]
    fn los_empates_de_nombre_no_se_pierden_entre_paginas() {
        let temp = TempDir::new("pagina-empates");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(&mut store, &b, (0..25).map(|n| named(n, "Ana")).collect());

        let seen = all_pages(store.connection(), 7, |_| {});
        let mut ids: Vec<String> = seen.into_iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), 25);
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 25);
    }

    #[test]
    fn el_limite_se_recorta_a_mil_y_cero_es_el_de_omision() {
        assert_eq!(page_limit(0), DEFAULT_PAGE as usize);
        assert_eq!(page_limit(1), 1);
        assert_eq!(page_limit(1000), 1000);
        assert_eq!(page_limit(1001), 1000);
        assert_eq!(page_limit(u32::MAX), 1000);

        let temp = TempDir::new("pagina-tope");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            (0..1203).map(|n| named(n, &format!("C {n:04}"))).collect(),
        );
        let page = list_contacts(store.connection(), None, None, page_limit(5000)).unwrap();
        assert_eq!(page.items.len(), 1000);
        assert!(page.next_cursor.is_some());
        let rest = list_contacts(
            store.connection(),
            None,
            Cursor::decode(page.next_cursor.as_deref().unwrap())
                .unwrap()
                .as_ref(),
            1000,
        )
        .unwrap();
        assert_eq!(rest.items.len(), 203);
        assert_eq!(rest.next_cursor, None);
    }

    /// Una página que llega al tope de texto se corta antes, con su cursor.
    #[test]
    fn la_pagina_se_corta_por_tamano_con_su_cursor() {
        let temp = TempDir::new("pagina-bytes");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            (0..10).map(|n| named(n, &format!("C {n}"))).collect(),
        );
        let small = page(store.connection(), None, None, None, 1000, 600).unwrap();
        assert!(small.items.len() < 10 && !small.items.is_empty());
        assert!(small.next_cursor.is_some());
    }

    /// Una fila como las que podía guardar el parser de antes: el nombre y
    /// la clave de orden llenos de caracteres de control, que en el JSON
    /// pesan seis bytes cada uno.
    fn stored_before_the_fix(n: usize) -> Box<ContactRow> {
        let mut row = named(n, "x");
        let name = format!("{n:04}{}", "\u{1}".repeat(4000));
        row.contact.display_name = name.clone();
        row.contact.sort_name = name;
        row
    }

    /// Las páginas se miden como se mandan: 400 filas de 4 KB de controles
    /// son 9,6 MB de JSON. Contando los bytes crudos entraban todas en una
    /// página que después no pasaba el tope de la respuesta, y la lista no
    /// avanzaba. Ahora cada página entra, y el cursor —también lleno de
    /// controles— se vuelve a leer hasta el final.
    #[test]
    fn una_pagina_con_controles_en_los_nombres_no_pasa_el_tope_del_json() {
        let temp = TempDir::new("pagina-controles");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            (0..400).map(stored_before_the_fix).collect(),
        );

        let mut seen = Vec::new();
        let mut cursor: Option<Cursor> = None;
        let mut pages = 0;
        loop {
            pages += 1;
            assert!(pages < 50, "la lista no termina");
            let page = list_contacts(store.connection(), None, cursor.as_ref(), 1000).unwrap();
            assert!(!page.items.is_empty(), "una página vacía antes del final");
            assert!(
                to_capped_json(&page, MAX_PAGE_REPLY_BYTES).is_ok(),
                "la página {pages} no entra en la respuesta"
            );
            seen.extend(page.items.into_iter().map(|c| c.id));
            let Some(next) = page.next_cursor else { break };
            assert!(
                Cursor::decode(&next).is_ok(),
                "el cursor de la página {pages} no se puede volver a leer"
            );
            cursor = Cursor::decode(&next).unwrap();
        }
        assert!(pages > 1, "tenía que cortarse por tamaño");
        let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
        assert_eq!((seen.len(), unique.len()), (400, 400));
    }

    /// Una fila que sola no entra en una página se saltea, y la lista sigue
    /// después de ella: ni un error, ni una página que vuelve siempre igual.
    #[test]
    fn una_fila_que_sola_no_entra_se_saltea_y_la_lista_sigue() {
        let temp = TempDir::new("pagina-fila-grande");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            vec![
                named(0, "C 0"),
                named(1, "C 1"),
                named(2, &format!("C 2 {}", "x".repeat(2000))),
                named(3, "C 3"),
                named(4, "C 4"),
            ],
        );
        let mut seen = Vec::new();
        let mut cursor: Option<Cursor> = None;
        for _ in 0..10 {
            let page = page(store.connection(), None, None, cursor.as_ref(), 1000, 600).unwrap();
            seen.extend(page.items.into_iter().map(|c| c.display_name));
            match page.next_cursor {
                Some(next) => cursor = Cursor::decode(&next).unwrap(),
                None => break,
            }
        }
        assert_eq!(seen, vec!["C 0", "C 1", "C 3", "C 4"]);
    }

    /// Si todas las filas que mira una página se saltean, la página vuelve
    /// vacía **con** cursor, y el cursor avanza: la siguiente trae lo que
    /// sigue. El final es `next_cursor == null`, no la página vacía.
    #[test]
    fn una_pagina_de_filas_salteadas_vuelve_vacia_con_cursor_y_la_siguiente_trae_lo_que_sigue() {
        let temp = TempDir::new("pagina-salteadas");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            vec![
                named(0, &format!("A {}", "x".repeat(2000))),
                named(1, &format!("B {}", "x".repeat(2000))),
                named(2, "C"),
            ],
        );
        let first = page(store.connection(), None, None, None, 1, 600).unwrap();
        assert!(first.items.is_empty());
        let next = first
            .next_cursor
            .expect("una página vacía de filas salteadas no es el final");
        let cursor = Cursor::decode(&next).unwrap();
        let second = page(store.connection(), None, None, cursor.as_ref(), 1, 600).unwrap();
        let names: Vec<&str> = second
            .items
            .iter()
            .map(|c| c.display_name.as_str())
            .collect();
        assert_eq!(names, vec!["C"]);
        assert_eq!(second.next_cursor, None);
    }

    #[test]
    fn un_cursor_malformado_es_un_argumento_invalido() {
        let engine = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let too_long = "A".repeat(MAX_CURSOR_BYTES + 1);
        let bad: Vec<String> = vec![
            "!!!".into(),
            "no es base64 ni de lejos".into(),
            engine.encode(b"basura"),
            engine.encode(br#"{"k":"a","i":1}"#),
            engine.encode(br#"["a",-1]"#),
            engine.encode(br#"["a",0]"#),
            engine.encode(br#"["a","1"]"#),
            engine.encode(br#"["a",1,2]"#),
            too_long,
        ];
        for text in &bad {
            assert_eq!(
                Cursor::decode(text),
                Err(InvalidArgument("el cursor no es válido"))
            );
        }
        assert_eq!(Cursor::decode(""), Ok(None));
        let cursor = Cursor {
            sort_key: "pérez, ana".into(),
            id: 42,
        };
        assert_eq!(Cursor::decode(&cursor.encode()), Ok(Some(cursor)));
    }

    #[test]
    fn un_identificador_que_no_es_un_numero_positivo_se_rechaza() {
        assert_eq!(parse_id("42"), Ok(42));
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            "1.0",
            " 1",
            "abc",
            "99999999999999999999",
        ] {
            assert!(parse_id(bad).is_err(), "{bad}");
        }
    }

    fn names(page: Page<ContactSummary>) -> Vec<String> {
        let mut names: Vec<String> = page.items.into_iter().map(|c| c.display_name).collect();
        names.sort();
        names
    }

    fn search(store: &Store, raw: &str) -> Vec<String> {
        match fts_query(raw).unwrap() {
            Some(query) => names(search_contacts(store.connection(), &query, None, 1000).unwrap()),
            None => Vec::new(),
        }
    }

    /// Lo que escribe la persona nunca es lenguaje de FTS5: ni operadores, ni
    /// comillas, ni paréntesis, ni columnas, ni un NUL. Nada rompe la consulta
    /// ni la vuelve otra búsqueda.
    #[test]
    fn la_busqueda_con_operadores_no_rompe_ni_cambia_de_sentido() {
        let temp = TempDir::new("buscar-operadores");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            vec![
                named(1, "Ana Pérez"),
                named(2, "Juan Or"),
                named(3, "Near Norte"),
                named(4, "Beto Not"),
            ],
        );

        // Con `OR` de FTS5 serían Ana y Juan; acá son tres palabras que tienen
        // que estar todas, y ninguno las tiene.
        assert!(search(&store, "ana OR juan").is_empty());
        // `NOT` y `NEAR` no son operadores: son palabras.
        assert_eq!(search(&store, "beto NOT"), vec!["Beto Not"]);
        assert_eq!(search(&store, "NEAR norte"), vec!["Near Norte"]);
        for raw in [
            "\"",
            "ana\"",
            "\"ana",
            "*",
            "ana*",
            "-ana",
            "(ana)",
            "ana)",
            "NEAR(ana juan)",
            "name:ana",
            "ana AND NOT juan",
            "^ana",
            "ana\0pérez",
            "{ana}",
            "ana + juan",
        ] {
            let query = fts_query(raw);
            assert!(
                query.is_ok(),
                "«{}» se tenía que aceptar",
                raw.escape_debug()
            );
            if let Ok(Some(query)) = query {
                assert!(
                    search_contacts(store.connection(), &query, None, 10).is_ok(),
                    "«{}» rompió la consulta",
                    raw.escape_debug()
                );
            }
        }
        // Un guion o un paréntesis pegado no le cambia el sentido a la palabra.
        assert_eq!(search(&store, "-ana"), vec!["Ana Pérez"]);
        assert_eq!(search(&store, "(ana)"), vec!["Ana Pérez"]);
        assert_eq!(search(&store, "ana\0pérez"), vec!["Ana Pérez"]);
    }

    #[test]
    fn la_busqueda_encuentra_sin_acentos_y_por_el_principio() {
        let temp = TempDir::new("buscar-prefijo");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(
            &mut store,
            &b,
            vec![
                named(1, "José Pérez"),
                named(2, "Josefina Gómez"),
                named(3, "Raúl"),
            ],
        );
        assert_eq!(search(&store, "jos"), vec!["Josefina Gómez", "José Pérez"]);
        assert_eq!(search(&store, "JOSE perez"), vec!["José Pérez"]);
        // Por el correo también.
        assert_eq!(search(&store, "c3@x"), vec!["Raúl"]);
    }

    #[test]
    fn la_busqueda_vacia_es_invalida_y_la_de_solo_signos_no_busca_nada() {
        for empty in ["", "   ", "\t\n"] {
            assert_eq!(
                fts_query(empty),
                Err(InvalidArgument("la búsqueda está vacía"))
            );
        }
        assert_eq!(fts_query("* - \"\""), Ok(None));
        assert!(fts_query(&"a".repeat(MAX_QUERY_BYTES + 1)).is_err());
        assert!(fts_query("a b c d e f g h i").is_err());
        assert_eq!(
            fts_query("a b c d e f g h")
                .unwrap()
                .unwrap()
                .matches('*')
                .count(),
            8
        );
        assert_eq!(fts_query("di\"go").unwrap().unwrap(), "\"di\"\"go\"*");
    }

    /// Una tarjeta sin nada que mostrar se guarda —es del servidor— pero no se
    /// lista, no se encuentra y no se devuelve.
    #[test]
    fn los_contactos_sin_nombre_no_se_listan_ni_se_devuelven() {
        let temp = TempDir::new("sin-nombre");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        let mut empty = named(1, "x");
        empty.contact = vcard::Contact::default();
        empty.raw_vcard = "BEGIN:VCARD\r\nEND:VCARD".into();
        add(&mut store, &b, vec![empty, named(2, "Ana")]);

        assert_eq!(
            names(list_contacts(store.connection(), None, None, 100).unwrap()),
            vec!["Ana"]
        );
        let hidden: i64 = store
            .connection()
            .query_row("SELECT id FROM contacts WHERE display_name = ''", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(get_contact(store.connection(), hidden).unwrap(), None);
        assert_eq!(
            list_address_books(store.connection()).unwrap()[0].contacts,
            1
        );
    }

    /// `GetContact` lee la tarjeta cruda en el momento y devuelve lo
    /// interpretado —correos, teléfonos, organización, notas, relaciones—, no
    /// la tarjeta.
    #[test]
    fn un_contacto_se_devuelve_interpretado_desde_la_tarjeta() {
        let temp = TempDir::new("un-contacto");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        let raw = "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:u-1\r\nFN:Ana Pérez\r\n\
                   EMAIL;TYPE=work:ana@x.com\r\nTEL;TYPE=cell:+54 11 5555\r\n\
                   ORG:Vasak\r\nNOTE:Una nota\r\nRELATED;TYPE=spouse:text:Juan\r\nEND:VCARD";
        add(
            &mut store,
            &b,
            vec![Box::new(ContactRow {
                href: "https://x/a/1.vcf".into(),
                etag: None,
                contact: vcard::contact_from(raw, "https://x/a/1.vcf").unwrap(),
                raw_vcard: raw.into(),
            })],
        );
        let id = parse_id(
            &list_contacts(store.connection(), None, None, 1)
                .unwrap()
                .items[0]
                .id,
        )
        .unwrap();
        let contact = get_contact(store.connection(), id).unwrap().unwrap();
        assert_eq!(contact.display_name, "Ana Pérez");
        assert_eq!(contact.uid, "u-1");
        assert_eq!(contact.emails[0].value, "ana@x.com");
        assert_eq!(contact.phones[0].value, "+54 11 5555");
        assert_eq!(contact.organization, "Vasak");
        assert_eq!(contact.notes, "Una nota");
        assert_eq!(contact.related.len(), 1);
        let json = to_capped_json(&contact, MAX_CONTACT_BYTES).unwrap();
        assert!(!json.contains("BEGIN:VCARD"), "no va la tarjeta cruda");
        assert!(
            !json.contains("https://x/"),
            "ni la dirección en el servidor"
        );
        assert_eq!(get_contact(store.connection(), id + 1000).unwrap(), None);
    }

    fn add_raw(store: &mut Store, book: &StoredAddressBook, raw: &str) -> i64 {
        add(
            store,
            book,
            vec![Box::new(ContactRow {
                href: "https://x/a/grande.vcf".into(),
                etag: None,
                contact: vcard::contact_from(raw, "https://x/a/grande.vcf").unwrap(),
                raw_vcard: raw.into(),
            })],
        );
        parse_id(
            &list_contacts(store.connection(), None, None, 1)
                .unwrap()
                .items[0]
                .id,
        )
        .unwrap()
    }

    /// Una tarjeta de 450 KB —menos que el tope de una tarjeta— con 150
    /// valores de 3000 caracteres de control: en el JSON eran 2,7 MB y
    /// `GetContact` no contestaba nunca. Sin los controles, entra entera.
    #[test]
    fn un_contacto_con_controles_se_devuelve_entero() {
        let temp = TempDir::new("contacto-controles");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        let noise = "\u{1}".repeat(3000);
        let mut raw = String::from("BEGIN:VCARD\r\nFN:Ana\r\n");
        for n in 0..50 {
            raw.push_str(&format!("EMAIL:a{n}{noise}@x.com\r\n"));
            raw.push_str(&format!("TEL:+54 {n}{noise}\r\n"));
            raw.push_str(&format!("RELATED:text:Juan {n}{noise}\r\n"));
        }
        raw.push_str("END:VCARD");
        assert!(raw.len() < 512 * 1024);
        let id = add_raw(&mut store, &b, &raw);

        let contact = get_contact(store.connection(), id).unwrap().unwrap();
        assert!(!contact.truncated, "tenía que entrar entero");
        assert_eq!(contact.emails.len(), 50);
        assert_eq!(contact.emails[7].value, "a7@x.com");
        assert!(to_capped_json(&contact, MAX_CONTACT_BYTES).is_ok());
    }

    /// Un contacto que no entra en 1 MiB de JSON —150 valores de 4000
    /// comillas, que el JSON escribe dobles— llega recortado desde el final,
    /// con `truncated`, y nunca como error.
    #[test]
    fn un_contacto_que_no_entra_se_devuelve_recortado() {
        let temp = TempDir::new("contacto-recortado");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        let quotes = "\"".repeat(4000);
        let mut raw = String::from("BEGIN:VCARD\r\nFN:Ana\r\nNOTE:una nota\r\n");
        for n in 0..50 {
            raw.push_str(&format!("EMAIL:a{n}{quotes}\r\n"));
            raw.push_str(&format!("TEL:{n}{quotes}\r\n"));
            raw.push_str(&format!("RELATED:text:{n}{quotes}\r\n"));
        }
        raw.push_str("END:VCARD");
        let id = add_raw(&mut store, &b, &raw);

        let contact = get_contact(store.connection(), id).unwrap().unwrap();
        assert!(contact.truncated);
        let json = to_capped_json(&contact, MAX_CONTACT_BYTES);
        assert!(json.is_ok(), "el contacto recortado tenía que entrar");
        assert!(json.unwrap().contains("\"truncated\":true"));
        assert_eq!(contact.display_name, "Ana");
        assert_eq!(contact.notes, "una nota");
        assert_eq!(
            contact.emails.len(),
            50,
            "los correos, lo último que se saca"
        );
        assert_eq!(contact.phones.len(), 50);
        assert!(
            contact.related.len() < 50,
            "se sacan primero las relaciones"
        );
        let kept_in_order = contact.related.iter().enumerate().all(|(n, r)| {
            r.value
                .trim_start_matches("text:")
                .starts_with(&format!("{n}\""))
        });
        assert!(kept_in_order, "se sacan del final");
    }

    #[test]
    fn una_respuesta_que_pasa_el_tope_no_sale() {
        let big = vec!["x".repeat(100); 20];
        assert!(to_capped_json(&big, 1000).is_err());
        assert!(to_capped_json(&big, 10_000).is_ok());
    }

    #[test]
    fn las_libretas_se_listan_con_cuantos_contactos_tienen() {
        let temp = TempDir::new("libretas");
        let mut store = open_store(&temp);
        let a = book(&mut store, "https://x/a/", "Trabajo");
        let b = book(&mut store, "https://x/b/", "Casa");
        add(&mut store, &a, vec![named(1, "Ana"), named(2, "Beto")]);
        add(
            &mut store,
            &b,
            vec![row("https://x/b/1.vcf", "Carla", "c@x.com")],
        );
        let books = list_address_books(store.connection()).unwrap();
        let summary: Vec<(&str, i64)> = books
            .iter()
            .map(|b| (b.display_name.as_str(), b.contacts))
            .collect();
        assert_eq!(summary, vec![("Casa", 1), ("Trabajo", 2)]);
        // Y la lista de una libreta sólo trae lo suyo.
        assert_eq!(
            names(list_contacts(store.connection(), Some(b.id), None, 100).unwrap()),
            vec!["Carla"]
        );
    }

    /// Las conexiones de lectura no pueden escribir: ni por la apertura ni por
    /// una orden.
    #[test]
    fn los_lectores_no_pueden_escribir() {
        let temp = TempDir::new("lectores");
        let mut store = open_store(&temp);
        let b = book(&mut store, "https://x/a/", "A");
        add(&mut store, &b, vec![named(1, "Ana")]);
        let readers = store.readers();

        let names = readers.read(|c| list_contacts(c, None, None, 10)).unwrap();
        assert_eq!(names.items.len(), 1);
        let write = readers.read(|c| {
            c.execute("DELETE FROM contacts", [])
                .map_err(super::super::classify)
        });
        assert!(write.is_err());
        assert_eq!(
            list_contacts(store.connection(), None, None, 10)
                .unwrap()
                .items
                .len(),
            1
        );
    }

    /// Soltar la base cierra sus lectores, aunque alguien tenga el grupo.
    #[test]
    fn soltar_la_base_cierra_sus_lectores() {
        let temp = TempDir::new("lectores-cierre");
        let store = open_store(&temp);
        let readers = store.readers();
        assert_eq!(readers.open_connections(), 2);
        drop(store);
        assert!(readers.is_closed());
        assert_eq!(readers.open_connections(), 0);
        assert_eq!(
            readers.read(list_address_books).err(),
            Some(StoreError::Missing)
        );
    }
}
