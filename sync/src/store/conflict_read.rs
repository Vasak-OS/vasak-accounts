//! La superficie de conflicto que leen las aplicaciones (`ListConflicts` /
//! `GetConflict` de `AccountsStore`): qué objetos locales chocaron con el
//! servidor, y la comparación «la mía / la del servidor» de uno de ellos.
//!
//! Un objeto está en conflicto cuando su op en `pending_dav_ops` quedó en
//! `state = 'conflict'` —un `412` del servidor: el recurso cambió desde
//! `base_etag`— (ver `queue.rs`). La escritura conservadora **no pisa nada**: la
//! fila guardada sigue marcada con `pending_op` y la copia local intacta, y A3
//! (`vasak-accounts#23`) trae además la **copia del servidor** (`server_etag` /
//! `server_raw`) a la misma fila de la op, cifrada. De ahí sale todo lo de acá.
//!
//! ── Qué sale y qué no ────────────────────────────────────────────────────────
//!
//! El identificador de cara a la aplicación es el **id local** del objeto (el
//! mismo de `GetEvent`/`GetContact`), nunca el `href`: la dirección del recurso
//! en el servidor no sale del almacén (igual criterio que el resto de las
//! lecturas y escrituras). `GetConflict` sí devuelve los **crudos** —la vCard o
//! el iCal local y la del servidor—, que es justo lo que la UI comparativa
//! necesita; por eso quien lo llama tiene que tener el permiso de lectura del
//! área, que la superficie D-Bus comprueba antes de llegar hasta acá.

use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use super::lifecycle::{CALENDAR_AREA, CONTACTS_AREA};
use super::queue::area_tables;
use super::{classify, StoreError};

/// Un objeto en conflicto, para la lista: lo mínimo para dibujar la fila. Nunca
/// el `href` ni los crudos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictItem {
    /// El id local del objeto, como lo toma `GetConflict` (y `GetEvent` /
    /// `GetContact`).
    pub id: String,
    /// Qué cambio local chocó: `put` (creación o edición) o `delete` (borrado).
    pub op: String,
    /// El título del evento o el nombre del contacto, para la fila. Vacío si no
    /// se pudo resolver.
    pub summary: String,
    /// Si ya se trajo la copia del servidor para comparar (A3 la trae con tope):
    /// con `false`, `GetConflict` dirá «copia del servidor no disponible».
    pub has_server_copy: bool,
}

/// La comparación de un objeto en conflicto: la versión local y la del servidor,
/// para la UI «mantener la mía / tomar la del servidor».
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConflictDetail {
    pub id: String,
    pub op: String,
    /// El crudo local —el iCal o la vCard que la persona tiene sin confirmar—,
    /// tal como está guardado. **Ausente** cuando el cambio local es un borrado
    /// (`op = 'delete'`): no hay versión local que mostrar, «la mía» es borrarlo.
    pub local: Option<String>,
    /// El crudo de la versión del servidor, si ya se trajo (A3). **Ausente**
    /// mientras no esté: entonces `server_unavailable` es `true`.
    pub server: Option<String>,
    /// El ETag de la versión del servidor, si hay copia.
    pub server_etag: Option<String>,
    /// Si todavía no hay copia del servidor con qué comparar: la UI muestra «copia
    /// del servidor no disponible» en vez de fallar.
    pub server_unavailable: bool,
}

/// La columna con el resumen de fila de cada área: el `summary` de un evento, el
/// `display_name` de un contacto.
fn summary_column(area: &str) -> Option<&'static str> {
    match area {
        CALENDAR_AREA => Some("summary"),
        CONTACTS_AREA => Some("display_name"),
        _ => None,
    }
}

/// La columna con el crudo guardado de cada área: el iCal de un evento, la vCard
/// de un contacto.
fn raw_column(area: &str) -> Option<&'static str> {
    match area {
        CALENDAR_AREA => Some("raw_ical"),
        CONTACTS_AREA => Some("raw_vcard"),
        _ => None,
    }
}

/// Los objetos de un área que están en conflicto, en el orden en que se
/// encolaron. Sólo del área que se pide: ninguna consulta cruza de área. Vacío
/// si no hay ninguno.
pub fn list_conflicts(
    connection: &Connection,
    area: &str,
) -> Result<Vec<ConflictItem>, StoreError> {
    let (table, coltable, colcol) = area_tables(area)
        .ok_or_else(|| StoreError::InvalidArgument("área sin conflictos".into()))?;
    let summary = summary_column(area).expect("un área con cola tiene columna de resumen");
    let sql = format!(
        "SELECT obj.id, p.op, coalesce(obj.{summary}, ''), p.server_raw IS NOT NULL
           FROM pending_dav_ops p
           JOIN {coltable} col ON col.href = p.collection_href
           JOIN {table} obj ON obj.{colcol} = col.id AND obj.href = p.object_href
          WHERE p.area = ?1 AND p.state = 'conflict'
          ORDER BY p.id"
    );
    let mut statement = connection.prepare(&sql).map_err(classify)?;
    let rows = statement
        .query_map([area], |row| {
            Ok(ConflictItem {
                id: row.get::<_, i64>(0)?.to_string(),
                op: row.get(1)?,
                summary: row.get(2)?,
                has_server_copy: row.get(3)?,
            })
        })
        .map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// La comparación de un objeto en conflicto, por su id local, o `None` si ese id
/// no está en conflicto en esa área. Trae el crudo local y la copia del servidor
/// (si A3 la trajo). Una consulta sola, acotada al área pedida.
pub fn get_conflict(
    connection: &Connection,
    area: &str,
    id: i64,
) -> Result<Option<ConflictDetail>, StoreError> {
    let (table, coltable, colcol) = area_tables(area)
        .ok_or_else(|| StoreError::InvalidArgument("área sin conflictos".into()))?;
    let raw = raw_column(area).expect("un área con cola tiene columna de crudo");
    let sql = format!(
        "SELECT p.op, obj.{raw}, p.server_raw, p.server_etag
           FROM {table} obj
           JOIN {coltable} col ON col.id = obj.{colcol}
           JOIN pending_dav_ops p
                 ON p.area = ?1 AND p.object_href = obj.href
                AND p.collection_href = col.href
          WHERE obj.id = ?2 AND p.state = 'conflict'"
    );
    type Row = (String, String, Option<Vec<u8>>, Option<String>);
    let row: Option<Row> = connection
        .query_row(&sql, rusqlite::params![area, id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .optional()
        .map_err(classify)?;
    let Some((op, local_raw, server_raw, server_etag)) = row else {
        return Ok(None);
    };
    // Un borrado local no tiene crudo local que mostrar: «la mía» es borrarlo.
    let local = (op != "delete").then_some(local_raw);
    let server_unavailable = server_raw.is_none();
    let server = server_raw.map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    Ok(Some(ConflictDetail {
        id: id.to_string(),
        op,
        local,
        server,
        server_etag,
        server_unavailable,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::contacts::tests::{open_store, row};
    use super::super::contacts::{ContactOp, StoredAddressBook};
    use super::super::paths::tests::TempDir;
    use super::super::Store;
    use super::*;

    const BOOK: &str = "https://x/a/";

    fn one_book(store: &mut Store) -> StoredAddressBook {
        store
            .upsert_address_books(&[(BOOK.into(), "A".into())])
            .unwrap()
            .remove(0)
    }

    /// Un contacto al día (sin op).
    fn add_synced(store: &mut Store, book: &StoredAddressBook, href: &str, name: &str) {
        store
            .apply_contacts(
                book,
                &[ContactOp::Upsert(row(href, name, "x@x.com"))],
                None,
                u64::MAX,
            )
            .unwrap();
    }

    /// Pone en conflicto el contacto `href`, encolando una edición y marcándola.
    fn make_conflict(store: &mut Store, book: &StoredAddressBook, href: &str, name: &str) {
        store
            .enqueue_contact_put(book, &row(href, name, "x@x.com"))
            .unwrap();
        let op = store
            .pending_ops(CONTACTS_AREA)
            .unwrap()
            .into_iter()
            .find(|o| o.object_href == href)
            .unwrap();
        store.mark_conflict(&op, "cambió en el servidor").unwrap();
    }

    /// `list_conflicts` lista **sólo** los objetos en conflicto del área pedida:
    /// no los que están al día, no los pendientes sin chocar, y nunca los de otra
    /// área. Trae el id local, la op, el resumen y si ya hay copia del servidor.
    #[test]
    fn lista_solo_los_conflictos_del_area() {
        let temp = TempDir::new("conflictos-lista");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // Uno al día, uno pendiente sin chocar, uno en conflicto.
        add_synced(&mut store, &book, "https://x/a/ok.vcf", "Al Día");
        store
            .enqueue_contact_put(&book, &row("https://x/a/pend.vcf", "Pendiente", "p@x.com"))
            .unwrap();
        make_conflict(&mut store, &book, "https://x/a/choca.vcf", "En Conflicto");

        let conflicts = list_conflicts(store.connection(), CONTACTS_AREA).unwrap();
        assert_eq!(conflicts.len(), 1, "sólo el que chocó");
        assert_eq!(conflicts[0].op, "put");
        assert_eq!(conflicts[0].summary, "En Conflicto");
        assert!(!conflicts[0].has_server_copy, "todavía no se trajo");

        // Nada se cruza al calendario, y sin conflictos la lista es vacía.
        assert!(list_conflicts(store.connection(), CALENDAR_AREA)
            .unwrap()
            .is_empty());
    }

    /// `get_conflict` del objeto en conflicto trae el crudo local y, si A3 ya la
    /// trajo, la copia del servidor con su ETag.
    #[test]
    fn el_detalle_trae_local_y_servidor() {
        let temp = TempDir::new("conflictos-detalle");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        make_conflict(&mut store, &book, "https://x/a/c.vcf", "Mía");
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store
            .store_server_copy(op.id, op.revision, Some("\"srv\""), b"BEGIN:VCARD servidor")
            .unwrap();

        let id = conflicts_first_id(&store);
        let detail = get_conflict(store.connection(), CONTACTS_AREA, id)
            .unwrap()
            .unwrap();
        assert_eq!(detail.op, "put");
        assert!(detail.local.unwrap().contains("Mía"), "el crudo local");
        assert_eq!(detail.server.as_deref(), Some("BEGIN:VCARD servidor"));
        assert_eq!(detail.server_etag.as_deref(), Some("\"srv\""));
        assert!(!detail.server_unavailable);
    }

    /// Sin copia del servidor todavía (A3 no la trajo), `get_conflict` **no
    /// falla**: devuelve el conflicto con `server_unavailable = true`.
    #[test]
    fn el_detalle_sin_copia_del_servidor_no_falla() {
        let temp = TempDir::new("conflictos-sin-copia");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        make_conflict(&mut store, &book, "https://x/a/c.vcf", "Mía");

        let id = conflicts_first_id(&store);
        let detail = get_conflict(store.connection(), CONTACTS_AREA, id)
            .unwrap()
            .unwrap();
        assert!(detail.server.is_none());
        assert!(detail.server_etag.is_none());
        assert!(
            detail.server_unavailable,
            "copia del servidor no disponible"
        );
        assert!(detail.local.is_some());
    }

    /// Un id que no está en conflicto —uno al día— da `None`.
    #[test]
    fn el_detalle_de_un_id_al_dia_es_none() {
        let temp = TempDir::new("conflictos-none");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        add_synced(&mut store, &book, "https://x/a/ok.vcf", "Al Día");
        let id = store
            .contact_id_by_href(book.id, "https://x/a/ok.vcf")
            .unwrap()
            .unwrap();
        assert!(get_conflict(store.connection(), CONTACTS_AREA, id)
            .unwrap()
            .is_none());
    }

    /// Un **borrado** local en conflicto no trae crudo local («la mía» es
    /// borrarlo): `op = 'delete'` y `local` ausente.
    #[test]
    fn un_borrado_en_conflicto_no_trae_local() {
        let temp = TempDir::new("conflictos-borrado");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        add_synced(&mut store, &book, "https://x/a/c.vcf", "Borrada");
        store
            .enqueue_delete(CONTACTS_AREA, BOOK, "https://x/a/c.vcf", Some("\"1\""))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();

        let id = conflicts_first_id(&store);
        let detail = get_conflict(store.connection(), CONTACTS_AREA, id)
            .unwrap()
            .unwrap();
        assert_eq!(detail.op, "delete");
        assert!(detail.local.is_none(), "un borrado no tiene versión local");
    }

    /// Un área sin cola de escritura (correo) es un argumento inválido.
    #[test]
    fn un_area_sin_cola_es_invalida() {
        let temp = TempDir::new("conflictos-area-mala");
        let store = open_store(&temp);
        assert!(matches!(
            list_conflicts(store.connection(), "email"),
            Err(StoreError::InvalidArgument(_))
        ));
        assert!(matches!(
            get_conflict(store.connection(), "email", 1),
            Err(StoreError::InvalidArgument(_))
        ));
    }

    fn conflicts_first_id(store: &Store) -> i64 {
        list_conflicts(store.connection(), CONTACTS_AREA).unwrap()[0]
            .id
            .parse()
            .unwrap()
    }
}
