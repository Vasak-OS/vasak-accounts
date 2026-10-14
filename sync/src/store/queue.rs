//! La cola de escrituras hacia el servidor, en la base cifrada.
//!
//! Hasta la v4 el almacén traía y nunca mandaba. La escritura conservadora
//! (decisión 3 del taller, `vasak-accounts#23`) agrega el camino de vuelta, y lo
//! hace **optimista y sin perder nada**:
//!
//! 1. **Encolar** ([`Store::enqueue_calendar_put`], `enqueue_contact_put`,
//!    [`Store::enqueue_delete`]) escribe el cambio en la base **ya mismo** —el
//!    crudo nuevo de un `put`, o la marca de borrado de un `delete`—, lo marca
//!    con `pending_op` y suma una fila a `pending_dav_ops` con el cuerpo y el
//!    `base_etag` (el ETag con el que se vio el recurso por última vez; nulo al
//!    crear algo nuevo). La persona ve su cambio sin esperar a la red, y la
//!    generación del área sube: la señal `Changed` sale sola.
//!
//! 2. **Empujar** (la etapa de replay en `replay.rs`) drena la cola contra el
//!    servidor y, según el resultado, cierra la op ([`Store::complete_put`],
//!    [`Store::complete_delete`]), la deja en conflicto ([`Store::mark_conflict`])
//!    o la deja para reintentar ([`Store::retry_later`]).
//!
//! Entre el paso 1 y el 2 puede correr una bajada: por eso la bajada **no pisa
//! ni borra** una fila marcada con `pending_op` (ver `apply_calendar_objects` y
//! `apply_contacts`). Si el `put` falla, la caché no queda como `local ==
//! servidor`: la marca sigue puesta y la op viva hasta confirmar.
//!
//! La cola vive **dentro de la base cifrada** porque guarda cuerpos privados
//! (un evento, una tarjeta). Vaciar o apagar la cuenta borra el archivo entero
//! y, con él, la cola: una op con datos privados no sobrevive a `ClearStore` ni
//! a `SetStoreEnabled(false)`.

use rusqlite::OptionalExtension;

use super::lifecycle::{CALENDAR_AREA, CONTACTS_AREA};
use super::{bump_generation, classify, Store, StoreError};

/// Qué hace una op pendiente con el recurso del servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// Crear o reemplazar: el cuerpo va en `payload`.
    Put,
    /// Borrar.
    Delete,
}

impl PendingKind {
    fn as_str(self) -> &'static str {
        match self {
            PendingKind::Put => "put",
            PendingKind::Delete => "delete",
        }
    }

    fn from_str(text: &str) -> Option<Self> {
        match text {
            "put" => Some(PendingKind::Put),
            "delete" => Some(PendingKind::Delete),
            _ => None,
        }
    }
}

/// En qué estado está una op pendiente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingState {
    /// Se puede (re)intentar.
    Ready,
    /// El servidor la rechazó con un `412`: el recurso cambió desde
    /// `base_etag`. No se pisa nada; lo resuelve M3 de cara a la persona.
    Conflict,
}

impl PendingState {
    fn from_str(text: &str) -> Option<Self> {
        match text {
            "ready" => Some(PendingState::Ready),
            "conflict" => Some(PendingState::Conflict),
            _ => None,
        }
    }
}

/// Una escritura pendiente, tal como está en la base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOp {
    pub id: i64,
    pub area: String,
    pub collection_href: String,
    pub object_href: String,
    pub kind: PendingKind,
    /// El ETag con el que se vio el recurso por última vez. `None` al crear.
    pub base_etag: Option<String>,
    /// El cuerpo a mandar en un `put`. `None` en un `delete`.
    pub payload: Option<Vec<u8>>,
    pub state: PendingState,
    pub attempts: i64,
    pub last_error: Option<String>,
}

/// El nombre estático del área, para subir su generación.
fn area_static(area: &str) -> Option<&'static str> {
    match area {
        CALENDAR_AREA => Some(CALENDAR_AREA),
        CONTACTS_AREA => Some(CONTACTS_AREA),
        _ => None,
    }
}

/// La tabla de objetos de un área: la que lleva el crudo y la marca `pending_op`.
fn object_table(area: &str) -> Option<&'static str> {
    match area {
        CALENDAR_AREA => Some("calendar_objects"),
        CONTACTS_AREA => Some("contacts"),
        _ => None,
    }
}

fn now_text() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Suma una fila a `pending_dav_ops`, reemplazando la que hubiera del mismo
/// objeto: una edición nueva pisa a la anterior sin confirmar (misma `UNIQUE`),
/// y arranca de cero los reintentos y el estado.
fn insert_pending_op(
    transaction: &rusqlite::Transaction<'_>,
    area: &str,
    collection_href: &str,
    object_href: &str,
    kind: PendingKind,
    base_etag: Option<&str>,
    payload: Option<&[u8]>,
) -> Result<(), StoreError> {
    transaction
        .execute(
            "INSERT INTO pending_dav_ops
               (area, collection_href, object_href, op, base_etag, payload, state, created_at,
                attempts, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'ready', ?7, 0, NULL)
             ON CONFLICT (area, object_href) DO UPDATE SET
               collection_href = excluded.collection_href, op = excluded.op,
               base_etag = excluded.base_etag, payload = excluded.payload,
               state = 'ready', created_at = excluded.created_at, attempts = 0,
               last_error = NULL",
            rusqlite::params![
                area,
                collection_href,
                object_href,
                kind.as_str(),
                base_etag,
                payload,
                now_text()
            ],
        )
        .map(|_| ())
        .map_err(classify)
}

impl Store {
    /// Encola un borrado: marca la fila guardada con `pending_op = 'delete'` —se
    /// queda hasta confirmar, para que la bajada no la vuelva a traer— y suma la
    /// op. Si no había fila guardada, igual encola el borrado (el recurso existe
    /// en el servidor aunque no esté en la caché).
    // Lo que encola es la superficie D-Bus del PR siguiente de este hito
    // (`vasak-accounts#23`); por ahora lo ejercitan las pruebas.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn enqueue_delete(
        &mut self,
        area: &str,
        collection_href: &str,
        object_href: &str,
        base_etag: Option<&str>,
    ) -> Result<(), StoreError> {
        let Some(area_static) = area_static(area) else {
            return Err(StoreError::InvalidArgument(format!(
                "«{area}» no es un área con cola de escritura"
            )));
        };
        let table = object_table(area).expect("el área tiene tabla si tiene cola");
        let transaction = self.connection.transaction().map_err(classify)?;
        transaction
            .execute(
                &format!("UPDATE {table} SET pending_op = 'delete' WHERE href = ?1"),
                [object_href],
            )
            .map_err(classify)?;
        insert_pending_op(
            &transaction,
            area,
            collection_href,
            object_href,
            PendingKind::Delete,
            base_etag,
            None,
        )?;
        let generation = bump_generation(&transaction, area_static)?;
        transaction.commit().map_err(classify)?;
        self.note_change(area_static, generation);
        Ok(())
    }

    /// Las ops pendientes de un área, en el orden en que se encolaron.
    pub fn pending_ops(&self, area: &str) -> Result<Vec<PendingOp>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, area, collection_href, object_href, op, base_etag, payload, state,
                        attempts, last_error
                   FROM pending_dav_ops
                  WHERE area = ?1
                  ORDER BY id",
            )
            .map_err(classify)?;
        let rows = statement
            .query_map([area], |row| {
                let op: String = row.get(4)?;
                let state: String = row.get(7)?;
                Ok(PendingOp {
                    id: row.get(0)?,
                    area: row.get(1)?,
                    collection_href: row.get(2)?,
                    object_href: row.get(3)?,
                    kind: PendingKind::from_str(&op).unwrap_or(PendingKind::Put),
                    base_etag: row.get(5)?,
                    payload: row.get(6)?,
                    state: PendingState::from_str(&state).unwrap_or(PendingState::Ready),
                    attempts: row.get(8)?,
                    last_error: row.get(9)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Las colecciones de un área que todavía tienen algo sin confirmar: una
    /// colección con ops pendientes **no se da por al día** en la bajada, para
    /// que el empuje se resuelva primero.
    pub fn pending_collections(&self, area: &str) -> Result<Vec<String>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT DISTINCT collection_href FROM pending_dav_ops WHERE area = ?1 ORDER BY 1",
            )
            .map_err(classify)?;
        let rows = statement
            .query_map([area], |row| row.get(0))
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Cuántas ops pendientes tiene un área, en cualquier estado.
    pub fn pending_count(&self, area: &str) -> Result<i64, StoreError> {
        self.connection
            .query_row(
                "SELECT count(*) FROM pending_dav_ops WHERE area = ?1",
                [area],
                |row| row.get(0),
            )
            .map_err(classify)
    }

    /// Cierra un `put` que salió bien. Con `new_etag`, el del recurso recién
    /// escrito: se guarda en la fila y la próxima bajada no la trae de nuevo.
    /// Sin él (el servidor no devolvió un ETag utilizable), se deja la fila con
    /// el ETag en `NULL` para que la bajada traiga el suyo. En los dos casos se
    /// limpia la marca `pending_op` y se borra la op.
    pub fn complete_put(
        &mut self,
        op: &PendingOp,
        new_etag: Option<&str>,
    ) -> Result<(), StoreError> {
        let table = object_table(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let transaction = self.connection.transaction().map_err(classify)?;
        transaction
            .execute(
                &format!("UPDATE {table} SET etag = ?1, pending_op = NULL WHERE href = ?2"),
                rusqlite::params![new_etag, op.object_href],
            )
            .map_err(classify)?;
        transaction
            .execute("DELETE FROM pending_dav_ops WHERE id = ?1", [op.id])
            .map_err(classify)?;
        transaction.commit().map_err(classify)
    }

    /// Cierra un `delete` que salió bien (o un `404`, idempotente): borra la
    /// fila guardada —con sus derivados, por la cascada— y la op. Sube la
    /// generación: el objeto ya no está de verdad.
    pub fn complete_delete(&mut self, op: &PendingOp) -> Result<(), StoreError> {
        let table = object_table(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let area_static = area_static(&op.area).expect("área con cola");
        let transaction = self.connection.transaction().map_err(classify)?;
        transaction
            .execute(
                &format!("DELETE FROM {table} WHERE href = ?1"),
                [&op.object_href],
            )
            .map_err(classify)?;
        transaction
            .execute("DELETE FROM pending_dav_ops WHERE id = ?1", [op.id])
            .map_err(classify)?;
        let generation = bump_generation(&transaction, area_static)?;
        transaction.commit().map_err(classify)?;
        self.note_change(area_static, generation);
        Ok(())
    }

    /// Deja una op en conflicto (`412`): el recurso cambió en el servidor desde
    /// `base_etag`. **No se pisa nada**: la fila guardada sigue marcada y la op
    /// queda en `conflict`, con `last_error` y un reintento más contado. Sube la
    /// generación para que la señal `Changed` avise, y M3 lo resuelva.
    pub fn mark_conflict(&mut self, op: &PendingOp, detail: &str) -> Result<(), StoreError> {
        let area_static = area_static(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let transaction = self.connection.transaction().map_err(classify)?;
        transaction
            .execute(
                "UPDATE pending_dav_ops
                    SET state = 'conflict', attempts = attempts + 1, last_error = ?2
                  WHERE id = ?1",
                rusqlite::params![op.id, detail],
            )
            .map_err(classify)?;
        let generation = bump_generation(&transaction, area_static)?;
        transaction.commit().map_err(classify)?;
        self.note_change(area_static, generation);
        Ok(())
    }

    /// Deja una op para reintentar más tarde (red, `423`, `507`): suma un
    /// reintento y guarda el detalle, sin tocar la fila guardada ni la
    /// generación. La op sigue en `ready`.
    pub fn retry_later(&mut self, op: &PendingOp, detail: &str) -> Result<(), StoreError> {
        self.connection
            .execute(
                "UPDATE pending_dav_ops
                    SET attempts = attempts + 1, last_error = ?2
                  WHERE id = ?1",
                rusqlite::params![op.id, detail],
            )
            .map(|_| ())
            .map_err(classify)
    }
}

/// Lo que comparten las dos áreas al encolar un `put`: inserta la op con el
/// cuerpo crudo. La escritura optimista de la fila la hace cada área (necesita
/// derivar lo suyo), en la misma transacción.
pub(super) fn enqueue_put_op(
    transaction: &rusqlite::Transaction<'_>,
    area: &str,
    collection_href: &str,
    object_href: &str,
    base_etag: Option<&str>,
    payload: &[u8],
) -> Result<(), StoreError> {
    insert_pending_op(
        transaction,
        area,
        collection_href,
        object_href,
        PendingKind::Put,
        base_etag,
        Some(payload),
    )
}

/// Si una fila guardada de un área tiene una marca `pending_op` puesta: la
/// bajada la respeta. `None` es lo normal —al día con el servidor—.
pub(super) fn pending_mark(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    collection_column: &str,
    collection_id: i64,
    href: &str,
) -> Result<Option<String>, StoreError> {
    transaction
        .query_row(
            &format!("SELECT pending_op FROM {table} WHERE {collection_column} = ?1 AND href = ?2"),
            rusqlite::params![collection_id, href],
            |row| row.get(0),
        )
        .optional()
        .map(Option::flatten)
        .map_err(classify)
}

#[cfg(test)]
mod tests {
    use super::super::contacts::tests::{open_store, row};
    use super::super::contacts::ContactOp;
    use super::super::paths::tests::TempDir;
    use super::*;

    const BOOK: &str = "https://x/a/";
    const HREF: &str = "https://x/a/ana.vcf";

    fn one_book(store: &mut Store) -> super::super::contacts::StoredAddressBook {
        store
            .upsert_address_books(&[(BOOK.into(), "A".into())])
            .unwrap()
            .remove(0)
    }

    fn pending_op_of(store: &Store, href: &str) -> Option<String> {
        store
            .connection()
            .query_row(
                "SELECT pending_op FROM contacts WHERE href = ?1",
                [href],
                |r| r.get::<_, Option<String>>(0),
            )
            .unwrap()
    }

    fn raw_of(store: &Store, href: &str) -> Option<String> {
        store
            .connection()
            .query_row(
                "SELECT raw_vcard FROM contacts WHERE href = ?1",
                [href],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    /// Encolar un `put` escribe el crudo **ya mismo**, lo marca con
    /// `pending_op = 'put'` y suma la op con su cuerpo. La persona lo ve sin
    /// esperar a la red.
    #[test]
    fn encolar_un_put_escribe_optimista_y_suma_la_op() {
        let temp = TempDir::new("cola-put");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        let card = row(HREF, "Ana", "a@x.com");

        store.enqueue_contact_put(&book, &card).unwrap();

        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
        assert_eq!(raw_of(&store, HREF), Some(card.raw_vcard.clone()));
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 1);
        let ops = store.pending_ops(CONTACTS_AREA).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, PendingKind::Put);
        assert_eq!(ops[0].payload.as_deref(), Some(card.raw_vcard.as_bytes()));
        assert_eq!(
            store.pending_collections(CONTACTS_AREA).unwrap(),
            vec![BOOK]
        );
    }

    /// **La bajada no pisa una fila marcada**: un `Upsert` del servidor sobre un
    /// cambio local sin confirmar se saltea, y el crudo local queda.
    #[test]
    fn la_bajada_no_pisa_un_cambio_local_sin_confirmar() {
        let temp = TempDir::new("cola-guarda-upsert");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        let local = row(HREF, "Mía", "yo@x.com");
        store.enqueue_contact_put(&book, &local).unwrap();

        // El servidor manda otra versión del mismo recurso.
        let server = row(HREF, "Del servidor", "srv@x.com");
        store
            .apply_contacts(&book, &[ContactOp::Upsert(server)], None, u64::MAX)
            .unwrap();

        // No se pisó: sigue el crudo local y la marca.
        assert_eq!(raw_of(&store, HREF), Some(local.raw_vcard));
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
    }

    /// **La bajada no borra una creación local sin confirmar**: un `Delete` del
    /// servidor sobre una fila marcada `'put'` se saltea (el servidor nunca la
    /// tuvo).
    #[test]
    fn la_bajada_no_borra_una_creacion_local_sin_confirmar() {
        let temp = TempDir::new("cola-guarda-delete");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana", "a@x.com"))
            .unwrap();

        store
            .apply_contacts(&book, &[ContactOp::Delete(HREF.into())], None, u64::MAX)
            .unwrap();

        assert!(raw_of(&store, HREF).is_some(), "la fila local sigue");
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
    }

    /// Cerrar un `put` con éxito limpia la marca, guarda el ETag del servidor y
    /// borra la op.
    #[test]
    fn cerrar_un_put_limpia_la_marca_y_guarda_el_etag() {
        let temp = TempDir::new("cola-cierra-put");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana", "a@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        store.complete_put(&op, Some("\"v2\"")).unwrap();

        assert_eq!(pending_op_of(&store, HREF), None);
        let etag: Option<String> = store
            .connection()
            .query_row("SELECT etag FROM contacts WHERE href = ?1", [HREF], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(etag.as_deref(), Some("\"v2\""));
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 0);
    }

    /// Un `put` sin ETag de respuesta deja el ETag local en `NULL` para refetch,
    /// pero cierra la op igual.
    #[test]
    fn cerrar_un_put_sin_etag_pide_refetch() {
        let temp = TempDir::new("cola-refetch");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana", "a@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        store.complete_put(&op, None).unwrap();

        let etag: Option<String> = store
            .connection()
            .query_row("SELECT etag FROM contacts WHERE href = ?1", [HREF], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(etag, None);
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 0);
    }

    /// Un conflicto (`412`) **no pisa lo local**: la op queda en `conflict`, con
    /// un reintento contado, y el crudo local sigue.
    #[test]
    fn un_conflicto_conserva_lo_local_y_deja_la_op_en_conflicto() {
        let temp = TempDir::new("cola-conflicto");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        let local = row(HREF, "Mía", "yo@x.com");
        store.enqueue_contact_put(&book, &local).unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        store.mark_conflict(&op, "cambió en el servidor").unwrap();

        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Conflict);
        assert_eq!(after.attempts, 1);
        assert_eq!(raw_of(&store, HREF), Some(local.raw_vcard));
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
    }

    /// Encolar un borrado marca la fila `'delete'` —se queda— y suma la op;
    /// cerrarlo borra la fila y la op.
    #[test]
    fn encolar_y_cerrar_un_borrado() {
        let temp = TempDir::new("cola-borra");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // Una fila al día, que después se borra.
        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(HREF, "Ana", "a@x.com"))],
                None,
                u64::MAX,
            )
            .unwrap();

        store
            .enqueue_delete(CONTACTS_AREA, BOOK, HREF, Some("\"1\""))
            .unwrap();
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("delete"));
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(op.kind, PendingKind::Delete);

        store.complete_delete(&op).unwrap();
        assert_eq!(raw_of(&store, HREF), None);
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 0);
    }

    /// Una edición nueva sobre un objeto con op pendiente **reemplaza** la op
    /// anterior: una sola por objeto, y arranca de cero los reintentos.
    #[test]
    fn una_edicion_nueva_reemplaza_la_op_pendiente() {
        let temp = TempDir::new("cola-reemplaza");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana", "a@x.com"))
            .unwrap();
        let first = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&first, "chocó").unwrap();

        // Edición nueva del mismo recurso: pisa la op, vuelve a 'ready'.
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana María", "a@x.com"))
            .unwrap();
        let ops = store.pending_ops(CONTACTS_AREA).unwrap();
        assert_eq!(ops.len(), 1, "una sola op por objeto");
        assert_eq!(ops[0].state, PendingState::Ready);
        assert_eq!(ops[0].attempts, 0);
    }
}
