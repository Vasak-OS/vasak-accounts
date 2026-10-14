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
    /// Testigo de versión: sube cada vez que una edición nueva reemplaza la op.
    /// El cierre de una op es condicional a este número (ver [`Store::complete_put`]).
    pub revision: i64,
    /// El ETag de la versión del servidor del recurso en conflicto, si ya se
    /// trajo. `None` mientras no se haya traído (el caso normal fuera de un
    /// conflicto, y el de un conflicto cuya copia todavía no entró).
    pub server_etag: Option<String>,
    /// El crudo de la versión del servidor del recurso en conflicto —el iCal o la
    /// vCard—, si ya se trajo. `None` mientras no se haya traído. Es dato privado:
    /// vive cifrado como el resto de la fila, y no se escribe en el diario.
    pub server_raw: Option<Vec<u8>>,
}

/// El nombre estático del área, para subir su generación.
fn area_static(area: &str) -> Option<&'static str> {
    match area {
        CALENDAR_AREA => Some(CALENDAR_AREA),
        CONTACTS_AREA => Some(CONTACTS_AREA),
        _ => None,
    }
}

/// Las tablas de un área, para escribir la fila guardada con su alcance de
/// colección: `(tabla de objetos, tabla de colecciones, columna de colección)`.
///
/// El alcance importa: el esquema deja el mismo `href` en dos colecciones
/// (`UNIQUE (calendar_id, href)` / `UNIQUE (address_book_id, href)`), así que
/// tocar «el objeto con este href» sin decir **de qué colección** podría borrar
/// o pisar el de otra. La op guarda su `collection_href`; de ahí sale el `id`.
fn area_tables(area: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match area {
        CALENDAR_AREA => Some(("calendar_objects", "calendars", "calendar_id")),
        CONTACTS_AREA => Some(("contacts", "address_books", "address_book_id")),
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
               last_error = NULL, revision = revision + 1",
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
    // Lo encola la superficie D-Bus de escritura (`DeleteEvent`, `DeleteContact`
    // en `store_api.rs`), y lo ejercitan también las pruebas.
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
        let (table, coltable, colcol) =
            area_tables(area).expect("el área tiene tablas si tiene cola");
        let transaction = self.connection.transaction().map_err(classify)?;
        transaction
            .execute(
                &format!(
                    "UPDATE {table} SET pending_op = 'delete'
                      WHERE href = ?1 AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?2)"
                ),
                rusqlite::params![object_href, collection_href],
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
                        attempts, last_error, revision, server_etag, server_raw
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
                    revision: row.get(10)?,
                    server_etag: row.get(11)?,
                    server_raw: row.get(12)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Las colecciones de un área con escrituras **todavía por intentar**
    /// (`state = 'ready'`): una colección así **no se da por al día** en la
    /// bajada, para que el empuje se resuelva primero.
    ///
    /// Las ops en `conflict` **no** cuentan: ya no se reintentan solas (las
    /// resuelve M3), y si siguieran trabando la colección su token no se
    /// guardaría nunca y la cuenta nunca llegaría a `Synced` (disponibilidad).
    /// La guarda de la bajada igual protege la fila local marcada.
    pub fn pending_collections(&self, area: &str) -> Result<Vec<String>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT DISTINCT collection_href FROM pending_dav_ops
                  WHERE area = ?1 AND state = 'ready' ORDER BY 1",
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

    /// Borra la op **sólo si no cambió desde la foto** (mismo `id` y `revision`).
    /// Devuelve si la borró: `false` quiere decir que una edición nueva la
    /// reemplazó entre la foto y ahora, y no hay que tocar nada de la edición
    /// nueva. La base de todos los cierres condicionados.
    fn close_op(
        transaction: &rusqlite::Transaction<'_>,
        op: &PendingOp,
    ) -> Result<bool, StoreError> {
        let affected = transaction
            .execute(
                "DELETE FROM pending_dav_ops WHERE id = ?1 AND revision = ?2",
                rusqlite::params![op.id, op.revision],
            )
            .map_err(classify)?;
        Ok(affected > 0)
    }

    /// Cierra un `put` que salió bien. Con `new_etag`, el del recurso recién
    /// escrito: se guarda en la fila y la próxima bajada no la trae de nuevo.
    /// Sin él (el servidor no devolvió un ETag utilizable), se deja la fila con
    /// el ETag en `NULL` para que la bajada traiga el suyo. En los dos casos se
    /// limpia la marca `pending_op` y se borra la op.
    ///
    /// **Condicional a la revisión de la op** (`op.revision`): si una edición
    /// nueva la reemplazó mientras el empuje hablaba con la red, no se cierra ni
    /// se limpia la marca —se deja viva la edición nueva, que la persona todavía
    /// quiere subir (lost-update)—. **Con alcance de colección**: no toca el
    /// objeto del mismo `href` en otra colección.
    pub fn complete_put(
        &mut self,
        op: &PendingOp,
        new_etag: Option<&str>,
    ) -> Result<(), StoreError> {
        let (table, coltable, colcol) = area_tables(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let transaction = self.connection.transaction().map_err(classify)?;
        if !Self::close_op(&transaction, op)? {
            return Ok(());
        }
        transaction
            .execute(
                &format!(
                    "UPDATE {table} SET etag = ?1, pending_op = NULL
                      WHERE href = ?2 AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?3)"
                ),
                rusqlite::params![new_etag, op.object_href, op.collection_href],
            )
            .map_err(classify)?;
        transaction.commit().map_err(classify)
    }

    /// Cierra un `delete` que salió bien (o un `404`, idempotente): borra la
    /// fila guardada —con sus derivados, por la cascada— y la op. Sube la
    /// generación: el objeto ya no está de verdad.
    ///
    /// **Condicional a la revisión** y **con alcance de colección**, como
    /// [`Self::complete_put`]: una edición nueva que reemplazó la op se conserva,
    /// y no se borra el objeto del mismo `href` en otra colección.
    pub fn complete_delete(&mut self, op: &PendingOp) -> Result<(), StoreError> {
        let (table, coltable, colcol) = area_tables(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let area_static = area_static(&op.area).expect("área con cola");
        let transaction = self.connection.transaction().map_err(classify)?;
        if !Self::close_op(&transaction, op)? {
            return Ok(());
        }
        transaction
            .execute(
                &format!(
                    "DELETE FROM {table}
                      WHERE href = ?1 AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?2)"
                ),
                rusqlite::params![op.object_href, op.collection_href],
            )
            .map_err(classify)?;
        let generation = bump_generation(&transaction, area_static)?;
        transaction.commit().map_err(classify)?;
        self.note_change(area_static, generation);
        Ok(())
    }

    /// Deja una op en conflicto: un `412` (el recurso cambió en el servidor desde
    /// `base_etag`), o un error permanente que no tiene sentido reintimar (ver
    /// `replay`). **No se pisa nada**: la fila guardada sigue marcada y la op
    /// queda en `conflict`, con `last_error` y un reintento más contado, para que
    /// M3 la resuelva. Sube la generación para que la señal `Changed` avise.
    ///
    /// Condicional a la revisión: si una edición nueva reemplazó la op, no se la
    /// marca en conflicto —la nueva arranca limpia en `ready`—.
    pub fn mark_conflict(&mut self, op: &PendingOp, detail: &str) -> Result<(), StoreError> {
        let area_static = area_static(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let transaction = self.connection.transaction().map_err(classify)?;
        let affected = transaction
            .execute(
                "UPDATE pending_dav_ops
                    SET state = 'conflict', attempts = attempts + 1, last_error = ?3
                  WHERE id = ?1 AND revision = ?2",
                rusqlite::params![op.id, op.revision, detail],
            )
            .map_err(classify)?;
        if affected == 0 {
            return Ok(());
        }
        let generation = bump_generation(&transaction, area_static)?;
        transaction.commit().map_err(classify)?;
        self.note_change(area_static, generation);
        Ok(())
    }

    /// Guarda la copia del servidor —su ETag y su crudo— de un recurso en
    /// conflicto, en las columnas cifradas `server_etag`/`server_raw` de la op.
    /// Devuelve si la guardó.
    ///
    /// **Condicional al `id`, la `revision` y el estado `conflict`**, por las
    /// mismas razones que [`Self::complete_put`]: el empuje saca la op, suelta el
    /// almacén para traer la copia por la red, y recién con ella vuelve a tomar el
    /// almacén para guardarla. Si en el medio una edición nueva reemplazó la op
    /// (revisión nueva, y de paso vuelta a `ready`), la foto traída es de una op
    /// que ya no existe: no se guarda, para no resucitar una copia vieja sobre la
    /// edición de la persona (lost-update) ni pisar una op que ya no está en
    /// conflicto (idempotencia). `false` quiere decir exactamente eso: la op
    /// cambió o se fue entre la foto y ahora, y no hay que tocar nada.
    ///
    /// No sube la generación: el conflicto ya avisó al marcarse
    /// ([`Self::mark_conflict`]); esto sólo le suma el detalle que M3 mostrará.
    pub fn store_server_copy(
        &mut self,
        id: i64,
        revision: i64,
        server_etag: Option<&str>,
        server_raw: &[u8],
    ) -> Result<bool, StoreError> {
        let affected = self
            .connection
            .execute(
                "UPDATE pending_dav_ops
                    SET server_etag = ?3, server_raw = ?4
                  WHERE id = ?1 AND revision = ?2 AND state = 'conflict'",
                rusqlite::params![id, revision, server_etag, server_raw],
            )
            .map_err(classify)?;
        Ok(affected > 0)
    }

    /// Deja una op para reintentar más tarde (red, `423`, `507`): suma un
    /// reintento y guarda el detalle, sin tocar la fila guardada ni la
    /// generación. La op sigue en `ready`.
    ///
    /// Condicional a la revisión: si una edición nueva reemplazó la op, no se le
    /// suma el reintento de la vieja (la nueva arranca en cero).
    pub fn retry_later(&mut self, op: &PendingOp, detail: &str) -> Result<(), StoreError> {
        self.connection
            .execute(
                "UPDATE pending_dav_ops
                    SET attempts = attempts + 1, last_error = ?3
                  WHERE id = ?1 AND revision = ?2",
                rusqlite::params![op.id, op.revision, detail],
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
    use rusqlite::OptionalExtension;

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

    /// La copia del servidor guardada en la op de un objeto: su ETag y su crudo.
    fn server_copy_of(store: &Store, href: &str) -> (Option<String>, Option<Vec<u8>>) {
        store
            .connection()
            .query_row(
                "SELECT server_etag, server_raw FROM pending_dav_ops WHERE object_href = ?1",
                [href],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
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

    /// Guardar la copia del servidor de un conflicto escribe su ETag y su crudo
    /// en la op, y los deja leer de vuelta.
    #[test]
    fn guardar_la_copia_del_servidor_de_un_conflicto() {
        let temp = TempDir::new("cola-copia-servidor");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        // Antes de traerla, no hay copia.
        assert_eq!(server_copy_of(&store, HREF), (None, None));

        let saved = store
            .store_server_copy(op.id, op.revision, Some("\"srv\""), b"BEGIN:VCARD servidor")
            .unwrap();
        assert!(saved, "se guardó");

        assert_eq!(
            server_copy_of(&store, HREF),
            (
                Some("\"srv\"".to_string()),
                Some(b"BEGIN:VCARD servidor".to_vec())
            )
        );
        // La vuelve a leer `pending_ops`.
        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.server_etag.as_deref(), Some("\"srv\""));
        assert_eq!(
            after.server_raw.as_deref(),
            Some(&b"BEGIN:VCARD servidor"[..])
        );
    }

    /// **Lost-update / idempotencia**: guardar la copia del servidor con la **foto
    /// vieja** después de que una edición nueva reemplazó la op (revisión nueva, y
    /// de vuelta a `ready`) **no toca nada**. La foto es de una op que ya no está
    /// en conflicto; guardarla resucitaría una versión vieja sobre la edición de
    /// la persona.
    #[test]
    fn guardar_una_copia_con_foto_vieja_no_pisa_la_edicion_nueva() {
        let temp = TempDir::new("cola-copia-stale");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let snapshot = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&snapshot, "chocó").unwrap();
        let snapshot = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        // Entre la foto y el guardado, la persona vuelve a editar: la op se
        // reemplaza (revisión nueva, estado `ready`).
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana María", "nuevo@x.com"))
            .unwrap();

        let saved = store
            .store_server_copy(snapshot.id, snapshot.revision, Some("\"srv\""), b"ajeno")
            .unwrap();
        assert!(!saved, "la foto vieja no guarda nada");
        // La edición nueva sigue limpia, sin copia del servidor encima.
        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Ready);
        assert_eq!(after.server_etag, None);
        assert_eq!(after.server_raw, None);
    }

    /// Guardar la copia del servidor sobre una op que **ya no está en conflicto**
    /// (volvió a `ready` con la misma revisión, caso teórico) tampoco escribe: la
    /// condición pide `state = 'conflict'`.
    #[test]
    fn guardar_una_copia_pide_estado_conflicto() {
        let temp = TempDir::new("cola-copia-ready");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        // La op está en `ready`, no en conflicto.
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        let saved = store
            .store_server_copy(op.id, op.revision, Some("\"srv\""), b"ajeno")
            .unwrap();
        assert!(!saved, "una op en `ready` no recibe copia del servidor");
        assert_eq!(server_copy_of(&store, HREF), (None, None));
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
        assert!(ops[0].revision > first.revision, "la revisión subió");
    }

    /// **H1**: cerrar una op con la **foto vieja** después de que una edición
    /// nueva la reemplazó durante la ventana de red **no pisa la edición nueva**.
    /// El empuje saca la foto, suelta el almacén, habla con la red y vuelve a
    /// cerrar; si en el medio la persona volvió a editar, el cierre con la foto
    /// vieja no debe borrar la op nueva ni limpiar su marca (lost-update).
    #[test]
    fn cerrar_con_una_foto_vieja_no_pisa_la_edicion_nueva() {
        let temp = TempDir::new("cola-lost-update");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // Foto de la op A (lo que el empuje llevaría a la red).
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana", "a@x.com"))
            .unwrap();
        let snapshot = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        // Entre la foto y el cierre, la persona vuelve a editar el mismo recurso.
        let edited = row(HREF, "Ana María", "nuevo@x.com");
        store.enqueue_contact_put(&book, &edited).unwrap();

        // El empuje cierra la op con la foto vieja: NO tiene que tocar la nueva.
        store.complete_put(&snapshot, Some("\"v2\"")).unwrap();

        // La edición nueva sobrevive: la op sigue (una), y la fila sigue marcada
        // 'put' con el crudo nuevo.
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 1);
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
        assert_eq!(raw_of(&store, HREF), Some(edited.raw_vcard));
    }

    /// **H3**: cerrar una op (borrado o put) **sólo toca su colección**. El
    /// esquema deja el mismo `href` en dos libretas; borrar en una no puede
    /// borrar la fila de la otra.
    #[test]
    fn cerrar_una_op_no_cruza_de_coleccion() {
        const BOOK2: &str = "https://x/b/";
        let temp = TempDir::new("cola-scope");
        let mut store = open_store(&temp);
        let books = store
            .upsert_address_books(&[(BOOK.into(), "A".into()), (BOOK2.into(), "B".into())])
            .unwrap();
        let (book1, book2) = (books[0].clone(), books[1].clone());
        // El MISMO href en las dos libretas.
        for book in [&book1, &book2] {
            store
                .apply_contacts(
                    book,
                    &[ContactOp::Upsert(row(HREF, "Ana", "a@x.com"))],
                    None,
                    u64::MAX,
                )
                .unwrap();
        }

        // Encolar el borrado en la libreta 1: sólo su fila queda marcada.
        store
            .enqueue_delete(CONTACTS_AREA, BOOK, HREF, Some("\"1\""))
            .unwrap();
        let mark_book2: Option<String> = store
            .connection()
            .query_row(
                "SELECT pending_op FROM contacts
                  WHERE href = ?1 AND address_book_id = ?2",
                rusqlite::params![HREF, book2.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(mark_book2, None, "la libreta 2 no se marca");

        // Cerrar el borrado: se va la fila de la libreta 1, NO la de la 2.
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.complete_delete(&op).unwrap();

        let present = |store: &Store, book_id: i64| -> bool {
            store
                .connection()
                .query_row(
                    "SELECT 1 FROM contacts WHERE href = ?1 AND address_book_id = ?2",
                    rusqlite::params![HREF, book_id],
                    |_| Ok(()),
                )
                .optional()
                .unwrap()
                .is_some()
        };
        assert!(!present(&store, book1.id), "la fila de la libreta 1 se fue");
        assert!(present(&store, book2.id), "la de la libreta 2 se conserva");
    }
}
