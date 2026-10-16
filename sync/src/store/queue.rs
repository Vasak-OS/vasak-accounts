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

/// Qué decidió la persona sobre un objeto en conflicto, al resolverlo
/// ([`Store::resolve_conflict`]). La superficie D-Bus (`ResolveConflict`) la
/// recibe como texto y la pasa ya validada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictChoice {
    /// La versión de la persona gana: se re-basa la op sobre el ETag actual del
    /// servidor y vuelve a `ready`, para que el empuje re-haga el `PUT`/`DELETE`
    /// con la precondición fresca y pise el servidor.
    KeepLocal,
    /// El servidor gana: su copia se adopta en la fila guardada y la op se
    /// descarta.
    TakeServer,
}

impl ConflictChoice {
    /// La decisión por su nombre en el bus, o `None` si no es ninguna de las dos.
    pub fn from_str(text: &str) -> Option<Self> {
        match text {
            "keep_local" => Some(ConflictChoice::KeepLocal),
            "take_server" => Some(ConflictChoice::TakeServer),
            _ => None,
        }
    }
}

/// El estado de sincronización de un objeto guardado, como lo ve una aplicación
/// que lo lee: para el ícono «sin sincronizar» y para saber si se puede editar.
///
/// Sale de la marca `pending_op` de la fila guardada y, si la hay, del estado de
/// su op en `pending_dav_ops` (ver [`SyncState::derive`]). No es lo mismo que
/// [`PendingState`], que es el estado interno de la op en la cola: `SyncState`
/// agrega el caso `synced` —ninguna op— que la cola no tiene por qué nombrar.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncState {
    /// Al día con el servidor: sin cambio local pendiente.
    #[default]
    Synced,
    /// Hay un cambio local sin confirmar, a la espera de subir (op en `ready`).
    Pending,
    /// El cambio local chocó con el servidor (op en `conflict`): lo resuelve la
    /// superficie de conflicto (`ListConflicts`/`GetConflict`).
    Conflict,
}

impl SyncState {
    /// Deriva el estado de la marca `pending_op` de la fila y del estado
    /// (`state`) de su op en `pending_dav_ops`. Sin marca, `synced`; con marca y
    /// op en `conflict`, `conflict`; con marca en cualquier otro caso, `pending`.
    pub fn derive(pending_op: Option<&str>, op_state: Option<&str>) -> Self {
        match pending_op {
            None => SyncState::Synced,
            Some(_) => match op_state {
                Some("conflict") => SyncState::Conflict,
                _ => SyncState::Pending,
            },
        }
    }
}

/// Una escritura pendiente, tal como está en la base.
///
/// **Sin `Debug` derivado** (como `DavCredential` en `dav::webdav`): `payload` y
/// `server_raw` son cuerpos privados de la persona —el evento o la tarjeta local,
/// y la copia del servidor del recurso en conflicto—, y un `Debug` derivado los
/// escribiría enteros en cualquier registro, `dbg!` de paso o mensaje de pánico
/// que lleve la op adentro. El `Debug` manual los tacha, mostrando sólo su largo.
#[derive(Clone, PartialEq, Eq)]
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

impl std::fmt::Debug for PendingOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Los cuerpos privados —`payload` y `server_raw`— se tachan mostrando sólo
        // su largo; el resto va tal cual.
        let redacted =
            |body: &Option<Vec<u8>>| body.as_ref().map(|b| format!("<{} bytes>", b.len()));
        f.debug_struct("PendingOp")
            .field("id", &self.id)
            .field("area", &self.area)
            .field("collection_href", &self.collection_href)
            .field("object_href", &self.object_href)
            .field("kind", &self.kind)
            .field("base_etag", &self.base_etag)
            .field("payload", &redacted(&self.payload))
            .field("state", &self.state)
            .field("attempts", &self.attempts)
            .field("last_error", &self.last_error)
            .field("revision", &self.revision)
            .field("server_etag", &self.server_etag)
            .field("server_raw", &redacted(&self.server_raw))
            .finish()
    }
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
pub(super) fn area_tables(area: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match area {
        CALENDAR_AREA => Some(("calendar_objects", "calendars", "calendar_id")),
        CONTACTS_AREA => Some(("contacts", "address_books", "address_book_id")),
        _ => None,
    }
}

/// La columna con el crudo guardado de cada área: el iCal de un evento, la vCard
/// de un contacto. Es la que adopta la copia del servidor al resolver un
/// conflicto con `take_server`.
fn raw_column(area: &str) -> Option<&'static str> {
    match area {
        CALENDAR_AREA => Some("raw_ical"),
        CONTACTS_AREA => Some("raw_vcard"),
        _ => None,
    }
}

fn now_text() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Suma una fila a `pending_dav_ops`, reemplazando la que hubiera del mismo
/// objeto: una edición nueva pisa a la anterior sin confirmar (misma `UNIQUE`),
/// y arranca de cero los reintentos y el estado.
///
/// Al re-encolar se **limpia la copia del servidor** (`server_etag`/`server_raw`
/// a `NULL`): era de la revisión anterior y la edición nueva es otro recurso que
/// todavía no chocó. Dejarla heredada rompería el invariante «la copia es de su
/// revisión» —si la edición nueva diera 412 y el fetch inline fallara, la guarda
/// de `replay` la vería no-nula y no volvería a traerla, y M3 mostraría la copia
/// de una revisión vieja como la actual—.
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
               last_error = NULL, revision = revision + 1,
               server_etag = NULL, server_raw = NULL",
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
        self.complete_put_scoped(op, |transaction, table, coltable, colcol| {
            transaction
                .execute(
                    &format!(
                        "UPDATE {table} SET etag = ?1, pending_op = NULL
                      WHERE href = ?2 AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?3)"
                    ),
                    rusqlite::params![new_etag, op.object_href, op.collection_href],
                )
                .map_err(classify)?;
            // Un `put` normal sólo toca `etag`/`pending_op`, no un `href` visible:
            // no sube la generación.
            Ok(None)
        })
    }

    /// El esqueleto común de los cierres de `put` que tocan la fila guardada
    /// ([`Self::complete_put`], [`Self::complete_create`]): resuelve las tablas del
    /// área, abre la transacción, **cierra la op condicional a `id`+`revision`**
    /// (`close_op`: si una edición nueva la reemplazó mientras el empuje hablaba con
    /// la red, no se toca nada —lost-update—), corre `work` —con su alcance de
    /// colección— y confirma. `work` devuelve `Some((área, generación))` cuando el
    /// cierre cambió filas visibles y hay que avisar a los lectores con
    /// [`Self::note_change`] (tras el commit); `None` cuando no (un `put` normal).
    fn complete_put_scoped<F>(&mut self, op: &PendingOp, work: F) -> Result<(), StoreError>
    where
        F: FnOnce(
            &rusqlite::Transaction<'_>,
            &str,
            &str,
            &str,
        ) -> Result<Option<(&'static str, u64)>, StoreError>,
    {
        let (table, coltable, colcol) = area_tables(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        let transaction = self.connection.transaction().map_err(classify)?;
        if !Self::close_op(&transaction, op)? {
            return Ok(());
        }
        let note = work(&transaction, table, coltable, colcol)?;
        transaction.commit().map_err(classify)?;
        if let Some((area_static, generation)) = note {
            self.note_change(area_static, generation);
        }
        Ok(())
    }

    /// Cierra un `put` de **creación por Graph**: como [`Self::complete_put`]
    /// guarda el ETag y limpia la marca `pending_op`, pero además **re-basa el
    /// `href`** de la fila guardada —de la dirección local sintética con la que se
    /// creó (`graph://default/…`) al `id` que asignó el servidor— para que la
    /// próxima bajada haga upsert sobre la misma fila y no la duplique.
    ///
    /// Es propio de Graph: en DAV el cliente elige el `href` del `PUT`, así que la
    /// creación ya nace con su dirección final y `complete_put` alcanza. En Graph
    /// el `id` lo pone el servidor en el `POST`, y recién ahí se conoce.
    ///
    /// **Condicional a la revisión** y **con alcance de colección**, como el resto
    /// de los cierres. Si la bajada de una vuelta anterior ya trajo el objeto bajo
    /// su `id` del servidor (idempotencia del `POST` por `transactionId`), re-basar
    /// el `href` chocaría con esa fila por el `UNIQUE (collection, href)`. **No se
    /// usa `UPDATE OR REPLACE`**: su `DELETE` implícito saltea el trigger
    /// `AFTER DELETE` del FTS cuando `recursive_triggers` está apagado (esta conexión
    /// no lo activa) —dejaría un fantasma en el índice de búsqueda— y la cascada de
    /// derivados. En cambio se borra **explícitamente** la fila distinta en conflicto
    /// (el `DELETE` sí dispara el trigger y la cascada) y recién después se re-basa la
    /// local con un `UPDATE` normal. Como se cambió un `href` visible (y quizá se borró
    /// un duplicado), **sube la generación** y avisa a los lectores.
    pub fn complete_create(
        &mut self,
        op: &PendingOp,
        new_href: &str,
        new_etag: Option<&str>,
    ) -> Result<(), StoreError> {
        let area_static = area_static(&op.area)
            .ok_or_else(|| StoreError::InvalidArgument("área sin cola".into()))?;
        self.complete_put_scoped(op, move |transaction, table, coltable, colcol| {
            // 1) Borrar SÓLO la fila distinta que ya ocupa `new_href` en esta
            //    colección (una bajada anterior la trajo). El `DELETE` explícito
            //    —a diferencia del implícito de `OR REPLACE`— dispara el trigger
            //    `AFTER DELETE` del FTS y la cascada de derivados.
            transaction
                .execute(
                    &format!(
                        "DELETE FROM {table}
                          WHERE href = ?1 AND href <> ?2
                            AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?3)"
                    ),
                    rusqlite::params![new_href, op.object_href, op.collection_href],
                )
                .map_err(classify)?;
            // 2) Re-basar la fila local al `id` del servidor (sin `OR REPLACE`: la
            //    fila en conflicto ya no está).
            transaction
                .execute(
                    &format!(
                        "UPDATE {table} SET href = ?1, etag = ?2, pending_op = NULL
                          WHERE href = ?3 AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?4)"
                    ),
                    rusqlite::params![new_href, new_etag, op.object_href, op.collection_href],
                )
                .map_err(classify)?;
            // 3) Se cambió un `href` visible (y quizá se borró un duplicado): sube la
            //    generación para que los lectores recarguen.
            let generation = bump_generation(transaction, area_static)?;
            Ok(Some((area_static, generation)))
        })
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

    /// Le suma un intento a una op en conflicto a la que **no se le pudo traer la
    /// copia del servidor** (la red falló, no entró en el plazo, o el recurso ya
    /// no está en el servidor). Acota la re-traída con el mismo tope que las
    /// escrituras (`MAX_REPLAY_ATTEMPTS`, en `replay`): un recurso borrado en el
    /// servidor —`multiget` con `Ok(None)` permanente— o una traída que falla
    /// vuelta tras vuelta no pueden re-traerse para siempre consumiendo el plazo de
    /// cada vuelta. Pasado el tope, el empuje deja de intentar la copia y M3
    /// muestra el conflicto con «copia del servidor no disponible».
    ///
    /// **Condicional al `id`, la `revision` y el estado `conflict`**, como
    /// [`Self::store_server_copy`]: una edición nueva que reemplazó la op (vuelta a
    /// `ready`, revisión nueva) no arrastra los intentos de la vieja. No toca la
    /// fila guardada ni la generación.
    pub fn count_conflict_fetch_attempt(
        &mut self,
        id: i64,
        revision: i64,
    ) -> Result<(), StoreError> {
        self.connection
            .execute(
                "UPDATE pending_dav_ops
                    SET attempts = attempts + 1
                  WHERE id = ?1 AND revision = ?2 AND state = 'conflict'",
                rusqlite::params![id, revision],
            )
            .map(|_| ())
            .map_err(classify)
    }

    /// Aplica la decisión de la persona sobre un objeto en conflicto, por su
    /// **id local** (el de `GetConflict`): `keep_local` re-basa el cambio local
    /// para que vuelva a subir, `take_server` adopta la copia del servidor y
    /// descarta el cambio local. Acotada al área pedida —ninguna consulta cruza
    /// de área— y con alcance de colección en la escritura.
    ///
    /// - **`keep_local`**: la versión de la persona gana. Se re-basa la op:
    ///   `base_etag` pasa a ser el `server_etag` (el ETag actual del servidor que
    ///   trajo A3), se limpia la copia del servidor (`server_etag`/`server_raw` a
    ///   `NULL`) y la op vuelve a `ready` con la revisión subida, para que el
    ///   empuje re-haga el `PUT`/`DELETE` con la precondición fresca y pise el
    ///   servidor. **Sin `server_etag`** (la copia todavía no entró) no hay sobre
    ///   qué re-basar: error, no una escritura incondicional.
    /// - **`take_server`**: el servidor gana. Se adopta su copia en la fila
    ///   guardada —su crudo y su ETag—, se limpia la marca `pending_op` y se
    ///   descarta la op. Un `delete` en conflicto que el servidor todavía tiene
    ///   deja el objeto vivo con la versión del servidor (misma escritura).
    ///   **Sin copia del servidor** (`server_raw` nulo) no hay qué adoptar:
    ///   error, sin perder el cambio local.
    ///
    /// Todo cierre va condicionado a `id + revision + state = 'conflict'`, como el
    /// resto de la cola. Es **idempotente**: si la op ya no está en conflicto
    /// —otra resolución, o una edición nueva que la reemplazó— no se toca nada y
    /// se devuelve un error benigno (`InvalidArgument`). Sube la generación para
    /// que la señal `Changed` recargue la ventana.
    pub fn resolve_conflict(
        &mut self,
        area: &str,
        id: i64,
        choice: ConflictChoice,
    ) -> Result<(), StoreError> {
        let area_static = area_static(area).ok_or_else(|| {
            StoreError::InvalidArgument(format!("«{area}» no es un área con cola de escritura"))
        })?;
        let (table, coltable, colcol) =
            area_tables(area).expect("el área tiene tablas si tiene cola");
        let raw_col = raw_column(area).expect("un área con cola tiene columna de crudo");
        let transaction = self.connection.transaction().map_err(classify)?;

        // La op en conflicto de este objeto, con su alcance de colección. Sólo del
        // área pedida: el `JOIN` no cruza de área ni de colección.
        let sql = format!(
            "SELECT p.id, p.revision, p.server_etag, p.server_raw, p.object_href,
                    p.collection_href
               FROM {table} obj
               JOIN {coltable} col ON col.id = obj.{colcol}
               JOIN pending_dav_ops p
                     ON p.area = ?1 AND p.object_href = obj.href
                    AND p.collection_href = col.href
              WHERE obj.id = ?2 AND p.state = 'conflict'"
        );
        type Row = (i64, i64, Option<String>, Option<Vec<u8>>, String, String);
        let found: Option<Row> = transaction
            .query_row(&sql, rusqlite::params![area, id], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .optional()
            .map_err(classify)?;
        // Idempotencia: si ese id ya no está en conflicto —se resolvió antes, o una
        // edición nueva reemplazó la op— no hay nada que hacer. Error benigno.
        let Some((op_id, revision, server_etag, server_raw, object_href, collection_href)) = found
        else {
            return Err(StoreError::InvalidArgument(
                "ese objeto ya no está en conflicto".into(),
            ));
        };

        let affected = match choice {
            ConflictChoice::KeepLocal => {
                // Sin el ETag del servidor no se puede re-basar: re-basar sin
                // precondición sería un `PUT` incondicional que pisa a ciegas. Un
                // ETag vacío o en blanco cuenta como ausente —un servidor roto puede
                // devolver `<getetag></getetag>` tras el 412, y `storable()` lo filtra
                // por largo, no por vacío—: re-basar con `base_etag = ""` tampoco es
                // una precondición, así que la invariante se comprueba acá y no
                // depende sólo de la guarda de `replay` aguas abajo.
                if server_etag
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err(StoreError::InvalidArgument(
                        "todavía no se trajo la copia del servidor con qué re-basar".into(),
                    ));
                }
                // `base_etag = server_etag` usa el valor **anterior** de la fila
                // aunque la misma orden ponga `server_etag = NULL` después: SQLite
                // evalúa el lado derecho de cada `SET` contra la fila original.
                transaction
                    .execute(
                        "UPDATE pending_dav_ops
                            SET base_etag = server_etag, server_etag = NULL, server_raw = NULL,
                                state = 'ready', attempts = 0, last_error = NULL,
                                revision = revision + 1
                          WHERE id = ?1 AND revision = ?2 AND state = 'conflict'",
                        rusqlite::params![op_id, revision],
                    )
                    .map_err(classify)?
            }
            ConflictChoice::TakeServer => {
                // Sin la copia del servidor no hay qué adoptar: no se descarta el
                // cambio local a ciegas.
                let Some(server_raw) = server_raw else {
                    return Err(StoreError::InvalidArgument(
                        "todavía no se trajo la copia del servidor para adoptarla".into(),
                    ));
                };
                // Primero se cierra la op (condicional a id+revision+conflicto): si
                // se movió, no se toca la fila guardada.
                let closed = transaction
                    .execute(
                        "DELETE FROM pending_dav_ops
                          WHERE id = ?1 AND revision = ?2 AND state = 'conflict'",
                        rusqlite::params![op_id, revision],
                    )
                    .map_err(classify)?;
                if closed > 0 {
                    // La copia del servidor se guarda en la columna de crudo (TEXT):
                    // se interpreta como texto, igual que `GetConflict` la muestra y
                    // que la bajada guarda el crudo del servidor. Con alcance de
                    // colección: no toca el mismo `href` de otra colección.
                    let server_text = String::from_utf8_lossy(&server_raw).into_owned();
                    transaction
                        .execute(
                            &format!(
                                "UPDATE {table} SET {raw_col} = ?1, etag = ?2, pending_op = NULL
                                  WHERE href = ?3
                                    AND {colcol} = (SELECT id FROM {coltable} WHERE href = ?4)"
                            ),
                            rusqlite::params![
                                server_text,
                                server_etag,
                                object_href,
                                collection_href
                            ],
                        )
                        .map_err(classify)?;
                }
                closed
            }
        };

        // El cierre condicional no alcanzó la op: se movió entre la lectura y la
        // escritura (dentro de la misma transacción es un imposible, pero la
        // guarda es la misma del resto de la cola). Idempotente.
        if affected == 0 {
            return Err(StoreError::InvalidArgument(
                "ese objeto ya no está en conflicto".into(),
            ));
        }

        let generation = bump_generation(&transaction, area_static)?;
        transaction.commit().map_err(classify)?;
        self.note_change(area_static, generation);
        Ok(())
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

    /// **Integridad**: re-encolar una edición nueva **limpia la copia del
    /// servidor** de la revisión anterior. Sin esto, una edición nueva heredaría
    /// `server_etag`/`server_raw` viejos, y si volviera a chocar sin poder traer
    /// su copia, M3 mostraría la del servidor de una revisión vieja como la actual.
    #[test]
    fn re_encolar_una_edicion_limpia_la_copia_del_servidor() {
        let temp = TempDir::new("cola-reencolar-limpia-copia");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store
            .store_server_copy(op.id, op.revision, Some("\"srv\""), b"CRUDO-VIEJO")
            .unwrap();
        // La copia vieja está guardada.
        assert_ne!(server_copy_of(&store, HREF), (None, None));

        // Edición nueva del mismo recurso: re-encola por `insert_pending_op`.
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana María", "nuevo@x.com"))
            .unwrap();

        // La copia heredada se limpió, y la op arrancó limpia.
        assert_eq!(server_copy_of(&store, HREF), (None, None));
        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Ready);
        assert_eq!(after.server_etag, None);
        assert_eq!(after.server_raw, None);
        assert!(after.revision > op.revision, "la revisión subió");
    }

    /// **Seguridad**: el `Debug` de una op **tacha** los cuerpos privados —el
    /// `payload` local y la copia del servidor—, mostrando sólo su largo: un `{:?}`
    /// no los filtra al diario.
    #[test]
    fn el_debug_de_una_op_tacha_los_cuerpos_privados() {
        let temp = TempDir::new("cola-debug-tacha");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Ana", "a@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store
            .store_server_copy(op.id, op.revision, Some("\"srv\""), b"CRUDO-DEL-SERVIDOR")
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        let text = format!("{op:?}");
        assert!(
            !text.contains("CRUDO-DEL-SERVIDOR"),
            "el crudo del servidor no sale: {text}"
        );
        assert!(
            !text.contains("BEGIN:VCARD"),
            "el payload local no sale: {text}"
        );
        // Se tacha mostrando el largo, no el contenido.
        assert!(text.contains("bytes"), "se muestra el largo: {text}");
        // El ETag del servidor sí sale (no es privado), y el estado también.
        assert!(
            text.contains("\\\"srv\\\""),
            "el ETag del servidor sale: {text}"
        );
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

    /// **Creación por Graph**: cerrar un `POST` re-basa el `href` de la fila local
    /// —de la dirección sintética al `id` del servidor— y guarda el ETag, para que
    /// la próxima bajada haga upsert sobre la misma fila y no la duplique.
    #[test]
    fn complete_create_rebasa_el_href_al_id_del_servidor() {
        const LOCAL: &str = "graph://default/local.vcf";
        const SERVER: &str = "AAMkServerId==";
        let temp = TempDir::new("cola-create-rebase");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // La creación local, encolada en su href sintético.
        store
            .enqueue_contact_put(&book, &row(LOCAL, "Local", "l@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        store.complete_create(&op, SERVER, Some("\"srv\"")).unwrap();

        // El href sintético ya no está; la fila vive bajo el id del servidor, con
        // su crudo local y el ETag del servidor, y sin marca ni op.
        assert_eq!(raw_of(&store, LOCAL), None, "quedó el href sintético");
        assert!(
            raw_of(&store, SERVER).is_some_and(|r| r.contains("Local")),
            "la fila no se re-basó al id del servidor"
        );
        assert_eq!(etag_of(&store, SERVER).as_deref(), Some("\"srv\""));
        assert_eq!(pending_op_of(&store, SERVER), None);
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 0);
    }

    /// **Idempotencia del `POST` por `transactionId`**: si una bajada anterior ya
    /// trajo el objeto bajo su `id` del servidor (porque el `POST` reintentado
    /// devolvió el mismo id), re-basar el `href` chocaría con esa fila por el
    /// `UNIQUE (libreta, href)`. El `UPDATE OR REPLACE` la reemplaza por la local
    /// —el mismo objeto con el crudo que la persona subió— en vez de fallar.
    #[test]
    fn complete_create_reemplaza_una_fila_ya_bajada_del_servidor() {
        const LOCAL: &str = "graph://default/local.vcf";
        const SERVER: &str = "AAMkServerId==";
        let temp = TempDir::new("cola-create-collision");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // La bajada ya trajo el objeto bajo su id del servidor.
        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(SERVER, "Servidor", "s@x.com"))],
                None,
                u64::MAX,
            )
            .unwrap();
        // Y está la creación local pendiente, en su href sintético.
        store
            .enqueue_contact_put(&book, &row(LOCAL, "Local", "l@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);

        store.complete_create(&op, SERVER, Some("\"srv\"")).unwrap();

        // Una sola fila bajo el id del servidor, con el crudo local (no el bajado),
        // y sin duplicado en el href sintético.
        assert_eq!(raw_of(&store, LOCAL), None);
        let server_raw = raw_of(&store, SERVER).expect("la fila vive bajo el id del servidor");
        assert!(server_raw.contains("Local"), "ganó el crudo local");
        assert!(!server_raw.contains("Servidor"), "quedó el crudo bajado");
    }

    /// El conteo de filas del índice de búsqueda que matchean un término.
    fn fts_hits(store: &Store, term: &str) -> i64 {
        store
            .connection()
            .query_row(
                "SELECT count(*) FROM contacts_fts WHERE contacts_fts MATCH ?1",
                [term],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// **Integridad del cierre de una creación sobre una fila ya bajada.** Si la
    /// bajada ya trajo el objeto bajo el `id` del servidor y se re-basa la fila local
    /// encima: (1) queda **una sola** fila, la local re-basada; (2) el índice de
    /// búsqueda **no guarda al fantasma** de la fila borrada —el `DELETE` explícito
    /// dispara el trigger `AFTER DELETE` del FTS, que el `UPDATE OR REPLACE` salteaba—;
    /// (3) la **generación sube**, así los lectores no se quedan con la foto vieja.
    #[test]
    fn complete_create_sobre_una_fila_bajada_limpia_el_indice_y_sube_la_generacion() {
        const LOCAL: &str = "graph://default/local.vcf";
        const SERVER: &str = "AAMkServerId==";
        let temp = TempDir::new("cola-create-fts");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(SERVER, "Fantasma", "f@x.com"))],
                None,
                u64::MAX,
            )
            .unwrap();
        store
            .enqueue_contact_put(&book, &row(LOCAL, "Reemplazo", "r@x.com"))
            .unwrap();
        assert_eq!(fts_hits(&store, "fantasma"), 1, "precondición: indexada");
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.take_changes();
        let before = super::super::read_generation(store.connection(), CONTACTS_AREA).unwrap();

        store.complete_create(&op, SERVER, Some("\"srv\"")).unwrap();

        // (1) Una sola fila bajo el id del servidor, con el crudo local.
        let rows: i64 = store
            .connection()
            .query_row("SELECT count(*) FROM contacts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "queda una sola fila");
        assert!(raw_of(&store, SERVER).is_some_and(|r| r.contains("Reemplazo")));
        // (2) Sin fantasma en el índice; la fila viva sí se encuentra.
        assert_eq!(fts_hits(&store, "fantasma"), 0, "fantasma en el FTS");
        assert_eq!(fts_hits(&store, "reemplazo"), 1, "la re-basada se busca");
        // (3) La generación subió y se avisó a los lectores.
        let after = super::super::read_generation(store.connection(), CONTACTS_AREA).unwrap();
        assert!(
            after > before,
            "la generación no subió: {before} -> {after}"
        );
        assert_eq!(store.take_changes(), vec![(CONTACTS_AREA, after)]);
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

    /// El ETag guardado de una fila de contacto por su `href`.
    fn etag_of(store: &Store, href: &str) -> Option<String> {
        store
            .connection()
            .query_row("SELECT etag FROM contacts WHERE href = ?1", [href], |r| {
                r.get(0)
            })
            .unwrap()
    }

    /// Deja un contacto al día (sin op), para después borrarlo o chocarlo.
    fn add_synced(store: &mut Store, book: &super::super::contacts::StoredAddressBook, href: &str) {
        store
            .apply_contacts(
                book,
                &[ContactOp::Upsert(row(href, "Al Día", "al@x.com"))],
                None,
                u64::MAX,
            )
            .unwrap();
    }

    /// Monta un conflicto de `put` con la copia del servidor ya traída, como lo
    /// dejaría el empuje contra un `412` más A3.
    fn put_conflict_with_server_copy(
        store: &mut Store,
        book: &super::super::contacts::StoredAddressBook,
    ) {
        store
            .enqueue_contact_put(book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "cambió en el servidor").unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store
            .store_server_copy(op.id, op.revision, Some("\"srv\""), b"BEGIN:VCARD servidor")
            .unwrap();
    }

    fn contact_id(store: &Store, href: &str, book_id: i64) -> i64 {
        store.contact_id_by_href(book_id, href).unwrap().unwrap()
    }

    /// **`keep_local`**: la versión local gana. La op se re-basa sobre el ETag del
    /// servidor (`base_etag = server_etag`), la copia del servidor se limpia, la op
    /// vuelve a `ready` con la revisión subida, y el crudo local y su marca quedan:
    /// el empuje la va a re-subir pisando el servidor.
    #[test]
    fn resolver_keep_local_rebasa_la_op() {
        let temp = TempDir::new("resolver-keep-local");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        put_conflict_with_server_copy(&mut store, &book);
        let before = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        let id = contact_id(&store, HREF, book.id);

        store
            .resolve_conflict(CONTACTS_AREA, id, ConflictChoice::KeepLocal)
            .unwrap();

        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Ready, "vuelve a reintentar");
        assert_eq!(
            after.base_etag.as_deref(),
            Some("\"srv\""),
            "re-basada sobre el ETag del servidor"
        );
        assert_eq!(after.server_etag, None, "la copia del servidor se limpió");
        assert_eq!(after.server_raw, None);
        assert_eq!(after.attempts, 0, "los reintentos arrancan de cero");
        assert!(after.revision > before.revision, "la revisión subió");
        // El crudo local y su marca quedan: la versión de la persona gana.
        assert!(raw_of(&store, HREF).is_some_and(|r| r.contains("Mía")));
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
    }

    /// **`keep_local` sin copia del servidor**: sin `server_etag` no hay sobre qué
    /// re-basar —re-basar a ciegas sería un `PUT` incondicional—, así que falla y
    /// **no toca nada**: la op sigue en conflicto.
    #[test]
    fn resolver_keep_local_sin_server_etag_falla() {
        let temp = TempDir::new("resolver-keep-local-sin-etag");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // Conflicto sin traer la copia del servidor: server_etag queda en NULL.
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let id = contact_id(&store, HREF, book.id);

        let result = store.resolve_conflict(CONTACTS_AREA, id, ConflictChoice::KeepLocal);
        assert!(matches!(result, Err(StoreError::InvalidArgument(_))));

        // La op sigue intacta, en conflicto: el `base_etag` no se re-basó (sigue el
        // local de origen, no el del servidor, que no se trajo).
        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Conflict);
        assert_eq!(after.base_etag.as_deref(), Some("\"1\""));
        assert_eq!(after.attempts, 1, "no se re-basó ni se contó un intento");
    }

    /// **Defensa en profundidad**: un `server_etag` vacío o en blanco —un servidor
    /// roto que tras el 412 devuelve `<getetag></getetag>`, que `storable()` deja
    /// pasar por filtrar por largo y no por vacío— cuenta como ausente. `keep_local`
    /// falla y **no re-basa con `base_etag = ""`**: la invariante «sin ETag del
    /// servidor no hay sobre qué re-basar» se comprueba acá, sin depender sólo de la
    /// guarda de `replay` aguas abajo.
    #[test]
    fn resolver_keep_local_con_server_etag_vacio_falla() {
        let temp = TempDir::new("resolver-keep-local-etag-vacio");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        // El servidor devolvió un ETag vacío: `server_etag = Some("")`.
        store
            .store_server_copy(op.id, op.revision, Some(""), b"BEGIN:VCARD servidor")
            .unwrap();
        let id = contact_id(&store, HREF, book.id);

        let result = store.resolve_conflict(CONTACTS_AREA, id, ConflictChoice::KeepLocal);
        assert!(matches!(result, Err(StoreError::InvalidArgument(_))));

        // La op sigue en conflicto, sin re-basar: el `base_etag` no quedó en `""`.
        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Conflict);
        assert_eq!(after.base_etag.as_deref(), Some("\"1\""));
    }

    /// **`take_server`**: el servidor gana. Su copia se adopta en la fila guardada
    /// —su crudo y su ETag—, la marca `pending_op` se limpia y la op se descarta.
    #[test]
    fn resolver_take_server_adopta_la_copia_y_borra_la_op() {
        let temp = TempDir::new("resolver-take-server");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        put_conflict_with_server_copy(&mut store, &book);
        let id = contact_id(&store, HREF, book.id);

        store
            .resolve_conflict(CONTACTS_AREA, id, ConflictChoice::TakeServer)
            .unwrap();

        assert_eq!(
            raw_of(&store, HREF).as_deref(),
            Some("BEGIN:VCARD servidor"),
            "la fila guarda el crudo del servidor"
        );
        assert_eq!(etag_of(&store, HREF).as_deref(), Some("\"srv\""));
        assert_eq!(pending_op_of(&store, HREF), None, "la marca se limpió");
        assert_eq!(
            store.pending_count(CONTACTS_AREA).unwrap(),
            0,
            "la op se fue"
        );
    }

    /// **`take_server` sin copia del servidor**: sin `server_raw` no hay qué
    /// adoptar, así que falla y **no descarta el cambio local**: la op sigue en
    /// conflicto y el crudo local queda.
    #[test]
    fn resolver_take_server_sin_copia_del_servidor_falla() {
        let temp = TempDir::new("resolver-take-server-sin-copia");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let id = contact_id(&store, HREF, book.id);

        let result = store.resolve_conflict(CONTACTS_AREA, id, ConflictChoice::TakeServer);
        assert!(matches!(result, Err(StoreError::InvalidArgument(_))));

        assert!(raw_of(&store, HREF).is_some_and(|r| r.contains("Mía")));
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
        assert_eq!(
            store.pending_count(CONTACTS_AREA).unwrap(),
            1,
            "la op sigue"
        );
    }

    /// **`take_server` de un borrado en conflicto**: el objeto sigue existiendo con
    /// la versión del servidor —no se borra—, la marca se limpia y la op se va.
    #[test]
    fn resolver_take_server_de_un_borrado_deja_la_version_del_servidor() {
        let temp = TempDir::new("resolver-take-server-borrado");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        add_synced(&mut store, &book, HREF);
        store
            .enqueue_delete(CONTACTS_AREA, BOOK, HREF, Some("\"1\""))
            .unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store.mark_conflict(&op, "chocó").unwrap();
        let op = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        store
            .store_server_copy(
                op.id,
                op.revision,
                Some("\"srv2\""),
                b"BEGIN:VCARD del servidor",
            )
            .unwrap();
        let id = contact_id(&store, HREF, book.id);

        store
            .resolve_conflict(CONTACTS_AREA, id, ConflictChoice::TakeServer)
            .unwrap();

        // El objeto NO se borró: quedó con la versión del servidor.
        assert_eq!(
            raw_of(&store, HREF).as_deref(),
            Some("BEGIN:VCARD del servidor")
        );
        assert_eq!(etag_of(&store, HREF).as_deref(), Some("\"srv2\""));
        assert_eq!(pending_op_of(&store, HREF), None);
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 0);
    }

    /// **Idempotencia**: resolver un objeto que **ya no está en conflicto** —su op
    /// está en `ready`, no en `conflict`— no rompe ni toca nada: error benigno.
    #[test]
    fn resolver_una_op_que_ya_no_esta_en_conflicto_no_rompe() {
        let temp = TempDir::new("resolver-idempotente");
        let mut store = open_store(&temp);
        let book = one_book(&mut store);
        // La op queda en `ready`, nunca chocó.
        store
            .enqueue_contact_put(&book, &row(HREF, "Mía", "yo@x.com"))
            .unwrap();
        let id = contact_id(&store, HREF, book.id);

        for choice in [ConflictChoice::KeepLocal, ConflictChoice::TakeServer] {
            let result = store.resolve_conflict(CONTACTS_AREA, id, choice);
            assert!(matches!(result, Err(StoreError::InvalidArgument(_))));
        }
        // Nada cambió: la op sigue en `ready`, con su crudo y su marca.
        let after = store.pending_ops(CONTACTS_AREA).unwrap().remove(0);
        assert_eq!(after.state, PendingState::Ready);
        assert_eq!(pending_op_of(&store, HREF).as_deref(), Some("put"));
        assert_eq!(store.pending_count(CONTACTS_AREA).unwrap(), 1);
    }

    /// Un área sin cola de escritura (correo) es un argumento inválido, **sin tocar
    /// el disco**.
    #[test]
    fn resolver_un_area_sin_cola_es_invalida() {
        let temp = TempDir::new("resolver-area-mala");
        let mut store = open_store(&temp);
        assert!(matches!(
            store.resolve_conflict("email", 1, ConflictChoice::KeepLocal),
            Err(StoreError::InvalidArgument(_))
        ));
    }
}
