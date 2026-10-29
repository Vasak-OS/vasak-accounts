//! Las dos colas privadas del correo: posponer un mensaje y recordar un
//! seguimiento. Sólo estado del almacén cifrado (tablas de la migración V13),
//! **sin red**: quien mueve el mensaje o manda el aviso es el bucle de
//! `store_api`, que lee de acá a su hora.
//!
//! Helpers calcados de los recordatorios del calendario
//! ([`super::calendar_read::due_reminders`] / `next_reminder_at`): funciones
//! puras sobre `&Connection`, con los tiempos en segundos epoch que recibe quien
//! llama. Así son deterministas —no miran el reloj— y el bucle les pasa el mismo
//! `now` que usa para dormir.
//!
//! **Una fila por mensaje** (`UNIQUE (message_id)` en las dos tablas): reponer un
//! posponer o un seguimiento ya puesto **actualiza** su hora (upsert por
//! `message_id`), no duplica ni falla. La anti-repetición es borrar la fila al
//! atenderla o cancelarla: por eso el vencimiento se consulta con `*_at <= now`
//! sin borde inferior, al revés que los recordatorios, que no se borran y se
//! acotan con `since`.
//!
//! Todavía no hay quien los llame fuera de las pruebas: los bucles de retorno y
//! de aviso y los métodos D-Bus (`Snooze`/`List`/`Cancel`, `SetFollowup`) llegan
//! en los PRs 3 y 4 de `vasak-accounts#22`. Por eso el módulo permite código sin
//! usar en la compilación que no es de prueba —como `calendar_read` con sus
//! accesores—, pero no en la de prueba, donde un helper muerto de verdad sí avisa.
#![cfg_attr(not(test), allow(dead_code))]

use rusqlite::Connection;

use super::{classify, StoreError};

/// Un mensaje sacado del INBOX hasta `return_at`, con lo que hace falta para
/// devolverlo a su casilla. La identidad estable es `message_id`; `new_uid` y
/// `uidvalidity` son el UID que dejó el `COPYUID` al mover a pospuestos, y están
/// en `None` cuando el servidor no dio `COPYUID` (sin `UIDPLUS`): ahí el retorno
/// re-ubica el mensaje por `Message-ID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnoozedMessage {
    pub id: i64,
    pub message_id: String,
    pub origin_mailbox: String,
    pub new_uid: Option<i64>,
    pub uidvalidity: Option<i64>,
    pub return_at: i64,
    pub created_at: i64,
}

/// Un mensaje enviado para el que hay que recordar un seguimiento a `remind_at`
/// si no hubo respuesta. `recipients` es a quién se le escribió, para el texto
/// del aviso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Followup {
    pub id: i64,
    pub message_id: String,
    pub recipients: String,
    pub remind_at: i64,
    pub created_at: i64,
}

/// Pospone un mensaje, o repone uno ya pospuesto: upsert por `message_id`.
/// Reponer actualiza la casilla de origen, el UID y las dos fechas; no duplica
/// ni falla.
pub fn upsert_snooze(
    connection: &Connection,
    message_id: &str,
    origin_mailbox: &str,
    new_uid: Option<i64>,
    uidvalidity: Option<i64>,
    return_at: i64,
    created_at: i64,
) -> Result<(), StoreError> {
    connection
        .execute(
            "INSERT INTO snoozed_messages
                 (message_id, origin_mailbox, new_uid, uidvalidity, return_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (message_id) DO UPDATE SET
                     origin_mailbox = excluded.origin_mailbox,
                     new_uid = excluded.new_uid,
                     uidvalidity = excluded.uidvalidity,
                     return_at = excluded.return_at,
                     created_at = excluded.created_at",
            rusqlite::params![
                message_id,
                origin_mailbox,
                new_uid,
                uidvalidity,
                return_at,
                created_at
            ],
        )
        .map_err(classify)?;
    Ok(())
}

/// Anota un seguimiento, o repone uno ya anotado: upsert por `message_id`.
/// Reponer actualiza los destinatarios y las dos fechas; no duplica ni falla.
pub fn upsert_followup(
    connection: &Connection,
    message_id: &str,
    recipients: &str,
    remind_at: i64,
    created_at: i64,
) -> Result<(), StoreError> {
    connection
        .execute(
            "INSERT INTO followups (message_id, recipients, remind_at, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (message_id) DO UPDATE SET
                     recipients = excluded.recipients,
                     remind_at = excluded.remind_at,
                     created_at = excluded.created_at",
            rusqlite::params![message_id, recipients, remind_at, created_at],
        )
        .map_err(classify)?;
    Ok(())
}

/// Los pospuestos cuyo `return_at` ya llegó (`<= now`), para devolverlos.
/// Ordenados por hora de vuelta. Sin borde inferior: la fila se borra al
/// atenderla, así que no se repite.
pub fn due_snoozed(connection: &Connection, now: i64) -> Result<Vec<SnoozedMessage>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, message_id, origin_mailbox, new_uid, uidvalidity, return_at, created_at
               FROM snoozed_messages INDEXED BY snoozed_messages_by_return
              WHERE return_at <= ?
              ORDER BY return_at, id",
        )
        .map_err(classify)?;
    let rows = statement
        .query_map([now], row_to_snoozed)
        .map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// Los seguimientos cuyo `remind_at` ya llegó (`<= now`), para avisar.
/// Ordenados por hora de aviso. Sin borde inferior: la fila se borra al
/// atenderla.
pub fn due_followups(connection: &Connection, now: i64) -> Result<Vec<Followup>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, message_id, recipients, remind_at, created_at
               FROM followups INDEXED BY followups_by_remind
              WHERE remind_at <= ?
              ORDER BY remind_at, id",
        )
        .map_err(classify)?;
    let rows = statement
        .query_map([now], row_to_followup)
        .map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// La próxima hora de vuelta después de `now`, o nada si no queda ninguna: el
/// techo del reloj del bucle, como [`super::calendar_read::next_reminder_at`].
pub fn next_snooze_at(connection: &Connection, now: i64) -> Result<Option<i64>, StoreError> {
    connection
        .query_row(
            "SELECT min(return_at) FROM snoozed_messages WHERE return_at > ?",
            [now],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(classify)
}

/// La próxima hora de aviso después de `now`, o nada si no queda ninguna.
pub fn next_followup_at(connection: &Connection, now: i64) -> Result<Option<i64>, StoreError> {
    connection
        .query_row(
            "SELECT min(remind_at) FROM followups WHERE remind_at > ?",
            [now],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(classify)
}

/// Todos los pospuestos, ordenados por hora de vuelta. Para `ListSnoozed`.
pub fn list_snoozed(connection: &Connection) -> Result<Vec<SnoozedMessage>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, message_id, origin_mailbox, new_uid, uidvalidity, return_at, created_at
               FROM snoozed_messages
              ORDER BY return_at, id",
        )
        .map_err(classify)?;
    let rows = statement.query_map([], row_to_snoozed).map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// Todos los seguimientos, ordenados por hora de aviso. Para `ListFollowups`.
pub fn list_followups(connection: &Connection) -> Result<Vec<Followup>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, message_id, recipients, remind_at, created_at
               FROM followups
              ORDER BY remind_at, id",
        )
        .map_err(classify)?;
    let rows = statement.query_map([], row_to_followup).map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// Borra el posponer de un mensaje (cancelar o atender). Devuelve si había fila:
/// un `CancelSnooze` de algo que otro dispositivo ya movió da `false`, no error.
pub fn delete_snooze(connection: &Connection, message_id: &str) -> Result<bool, StoreError> {
    let affected = connection
        .execute(
            "DELETE FROM snoozed_messages WHERE message_id = ?1",
            rusqlite::params![message_id],
        )
        .map_err(classify)?;
    Ok(affected > 0)
}

/// Borra el seguimiento de un mensaje (cancelar o atender). Devuelve si había
/// fila.
pub fn delete_followup(connection: &Connection, message_id: &str) -> Result<bool, StoreError> {
    let affected = connection
        .execute(
            "DELETE FROM followups WHERE message_id = ?1",
            rusqlite::params![message_id],
        )
        .map_err(classify)?;
    Ok(affected > 0)
}

fn row_to_snoozed(row: &rusqlite::Row) -> rusqlite::Result<SnoozedMessage> {
    Ok(SnoozedMessage {
        id: row.get(0)?,
        message_id: row.get(1)?,
        origin_mailbox: row.get(2)?,
        new_uid: row.get(3)?,
        uidvalidity: row.get(4)?,
        return_at: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn row_to_followup(row: &rusqlite::Row) -> rusqlite::Result<Followup> {
    Ok(Followup {
        id: row.get(0)?,
        message_id: row.get(1)?,
        recipients: row.get(2)?,
        remind_at: row.get(3)?,
        created_at: row.get(4)?,
    })
}
