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

use super::{classify, Store, StoreError};

/// Un mensaje sacado del INBOX hasta `return_at`, con lo que hace falta para
/// devolverlo a su casilla. La identidad estable es `message_id`; `new_uid` y
/// `uidvalidity` son el UID que dejó el `COPYUID` al mover a pospuestos, y están
/// en `None` cuando el servidor no dio `COPYUID` (sin `UIDPLUS`): ahí el retorno
/// re-ubica el mensaje por `Message-ID`.
///
/// Se serializa para `ListSnoozed`: `message_id` tal cual —es un identificador,
/// como en `ReplyInfo`— y el resto con nombres en español. El `id` de fila y el
/// `created_at` no salen: son de adentro, no los mira la ventana.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SnoozedMessage {
    #[serde(skip)]
    pub id: i64,
    pub message_id: String,
    #[serde(rename = "casilla_origen")]
    pub origin_mailbox: String,
    #[serde(rename = "uid", skip_serializing_if = "Option::is_none")]
    pub new_uid: Option<i64>,
    #[serde(rename = "uidvalidity", skip_serializing_if = "Option::is_none")]
    pub uidvalidity: Option<i64>,
    #[serde(rename = "volver_a")]
    pub return_at: i64,
    #[serde(skip)]
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

/// La escritura de los pospuestos pasa por el `Store`, que es el único que tiene
/// la conexión de escritura (el camino con la cerradura del administrador, como
/// el resto de las mutaciones). Las lecturas, en cambio, van por el grupo de
/// lectura con las funciones libres de arriba, así que no necesitan método acá.
impl Store {
    /// Pospone (o repone) un mensaje. Delega en [`upsert_snooze`].
    pub fn upsert_snooze(
        &self,
        message_id: &str,
        origin_mailbox: &str,
        new_uid: Option<i64>,
        uidvalidity: Option<i64>,
        return_at: i64,
        created_at: i64,
    ) -> Result<(), StoreError> {
        upsert_snooze(
            &self.connection,
            message_id,
            origin_mailbox,
            new_uid,
            uidvalidity,
            return_at,
            created_at,
        )
    }

    /// Borra el posponer de un mensaje. Delega en [`delete_snooze`].
    pub fn delete_snooze(&self, message_id: &str) -> Result<bool, StoreError> {
        delete_snooze(&self.connection, message_id)
    }
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

#[cfg(test)]
mod tests {
    use super::super::contacts::tests::open_store;
    use super::super::paths::tests::TempDir;
    use super::*;

    const NOW: i64 = 1_000;

    fn snooze(c: &Connection, id: &str, return_at: i64) {
        upsert_snooze(c, id, "INBOX", Some(7), Some(3), return_at, 1).unwrap();
    }

    fn followup(c: &Connection, id: &str, remind_at: i64) {
        upsert_followup(c, id, "ana@x.com", remind_at, 1).unwrap();
    }

    fn ids_of_snoozed(rows: &[SnoozedMessage]) -> Vec<&str> {
        rows.iter().map(|r| r.message_id.as_str()).collect()
    }

    fn ids_of_followups(rows: &[Followup]) -> Vec<&str> {
        rows.iter().map(|r| r.message_id.as_str()).collect()
    }

    #[test]
    fn posponer_guarda_el_mensaje_y_la_lista_lo_devuelve() {
        let temp = TempDir::new("snooze-lista");
        let store = open_store(&temp);
        let c = store.connection();
        assert!(list_snoozed(c).unwrap().is_empty());

        upsert_snooze(c, "<a@x>", "INBOX", Some(7), Some(3), 2_000, 500).unwrap();

        let rows = list_snoozed(c).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.message_id, "<a@x>");
        assert_eq!(row.origin_mailbox, "INBOX");
        assert_eq!(row.new_uid, Some(7));
        assert_eq!(row.uidvalidity, Some(3));
        assert_eq!(row.return_at, 2_000);
        assert_eq!(row.created_at, 500);
    }

    #[test]
    fn reponer_un_posponer_actualiza_la_hora_y_el_ruteo_sin_duplicar() {
        let temp = TempDir::new("snooze-upsert");
        let store = open_store(&temp);
        let c = store.connection();
        upsert_snooze(c, "<a@x>", "INBOX", Some(7), Some(3), 2_000, 500).unwrap();
        upsert_snooze(c, "<a@x>", "Trabajo", Some(9), Some(4), 5_000, 600).unwrap();

        let rows = list_snoozed(c).unwrap();
        assert_eq!(rows.len(), 1, "no debe duplicar por message_id");
        assert_eq!(rows[0].origin_mailbox, "Trabajo");
        assert_eq!(rows[0].new_uid, Some(9));
        assert_eq!(rows[0].uidvalidity, Some(4));
        assert_eq!(rows[0].return_at, 5_000);
        assert_eq!(rows[0].created_at, 600);
    }

    #[test]
    fn el_seguimiento_se_guarda_y_la_lista_lo_devuelve() {
        let temp = TempDir::new("followup-lista");
        let store = open_store(&temp);
        let c = store.connection();
        assert!(list_followups(c).unwrap().is_empty());

        upsert_followup(c, "<f@x>", "ana@x.com, beto@x.com", 2_000, 500).unwrap();

        let rows = list_followups(c).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, "<f@x>");
        assert_eq!(rows[0].recipients, "ana@x.com, beto@x.com");
        assert_eq!(rows[0].remind_at, 2_000);
        assert_eq!(rows[0].created_at, 500);
    }

    #[test]
    fn reponer_un_seguimiento_actualiza_la_hora_sin_duplicar() {
        let temp = TempDir::new("followup-upsert");
        let store = open_store(&temp);
        let c = store.connection();
        upsert_followup(c, "<f@x>", "ana@x.com", 2_000, 500).unwrap();
        upsert_followup(c, "<f@x>", "beto@x.com", 7_000, 600).unwrap();

        let rows = list_followups(c).unwrap();
        assert_eq!(rows.len(), 1, "no debe duplicar por message_id");
        assert_eq!(rows[0].recipients, "beto@x.com");
        assert_eq!(rows[0].remind_at, 7_000);
        assert_eq!(rows[0].created_at, 600);
    }

    #[test]
    fn las_listas_van_ordenadas_por_hora() {
        let temp = TempDir::new("orden");
        let store = open_store(&temp);
        let c = store.connection();
        snooze(c, "<tarde>", 3_000);
        snooze(c, "<temprano>", 2_000);
        followup(c, "<tarde>", 3_000);
        followup(c, "<temprano>", 2_000);

        assert_eq!(
            ids_of_snoozed(&list_snoozed(c).unwrap()),
            ["<temprano>", "<tarde>"]
        );
        assert_eq!(
            ids_of_followups(&list_followups(c).unwrap()),
            ["<temprano>", "<tarde>"]
        );
    }

    #[test]
    fn los_pospuestos_vencidos_incluyen_el_borde_y_excluyen_el_futuro() {
        let temp = TempDir::new("snooze-vencidos");
        let store = open_store(&temp);
        let c = store.connection();
        snooze(c, "<pasado>", NOW - 100);
        snooze(c, "<justo>", NOW);
        snooze(c, "<futuro>", NOW + 1);

        let due = due_snoozed(c, NOW).unwrap();
        assert_eq!(ids_of_snoozed(&due), ["<pasado>", "<justo>"]);
        // Lo que se devuelve es la fila entera, lista para mover.
        assert_eq!(due[1].origin_mailbox, "INBOX");
        assert_eq!(due[1].new_uid, Some(7));
        assert!(due_snoozed(c, NOW - 101).unwrap().is_empty());
    }

    #[test]
    fn los_seguimientos_vencidos_incluyen_el_borde_y_excluyen_el_futuro() {
        let temp = TempDir::new("followup-vencidos");
        let store = open_store(&temp);
        let c = store.connection();
        followup(c, "<pasado>", NOW - 100);
        followup(c, "<justo>", NOW);
        followup(c, "<futuro>", NOW + 1);

        let due = due_followups(c, NOW).unwrap();
        assert_eq!(ids_of_followups(&due), ["<pasado>", "<justo>"]);
        assert_eq!(due[1].recipients, "ana@x.com");
        assert!(due_followups(c, NOW - 101).unwrap().is_empty());
    }

    /// Contrato: `next_*` mira **estrictamente después** de `now` (`> now`). Lo
    /// que vence en `now` ya lo devuelve `due_*`; si `next_*` también lo diera, el
    /// bucle dormiría cero segundos sobre algo que ya atendió.
    #[test]
    fn la_proxima_vuelta_es_la_menor_estrictamente_futura() {
        let temp = TempDir::new("snooze-proximo");
        let store = open_store(&temp);
        let c = store.connection();
        assert_eq!(next_snooze_at(c, NOW).unwrap(), None, "tabla vacía");

        snooze(c, "<viejo>", NOW - 500);
        snooze(c, "<justo>", NOW);
        snooze(c, "<lejos>", NOW + 900);
        snooze(c, "<cerca>", NOW + 10);

        // El menor absoluto (NOW - 500) y el `== now` no cuentan: el próximo es el
        // menor de los futuros.
        assert_eq!(next_snooze_at(c, NOW).unwrap(), Some(NOW + 10));
        assert_eq!(next_snooze_at(c, NOW + 10).unwrap(), Some(NOW + 900));
        assert_eq!(
            next_snooze_at(c, NOW + 900).unwrap(),
            None,
            "no queda ninguna"
        );
    }

    #[test]
    fn el_proximo_aviso_es_el_menor_estrictamente_futuro() {
        let temp = TempDir::new("followup-proximo");
        let store = open_store(&temp);
        let c = store.connection();
        assert_eq!(next_followup_at(c, NOW).unwrap(), None, "tabla vacía");

        followup(c, "<viejo>", NOW - 500);
        followup(c, "<justo>", NOW);
        followup(c, "<lejos>", NOW + 900);
        followup(c, "<cerca>", NOW + 10);

        assert_eq!(next_followup_at(c, NOW).unwrap(), Some(NOW + 10));
        assert_eq!(next_followup_at(c, NOW + 10).unwrap(), Some(NOW + 900));
        assert_eq!(
            next_followup_at(c, NOW + 900).unwrap(),
            None,
            "no queda ninguna"
        );
    }

    #[test]
    fn cancelar_un_posponer_dice_si_habia_y_es_idempotente() {
        let temp = TempDir::new("snooze-borrar");
        let store = open_store(&temp);
        let c = store.connection();
        snooze(c, "<a@x>", 2_000);
        snooze(c, "<b@x>", 3_000);

        assert!(delete_snooze(c, "<a@x>").unwrap());
        assert_eq!(ids_of_snoozed(&list_snoozed(c).unwrap()), ["<b@x>"]);
        // Otra vez, o uno que nunca existió: `false`, sin error y sin tocar el resto.
        assert!(!delete_snooze(c, "<a@x>").unwrap());
        assert!(!delete_snooze(c, "<nunca@x>").unwrap());
        assert_eq!(list_snoozed(c).unwrap().len(), 1);
    }

    #[test]
    fn cancelar_un_seguimiento_dice_si_habia_y_es_idempotente() {
        let temp = TempDir::new("followup-borrar");
        let store = open_store(&temp);
        let c = store.connection();
        followup(c, "<a@x>", 2_000);
        followup(c, "<b@x>", 3_000);

        assert!(delete_followup(c, "<a@x>").unwrap());
        assert_eq!(ids_of_followups(&list_followups(c).unwrap()), ["<b@x>"]);
        assert!(!delete_followup(c, "<a@x>").unwrap());
        assert!(!delete_followup(c, "<nunca@x>").unwrap());
        assert_eq!(list_followups(c).unwrap().len(), 1);
    }

    #[test]
    fn atender_un_vencido_lo_borra_y_no_se_repite() {
        let temp = TempDir::new("snooze-atender");
        let store = open_store(&temp);
        let c = store.connection();
        snooze(c, "<a@x>", NOW - 1);
        followup(c, "<f@x>", NOW - 1);

        assert_eq!(due_snoozed(c, NOW).unwrap().len(), 1);
        assert!(delete_snooze(c, "<a@x>").unwrap());
        assert!(due_snoozed(c, NOW).unwrap().is_empty());

        assert_eq!(due_followups(c, NOW).unwrap().len(), 1);
        assert!(delete_followup(c, "<f@x>").unwrap());
        assert!(due_followups(c, NOW).unwrap().is_empty());
    }

    /// Sin `COPYUID` (servidor sin `UIDPLUS`) no hay UID nuevo: se guarda y se lee
    /// como `None` —no como `0`—, y el retorno re-ubica por `Message-ID`.
    #[test]
    fn sin_uid_nuevo_se_guarda_y_se_lee_como_nada() {
        let temp = TempDir::new("snooze-nulos");
        let store = open_store(&temp);
        let c = store.connection();
        upsert_snooze(c, "<sin@x>", "INBOX", None, None, 2_000, 1).unwrap();
        upsert_snooze(c, "<con@x>", "INBOX", Some(0), Some(0), 3_000, 1).unwrap();

        let rows = list_snoozed(c).unwrap();
        assert_eq!((rows[0].new_uid, rows[0].uidvalidity), (None, None));
        // Un 0 de verdad se conserva: no se confunde con la ausencia.
        assert_eq!((rows[1].new_uid, rows[1].uidvalidity), (Some(0), Some(0)));

        // Y reponer con UID pasa de nada a valor, y de valor a nada.
        upsert_snooze(c, "<sin@x>", "INBOX", Some(11), Some(5), 2_000, 1).unwrap();
        upsert_snooze(c, "<con@x>", "INBOX", None, None, 3_000, 1).unwrap();
        let rows = list_snoozed(c).unwrap();
        assert_eq!((rows[0].new_uid, rows[0].uidvalidity), (Some(11), Some(5)));
        assert_eq!((rows[1].new_uid, rows[1].uidvalidity), (None, None));
    }

    /// Una fila por mensaje, y cada cola es independiente de la otra: el mismo
    /// `Message-ID` puede estar pospuesto y con seguimiento a la vez.
    #[test]
    fn las_dos_colas_son_independientes_para_el_mismo_mensaje() {
        let temp = TempDir::new("colas");
        let store = open_store(&temp);
        let c = store.connection();
        snooze(c, "<m@x>", 2_000);
        followup(c, "<m@x>", 3_000);

        assert!(delete_snooze(c, "<m@x>").unwrap());
        assert!(list_snoozed(c).unwrap().is_empty());
        assert_eq!(list_followups(c).unwrap().len(), 1);
    }

    /// Lo que `ListSnoozed` le da a la ventana: exactamente estos campos, con
    /// estos nombres, y nada de lo de adentro (`id` de fila, `created_at`). La
    /// ventana lee el JSON desde afuera de este proceso, así que renombrar un
    /// campo en Rust tiene que romper acá y no en su pantalla.
    #[test]
    fn el_json_de_un_pospuesto_lleva_solo_los_campos_de_la_ventana() {
        let row = SnoozedMessage {
            id: 41,
            message_id: "<a@x>".into(),
            origin_mailbox: "INBOX".into(),
            new_uid: Some(7),
            uidvalidity: Some(3),
            return_at: 2_000,
            created_at: 500,
        };
        let json = serde_json::to_value(&row).unwrap();

        assert_eq!(
            crate::test_support::json_keys(&json),
            [
                "casilla_origen",
                "message_id",
                "uid",
                "uidvalidity",
                "volver_a"
            ]
        );
        assert_eq!(
            json,
            serde_json::json!({
                "message_id": "<a@x>",
                "casilla_origen": "INBOX",
                "uid": 7,
                "uidvalidity": 3,
                "volver_a": 2_000,
            })
        );
    }

    /// Sin `COPYUID` (servidor sin UIDPLUS) el UID y su validez no salen: no hay
    /// nada que decir, y la ventana no recibe un `null` por un número.
    #[test]
    fn el_json_sin_copyuid_omite_el_uid_y_su_validez() {
        let row = SnoozedMessage {
            id: 1,
            message_id: "<b@x>".into(),
            origin_mailbox: "Trabajo".into(),
            new_uid: None,
            uidvalidity: None,
            return_at: 9,
            created_at: 1,
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(
            crate::test_support::json_keys(&json),
            ["casilla_origen", "message_id", "volver_a"]
        );
    }

    /// Lo que se lee del almacén sale tal cual por el JSON de la lista: la ruta
    /// de punta a punta de `ListSnoozed` sin el bus.
    #[test]
    fn la_lista_del_almacen_se_serializa_para_la_ventana() {
        let temp = TempDir::new("snooze-json");
        let store = open_store(&temp);
        let c = store.connection();
        upsert_snooze(c, "<a@x>", "INBOX", Some(7), Some(3), 2_000, 500).unwrap();

        let json = serde_json::to_value(list_snoozed(c).unwrap()).unwrap();
        assert_eq!(
            json,
            serde_json::json!([{
                "message_id": "<a@x>",
                "casilla_origen": "INBOX",
                "uid": 7,
                "uidvalidity": 3,
                "volver_a": 2_000,
            }])
        );
    }

    /// La escritura por el `Store` (el camino que usa el servicio): pospone,
    /// repone con la hora nueva sin duplicar, y borra devolviendo si había fila.
    #[test]
    fn el_store_pospone_repone_y_borra() {
        let temp = TempDir::new("snooze-store");
        let store = open_store(&temp);

        store
            .upsert_snooze("<a@x>", "INBOX", Some(7), Some(3), 2_000, 500)
            .unwrap();
        // Reponer: misma identidad, hora y UID nuevos, una sola fila.
        store
            .upsert_snooze("<a@x>", "INBOX", None, None, 3_000, 600)
            .unwrap();

        let rows = list_snoozed(store.connection()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].return_at, 3_000);
        assert_eq!((rows[0].new_uid, rows[0].uidvalidity), (None, None));

        assert!(store.delete_snooze("<a@x>").unwrap());
        assert!(!store.delete_snooze("<a@x>").unwrap());
        assert!(list_snoozed(store.connection()).unwrap().is_empty());
    }
}
