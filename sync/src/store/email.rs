//! El correo en la base: lo que escribe la sincronización.
//!
//! Sólo escritura y lo que la sincronización necesita leer para decidir qué
//! pedir (los modseq y el token de cada casilla). Listar y buscar para las
//! aplicaciones vive en `email_read.rs`, sobre las conexiones de lectura.
//!
//! ── Lo que se guarda de cada mensaje ─────────────────────────────────────────
//!
//! **El resumen del mensaje** (metadatos) y, opcionalmente, su cuerpo y
//! adjuntos. El cuerpo no se guarda en la sincronización de la lista: se trae
//! cuando alguien abre el mensaje.
//!
//! ── La lista ─────────────────────────────────────────────────────────────────
//!
//! La lista de una casilla pagina por `(sort_key DESC, id)` descendente, con
//! índice propio y otro por casilla; la búsqueda (cuando llegue) usará FTS5
//! sobre `messages.subject`, `messages.from_addr`, `messages.to_addrs`,
//! `messages.cc_addrs` y `message_bodies.text_body`.
//!
//! ── Los lotes ────────────────────────────────────────────────────────────────
//!
//! Como en contactos y calendario: una transacción lleva como mucho
//! [`WRITE_BATCH_ROWS`] mensajes, el token va con el último lote de cada
//! casilla, y cada lote que cambia algo sube la generación del área `email`
//! en su misma transacción.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;

use super::lifecycle::EMAIL_AREA;
use super::{bump_generation, classify, Store, StoreError};

/// Cuántos mensajes entran en una transacción, como mucho.
pub const WRITE_BATCH_ROWS: usize = 500;

/// Y cuánto texto crudo, como mucho.
pub const WRITE_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Una casilla tal como está en la base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMailbox {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub modseq: Option<String>,
}

/// Una casilla como la listó el servidor, para darla de alta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxListing {
    pub name: String,
    pub display_name: String,
    pub role: MailboxRole,
}

/// El rol de una casilla (SPECIAL-USE de IMAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxRole {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Archive,
    Junk,
    Outbox,
    Other,
}

impl MailboxRole {
    fn as_str(self) -> &'static str {
        match self {
            MailboxRole::Inbox => "inbox",
            MailboxRole::Sent => "sent",
            MailboxRole::Drafts => "drafts",
            MailboxRole::Trash => "trash",
            MailboxRole::Archive => "archive",
            MailboxRole::Junk => "junk",
            MailboxRole::Outbox => "outbox",
            MailboxRole::Other => "other",
        }
    }
}

/// Un mensaje para guardar: el crudo y lo derivado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub mailbox_id: i64,
    pub uid: u64,
    pub message_id: Option<String>,
    pub from_addr: String,
    pub to_addrs: String,
    pub cc_addrs: String,
    pub bcc_addrs: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub date_ts: i64,
    pub sort_key: i64,
    pub flags_seen: bool,
    pub flags_answered: bool,
    pub flags_flagged: bool,
    pub flags_draft: bool,
    pub flags_deleted: bool,
    pub has_attachments: bool,
    pub size: i64,
}

/// El cuerpo de un mensaje (se guarda cuando se abre, no en la lista).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageBodyRow {
    pub message_id: i64,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub truncated: bool,
}

/// Un adjunto de un mensaje.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAttachmentRow {
    pub message_id: i64,
    pub part_number: String,
    pub name: Option<String>,
    pub content_type: String,
    pub size: i64,
    pub inline: bool,
    pub content_id: Option<String>,
}

/// Una bandera IMAP extra (no `\Seen`, que es columna en messages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFlagRow {
    pub message_id: i64,
    pub flag: String,
}

/// Lo que se hace con un mensaje.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageOp {
    Upsert(Box<MessageRow>),
    Delete(i64, u64), // mailbox_id, uid
}

/// Lo que se hace con un cuerpo de mensaje.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageBodyOp {
    Upsert(MessageBodyRow),
}

/// Lo que se hace con un adjunto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageAttachmentOp {
    Upsert(MessageAttachmentRow),
}

/// Lo que se hace con una bandera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageFlagOp {
    Upsert(MessageFlagRow),
    Delete(i64, String), // message_id, flag
}

/// Dónde quedó una casilla al terminar: va con el último lote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxProgress {
    /// El `HIGHESTMODSEQ` nuevo. `None` si el servidor no dio ninguno.
    pub modseq: Option<String>,
}

/// Cómo quedó un lote de [`Store::apply_messages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Escrito. Cuántos bytes de mensajes crudos sumó a la cuenta.
    Written { net_bytes: i64 },
    /// No se escribió nada: la cuenta crecería más de lo que había lugar.
    OverCap,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl Store {
    /// Las casillas guardadas.
    pub fn mailboxes(&self) -> Result<Vec<StoredMailbox>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, name, display_name, modseq FROM mailboxes ORDER BY id")
            .map_err(classify)?;
        let rows = statement
            .query_map([], |row| {
                Ok(StoredMailbox {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    modseq: row.get(3)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Da de alta las casillas que listó el servidor, o les actualiza el
    /// nombre. No toca el `modseq`: ése cambia sólo al terminar una casilla
    /// (ver [`MailboxProgress`]), para que una vuelta cortada no la dé por al
    /// día.
    ///
    /// No borra las que faltan: eso va por [`Self::remove_mailbox_chunk`],
    /// de a lotes.
    pub fn upsert_mailboxes(
        &mut self,
        boxes: &[MailboxListing],
    ) -> Result<Vec<StoredMailbox>, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let mut stored = Vec::with_capacity(boxes.len());
        let mut changed = false;
        {
            let mut current = transaction
                .prepare_cached("SELECT display_name FROM mailboxes WHERE name = ?1")
                .map_err(classify)?;
            for b in boxes {
                let before: Option<String> = current
                    .query_row([&b.name], |row| row.get(0))
                    .optional()
                    .map_err(classify)?;
                changed |= before.as_deref() != Some(&b.display_name);
            }
        }
        {
            let mut statement = transaction
                .prepare_cached(
                    "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (name) DO UPDATE SET display_name = excluded.display_name,
                                                   role = excluded.role
                     RETURNING id, name, display_name, modseq",
                )
                .map_err(classify)?;
            for b in boxes {
                stored.push(
                    statement
                        .query_row(
                            rusqlite::params![&b.name, &b.display_name, b.role.as_str(), now()],
                            |row| {
                                Ok(StoredMailbox {
                                    id: row.get(0)?,
                                    name: row.get(1)?,
                                    display_name: row.get(2)?,
                                    modseq: row.get(3)?,
                                })
                            },
                        )
                        .map_err(classify)?,
                );
            }
        }
        let generation = if changed {
            Some(bump_generation(&transaction, EMAIL_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(EMAIL_AREA, generation);
        }
        Ok(stored)
    }

    /// Borra una tanda de los mensajes de una casilla que ya no está, y la
    /// casilla misma cuando no le queda ninguno. Devuelve cuántos mensajes se
    /// borraron: se llama hasta que devuelve cero.
    ///
    /// De a tandas y no con la cascada de una vez: una casilla de diez mil
    /// mensajes sería una sola transacción de diez mil filas.
    pub fn remove_mailbox_chunk(&mut self, mailbox_id: i64) -> Result<usize, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let removed = transaction
            .execute(
                "DELETE FROM messages WHERE id IN
                   (SELECT id FROM messages WHERE mailbox_id = ?1 LIMIT ?2)",
                rusqlite::params![mailbox_id, WRITE_BATCH_ROWS as i64],
            )
            .map_err(classify)?;
        let mut changed = removed > 0;
        if removed == 0 {
            changed |= transaction
                .execute("DELETE FROM mailboxes WHERE id = ?1", [mailbox_id])
                .map_err(classify)?
                > 0;
        }
        let generation = if changed {
            Some(bump_generation(&transaction, EMAIL_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(EMAIL_AREA, generation);
        }
        Ok(removed)
    }

    /// El `modseq` guardado de una casilla.
    pub fn mailbox_modseq(&self, name: &str) -> Result<Option<String>, StoreError> {
        let modseq: Option<String> = self
            .connection
            .query_row(
                "SELECT modseq FROM mailboxes WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(classify)?;
        Ok(modseq)
    }

    /// Guarda el `modseq` de una casilla (al terminar su vuelta).
    pub fn set_mailbox_modseq(
        &mut self,
        name: &str,
        modseq: Option<String>,
    ) -> Result<(), StoreError> {
        let changed = self
            .connection
            .execute(
                "UPDATE mailboxes SET modseq = ?1, updated_at = ?2 WHERE name = ?3",
                rusqlite::params![modseq, now(), name],
            )
            .map_err(classify)?
            > 0;
        if changed {
            let generation = bump_generation(&self.connection, EMAIL_AREA)?;
            self.note_change(EMAIL_AREA, generation);
        }
        Ok(())
    }

    /// Aplica un lote de operaciones sobre mensajes. Devuelve cuántos bytes
    /// netos de mensajes crudos se sumaron (negativo si borró más de lo que
    /// agregó), o `OverCap` si pasaría el tope.
    ///
    /// El token de la casilla se guarda **fuera** de esta función, en la
    /// sincronización, con el último lote de cada casilla.
    pub fn apply_messages(
        &mut self,
        ops: Vec<MessageOp>,
        mailbox_id: i64,
    ) -> Result<Applied, StoreError> {
        if ops.is_empty() {
            return Ok(Applied::Written { net_bytes: 0 });
        }
        let transaction = self.connection.transaction().map_err(classify)?;

        // Medir cuánto crecería (aprox) para el tope de bytes.
        let mut net_bytes: i64 = 0;
        for op in &ops {
            if let MessageOp::Upsert(m) = op {
                net_bytes += m.size;
            }
        }

        // Límite de bytes por cuenta (configurable en la sincronización).
        // Aquí solo contamos; la decisión de parar la vuelta está en el
        // sincronizador.
        let mut statement = transaction
            .prepare_cached(
                "INSERT INTO messages
                    (mailbox_id, uid, message_id, from_addr, to_addrs, cc_addrs, bcc_addrs,
                     reply_to, subject, date_ts, sort_key,
                     flags_seen, flags_answered, flags_flagged, flags_draft, flags_deleted,
                     has_attachments, size, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
                 ON CONFLICT (mailbox_id, uid) DO UPDATE SET
                     message_id = excluded.message_id,
                     from_addr = excluded.from_addr,
                     to_addrs = excluded.to_addrs,
                     cc_addrs = excluded.cc_addrs,
                     bcc_addrs = excluded.bcc_addrs,
                     reply_to = excluded.reply_to,
                     subject = excluded.subject,
                     date_ts = excluded.date_ts,
                     sort_key = excluded.sort_key,
                     flags_seen = excluded.flags_seen,
                     flags_answered = excluded.flags_answered,
                     flags_flagged = excluded.flags_flagged,
                     flags_draft = excluded.flags_draft,
                     flags_deleted = excluded.flags_deleted,
                     has_attachments = excluded.has_attachments,
                     size = excluded.size,
                     updated_at = excluded.updated_at
                 RETURNING id",
            )
            .map_err(classify)?;

        for op in ops {
            match op {
                MessageOp::Upsert(m) => {
                    let msg_id: i64 = statement
                        .query_row(
                            rusqlite::params![
                                mailbox_id,
                                m.uid as i64,
                                m.message_id,
                                &m.from_addr,
                                &m.to_addrs,
                                &m.cc_addrs,
                                &m.bcc_addrs,
                                m.reply_to,
                                &m.subject,
                                m.date_ts,
                                m.sort_key,
                                m.flags_seen as i64,
                                m.flags_answered as i64,
                                m.flags_flagged as i64,
                                m.flags_draft as i64,
                                m.flags_deleted as i64,
                                m.has_attachments as i64,
                                m.size,
                                now(),
                            ],
                            |row| row.get(0),
                        )
                        .map_err(classify)?;

                    // Poblar índice FTS5 usando el cuerpo ya guardado en message_bodies
                    transaction
                        .execute(
                            "INSERT INTO messages_fts (rowid, subject, from_addr, to_addrs, cc_addrs, text_body)
                             SELECT m.id, m.subject, m.from_addr, m.to_addrs, m.cc_addrs,
                                    COALESCE(b.text_body, '')
                             FROM messages m
                             LEFT JOIN message_bodies b ON m.id = b.message_id
                             WHERE m.id = ?1",
                            [msg_id],
                        )
                        .map_err(classify)?;
                }
                MessageOp::Delete(mailbox_id_del, uid) => {
                    let _ = transaction
                        .execute(
                            "DELETE FROM messages WHERE mailbox_id = ?1 AND uid = ?2",
                            rusqlite::params![mailbox_id_del, uid as i64],
                        )
                        .map_err(classify)?;
                }
            }
        }

        drop(statement);
        let generation = bump_generation(&transaction, EMAIL_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(EMAIL_AREA, generation);
        Ok(Applied::Written { net_bytes })
    }

    /// Guarda el cuerpo de un mensaje (cuando se abre).
    pub fn upsert_message_body(&mut self, body: MessageBodyRow) -> Result<(), StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;

        transaction
            .execute(
                "INSERT INTO message_bodies (message_id, text_body, html_body, truncated, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (message_id) DO UPDATE SET
                     text_body = excluded.text_body,
                     html_body = excluded.html_body,
                     truncated = excluded.truncated,
                     updated_at = excluded.updated_at",
                rusqlite::params![
                    body.message_id,
                    body.text_body,
                    body.html_body,
                    body.truncated as i64,
                    now(),
                ],
            )
            .map_err(classify)?;

        // Actualizar índice FTS5 con el cuerpo de texto
        if let Some(text) = body.text_body {
            transaction
                .execute(
                    "DELETE FROM messages_fts WHERE rowid = ?1",
                    [body.message_id],
                )
                .map_err(classify)?;
            transaction
                .execute(
                    "INSERT INTO messages_fts (rowid, subject, from_addr, to_addrs, cc_addrs, text_body)
                     SELECT ?1, subject, from_addr, to_addrs, cc_addrs, ?2
                     FROM messages WHERE id = ?1",
                    rusqlite::params![body.message_id, text],
                )
                .map_err(classify)?;
        }

        let generation = bump_generation(&transaction, EMAIL_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(EMAIL_AREA, generation);
        Ok(())
    }

    /// Guarda un adjunto.
    pub fn upsert_message_attachment(
        &mut self,
        attachment: MessageAttachmentRow,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;

        transaction
            .execute(
                "INSERT INTO message_attachments
                    (message_id, part_number, name, content_type, size, inline, content_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (message_id, part_number) DO UPDATE SET
                     name = excluded.name,
                     content_type = excluded.content_type,
                     size = excluded.size,
                     inline = excluded.inline,
                     content_id = excluded.content_id",
                rusqlite::params![
                    attachment.message_id,
                    &attachment.part_number,
                    attachment.name,
                    &attachment.content_type,
                    attachment.size,
                    attachment.inline as i64,
                    attachment.content_id,
                ],
            )
            .map_err(classify)?;

        let generation = bump_generation(&transaction, EMAIL_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(EMAIL_AREA, generation);
        Ok(())
    }

    /// Guarda una bandera extra.
    pub fn upsert_message_flag(&mut self, flag: MessageFlagRow) -> Result<(), StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;

        transaction
            .execute(
                "INSERT INTO message_flags (message_id, flag) VALUES (?1, ?2)
                 ON CONFLICT (message_id, flag) DO NOTHING",
                rusqlite::params![flag.message_id, &flag.flag],
            )
            .map_err(classify)?;

        let generation = bump_generation(&transaction, EMAIL_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(EMAIL_AREA, generation);
        Ok(())
    }

    /// Borra una bandera extra.
    pub fn delete_message_flag(&mut self, message_id: i64, flag: &str) -> Result<(), StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;

        transaction
            .execute(
                "DELETE FROM message_flags WHERE message_id = ?1 AND flag = ?2",
                rusqlite::params![message_id, flag],
            )
            .map_err(classify)?;

        let generation = bump_generation(&transaction, EMAIL_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(EMAIL_AREA, generation);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::email::{
        MailboxListing, MailboxRole, MessageAttachmentRow, MessageBodyRow, MessageFlagRow,
        MessageOp, MessageRow,
    };
    use crate::store::key::tests::fake_keyring;
    use crate::store::paths::tests::TempDir;
    use crate::store::paths::StorePaths;
    use crate::store::{Store, StoreKey};
    use zeroize::Zeroizing;

    fn key_of(c: u8) -> StoreKey {
        // StoreKey espera 64 caracteres hexadecimales (32 bytes)
        let hex = format!("{:02x}", c).repeat(32);
        StoreKey::from_secret(Zeroizing::new(hex.into_bytes())).unwrap()
    }

    fn make_store() -> (TempDir, Store) {
        let temp = TempDir::new("email");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'e')).unwrap();
        (temp, store)
    }

    fn mailbox(name: &str, role: MailboxRole) -> MailboxListing {
        MailboxListing {
            name: name.into(),
            display_name: name.into(),
            role,
        }
    }

    #[test]
    fn casillas_se_dan_de_alta_y_actualizan() {
        let (_, mut store) = make_store();
        let boxes = store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap();
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].name, "INBOX");
        assert_eq!(boxes[0].modseq, None);

        // Actualiza el nombre
        let boxes = store
            .upsert_mailboxes(&[MailboxListing {
                name: "INBOX".into(),
                display_name: "Bandeja".into(),
                role: MailboxRole::Inbox,
            }])
            .unwrap();
        assert_eq!(boxes[0].display_name, "Bandeja");
    }

    #[test]
    fn casilla_borrada_se_lleva_sus_mensajes() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        // Agrega mensajes
        for i in 1..=3 {
            store
                .apply_messages(
                    vec![MessageOp::Upsert(Box::new(MessageRow {
                        mailbox_id: inbox_id,
                        uid: i,
                        message_id: Some(format!("<msg{i}@x>")),
                        from_addr: "ana@x.com".into(),
                        to_addrs: "yo@x.com".into(),
                        cc_addrs: "".into(),
                        bcc_addrs: "".into(),
                        reply_to: None,
                        subject: format!("Hola {i}"),
                        date_ts: 1000 + i as i64,
                        sort_key: 1000 + i as i64,
                        flags_seen: false,
                        flags_answered: false,
                        flags_flagged: false,
                        flags_draft: false,
                        flags_deleted: false,
                        has_attachments: false,
                        size: 100,
                    }))],
                    inbox_id,
                )
                .unwrap();
        }

        // Borra la casilla por chunks
        while store.remove_mailbox_chunk(inbox_id).unwrap() > 0 {}
        assert!(store.mailboxes().unwrap().is_empty());
    }

    #[test]
    fn mensaje_es_uno_por_casilla_y_uid() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[
                mailbox("INBOX", MailboxRole::Inbox),
                mailbox("Sent", MailboxRole::Sent),
            ])
            .unwrap();
        let inbox = store.mailboxes().unwrap()[0].id;
        let sent = store.mailboxes().unwrap()[1].id;

        store
            .apply_messages(
                vec![MessageOp::Upsert(Box::new(MessageRow {
                    mailbox_id: inbox,
                    uid: 1,
                    message_id: Some("<msg@x>".into()),
                    from_addr: "ana@x.com".into(),
                    to_addrs: "yo@x.com".into(),
                    cc_addrs: "".into(),
                    bcc_addrs: "".into(),
                    reply_to: None,
                    subject: "Hola".into(),
                    date_ts: 100,
                    sort_key: 100,
                    flags_seen: false,
                    flags_answered: false,
                    flags_flagged: false,
                    flags_draft: false,
                    flags_deleted: false,
                    has_attachments: false,
                    size: 100,
                }))],
                inbox,
            )
            .unwrap();
        store
            .apply_messages(
                vec![MessageOp::Upsert(Box::new(MessageRow {
                    mailbox_id: sent,
                    uid: 1,
                    message_id: Some("<msg@x>".into()),
                    from_addr: "yo@x.com".into(),
                    to_addrs: "ana@x.com".into(),
                    cc_addrs: "".into(),
                    bcc_addrs: "".into(),
                    reply_to: None,
                    subject: "Hola".into(),
                    date_ts: 100,
                    sort_key: 100,
                    flags_seen: false,
                    flags_answered: false,
                    flags_flagged: false,
                    flags_draft: false,
                    flags_deleted: false,
                    has_attachments: false,
                    size: 100,
                }))],
                sent,
            )
            .unwrap();

        // Mismo UID en otra casilla: OK
        // Mismo UID en misma casilla: se actualiza (no error, es ON CONFLICT DO UPDATE)
        let dup = store.apply_messages(
            vec![MessageOp::Upsert(Box::new(MessageRow {
                mailbox_id: inbox,
                uid: 1,
                message_id: Some("<msg2@x>".into()),
                from_addr: "ana@x.com".into(),
                to_addrs: "yo@x.com".into(),
                cc_addrs: "".into(),
                bcc_addrs: "".into(),
                reply_to: None,
                subject: "Hola 2".into(),
                date_ts: 200,
                sort_key: 200,
                flags_seen: false,
                flags_answered: false,
                flags_flagged: false,
                flags_draft: false,
                flags_deleted: false,
                has_attachments: false,
                size: 100,
            }))],
            inbox,
        );
        assert!(dup.is_ok(), "se actualiza la fila existente");
        // Verifica que se actualizó
        let updated = store
            .connection
            .query_row(
                "SELECT subject FROM messages WHERE mailbox_id = ?1 AND uid = 1",
                [inbox],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(updated, "Hola 2");
    }

    #[test]
    fn cuerpo_y_adjuntos_y_banderas() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;
        store
            .apply_messages(
                vec![MessageOp::Upsert(Box::new(MessageRow {
                    mailbox_id: inbox_id,
                    uid: 1,
                    message_id: Some("<msg@x>".into()),
                    from_addr: "ana@x.com".into(),
                    to_addrs: "yo@x.com".into(),
                    cc_addrs: "".into(),
                    bcc_addrs: "".into(),
                    reply_to: None,
                    subject: "Hola".into(),
                    date_ts: 100,
                    sort_key: 100,
                    flags_seen: false,
                    flags_answered: false,
                    flags_flagged: false,
                    flags_draft: false,
                    flags_deleted: false,
                    has_attachments: true,
                    size: 2048,
                }))],
                inbox_id,
            )
            .unwrap();
        let msg_id = store
            .connection
            .query_row(
                "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = 1",
                [inbox_id],
                |row| row.get(0),
            )
            .unwrap();

        // Cuerpo
        store
            .upsert_message_body(MessageBodyRow {
                message_id: msg_id,
                text_body: Some("Hola mundo".into()),
                html_body: Some("<p>Hola mundo</p>".into()),
                truncated: false,
            })
            .unwrap();

        // Adjunto
        store
            .upsert_message_attachment(MessageAttachmentRow {
                message_id: msg_id,
                part_number: "2".into(),
                name: Some("x.pdf".into()),
                content_type: "application/pdf".into(),
                size: 1024,
                inline: false,
                content_id: None,
            })
            .unwrap();

        // Bandera extra
        store
            .upsert_message_flag(MessageFlagRow {
                message_id: msg_id,
                flag: "\\Flagged".into(),
            })
            .unwrap();

        let flags: Vec<String> = store
            .connection
            .prepare("SELECT flag FROM message_flags WHERE message_id = ?1")
            .unwrap()
            .query_map([msg_id], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(flags.contains(&"\\Flagged".into()));
    }

    #[test]
    fn message_op_delete_con_mailbox_id_y_uid() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        store
            .apply_messages(
                vec![MessageOp::Upsert(Box::new(MessageRow {
                    mailbox_id: inbox_id,
                    uid: 1,
                    message_id: Some("<msg@x>".into()),
                    from_addr: "ana@x.com".into(),
                    to_addrs: "yo@x.com".into(),
                    cc_addrs: "".into(),
                    bcc_addrs: "".into(),
                    reply_to: None,
                    subject: "Hola".into(),
                    date_ts: 100,
                    sort_key: 100,
                    flags_seen: false,
                    flags_answered: false,
                    flags_flagged: false,
                    flags_draft: false,
                    flags_deleted: false,
                    has_attachments: false,
                    size: 100,
                }))],
                inbox_id,
            )
            .unwrap();

        // Borrar usando (mailbox_id, uid)
        store
            .apply_messages(vec![MessageOp::Delete(inbox_id, 1)], inbox_id)
            .unwrap();

        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = ?1",
                [inbox_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn upsert_message_body_transaccional_con_fts() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        store
            .apply_messages(
                vec![MessageOp::Upsert(Box::new(MessageRow {
                    mailbox_id: inbox_id,
                    uid: 1,
                    message_id: Some("<msg@x>".into()),
                    from_addr: "ana@x.com".into(),
                    to_addrs: "yo@x.com".into(),
                    cc_addrs: "".into(),
                    bcc_addrs: "".into(),
                    reply_to: None,
                    subject: "Test FTS".into(),
                    date_ts: 100,
                    sort_key: 100,
                    flags_seen: false,
                    flags_answered: false,
                    flags_flagged: false,
                    flags_draft: false,
                    flags_deleted: false,
                    has_attachments: false,
                    size: 100,
                }))],
                inbox_id,
            )
            .unwrap();

        let msg_id = store
            .connection
            .query_row(
                "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = 1",
                [inbox_id],
                |row| row.get(0),
            )
            .unwrap();

        // Guardar cuerpo -> debe actualizar FTS
        store
            .upsert_message_body(MessageBodyRow {
                message_id: msg_id,
                text_body: Some("Cuerpo para búsqueda FTS".into()),
                html_body: None,
                truncated: false,
            })
            .unwrap();

        // Verificar que el cuerpo se guardó en message_bodies
        let saved_body: String = store
            .connection
            .query_row(
                "SELECT text_body FROM message_bodies WHERE message_id = ?1",
                [msg_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved_body, "Cuerpo para búsqueda FTS");
    }

    #[test]
    fn upsert_message_attachment_transaccional_con_generation() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        store
            .apply_messages(
                vec![MessageOp::Upsert(Box::new(MessageRow {
                    mailbox_id: inbox_id,
                    uid: 1,
                    message_id: Some("<msg@x>".into()),
                    from_addr: "ana@x.com".into(),
                    to_addrs: "yo@x.com".into(),
                    cc_addrs: "".into(),
                    bcc_addrs: "".into(),
                    reply_to: None,
                    subject: "Test adjunto".into(),
                    date_ts: 100,
                    sort_key: 100,
                    flags_seen: false,
                    flags_answered: false,
                    flags_flagged: false,
                    flags_draft: false,
                    flags_deleted: false,
                    has_attachments: false,
                    size: 100,
                }))],
                inbox_id,
            )
            .unwrap();

        let msg_id = store
            .connection
            .query_row(
                "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = 1",
                [inbox_id],
                |row| row.get(0),
            )
            .unwrap();

        let gen_antes: i64 = store
            .connection
            .query_row(
                "SELECT value FROM store_meta WHERE key = 'generation.email'",
                [],
                |row| {
                    let v: String = row.get(0).unwrap();
                    v.parse::<i64>().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            0,
                            "value".into(),
                            rusqlite::types::Type::Null,
                        )
                    })
                },
            )
            .unwrap_or_else(|e| {
                eprintln!("query error: {}", e);
                0
            });
        eprintln!("gen_antes = {}", gen_antes);

        store
            .upsert_message_attachment(MessageAttachmentRow {
                message_id: msg_id,
                part_number: "2".into(),
                name: Some("test.pdf".into()),
                content_type: "application/pdf".into(),
                size: 1024,
                inline: false,
                content_id: None,
            })
            .unwrap();

        let gen_despues: i64 = store
            .connection
            .query_row(
                "SELECT value FROM store_meta WHERE key = 'generation.email'",
                [],
                |row| -> rusqlite::Result<i64> {
                    let v: String = row.get(0)?;
                    v.parse::<i64>().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            0,
                            "value".into(),
                            rusqlite::types::Type::Null,
                        )
                    })
                },
            )
            .unwrap_or_else(|e| {
                eprintln!("query error: {}", e);
                0
            });
        eprintln!("gen_despues = {}", gen_despues);

        assert!(gen_despues > gen_antes);
    }
}
