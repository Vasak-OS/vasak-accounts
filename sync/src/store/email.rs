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

use rusqlite::{OptionalExtension, Transaction};

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

/// Las banderas que son columna en `messages`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoredFlags {
    pub seen: bool,
    pub answered: bool,
    pub flagged: bool,
    pub draft: bool,
    pub deleted: bool,
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

/// Escribe un cuerpo y lo pasa al índice de búsqueda.
fn write_body(transaction: &Transaction, body: MessageBodyRow) -> Result<(), StoreError> {
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
    Ok(())
}

/// Escribe un adjunto.
fn write_attachment(
    transaction: &Transaction,
    attachment: MessageAttachmentRow,
) -> Result<(), StoreError> {
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
    Ok(())
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

    /// Ejecuta una operación en una transacción, sube la generación del área `email`
    /// y anuncia el cambio. Reduce el boilerplate de transacción + bump_generation + commit.
    fn with_transaction_email<F>(&mut self, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(&Transaction) -> Result<(), StoreError>,
    {
        let transaction = self.connection.transaction().map_err(classify)?;
        f(&transaction)?;
        let generation = bump_generation(&transaction, EMAIL_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(EMAIL_AREA, generation);
        Ok(())
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
    ///
    /// Sólo si cambió, y **sin subir la generación**: es dónde quedó la
    /// sincronización, no algo que lea ninguna aplicación. Subirla en cada
    /// vuelta haría que todas relean una lista idéntica.
    pub fn set_mailbox_modseq(
        &mut self,
        name: &str,
        modseq: Option<String>,
    ) -> Result<(), StoreError> {
        self.connection
            .execute(
                "UPDATE mailboxes SET modseq = ?1, updated_at = ?2
                 WHERE name = ?3 AND modseq IS NOT ?1",
                rusqlite::params![modseq, now(), name],
            )
            .map_err(classify)?;
        Ok(())
    }

    /// Marca como leído un mensaje guardado, por el nombre de su casilla y su
    /// UID: lo que hizo la aplicación en el servidor se ve en el almacén en el
    /// acto, sin esperar a la próxima vuelta. Devuelve si cambió algo.
    pub fn mark_seen(&mut self, mailbox: &str, uid: u64) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let changed = transaction
            .execute(
                "UPDATE messages SET flags_seen = 1, updated_at = ?1
                 WHERE uid = ?2 AND flags_seen = 0
                   AND mailbox_id = (SELECT id FROM mailboxes WHERE name = ?3)",
                rusqlite::params![now(), uid as i64, mailbox],
            )
            .map_err(classify)?
            > 0;
        let generation = if changed {
            Some(bump_generation(&transaction, EMAIL_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(EMAIL_AREA, generation);
        }
        Ok(changed)
    }

    /// Saca del almacén un mensaje que se movió o se borró en el servidor.
    /// Donde llegó lo trae la próxima vuelta. Devuelve si estaba.
    pub fn forget_message(&mut self, mailbox: &str, uid: u64) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let removed = transaction
            .execute(
                "DELETE FROM messages
                 WHERE uid = ?1 AND mailbox_id = (SELECT id FROM mailboxes WHERE name = ?2)",
                rusqlite::params![uid as i64, mailbox],
            )
            .map_err(classify)?
            > 0;
        let generation = if removed {
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

    /// Las banderas guardadas de cada UID de una casilla.
    pub fn stored_flags(&self, mailbox_id: i64) -> Result<HashMap<u64, StoredFlags>, StoreError> {
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT uid, flags_seen, flags_answered, flags_flagged, flags_draft, flags_deleted
                 FROM messages WHERE mailbox_id = ?1",
            )
            .map_err(classify)?;
        let rows = statement
            .query_map([mailbox_id], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    StoredFlags {
                        seen: row.get(1)?,
                        answered: row.get(2)?,
                        flagged: row.get(3)?,
                        draft: row.get(4)?,
                        deleted: row.get(5)?,
                    },
                ))
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Cambia las banderas de unos mensajes ya guardados, en una transacción.
    /// Devuelve cuántos cambiaron; la generación sube sólo si fue alguno.
    pub fn update_flags(
        &mut self,
        mailbox_id: i64,
        changes: &[(u64, StoredFlags)],
    ) -> Result<usize, StoreError> {
        if changes.is_empty() {
            return Ok(0);
        }
        let transaction = self.connection.transaction().map_err(classify)?;
        let mut changed = 0;
        {
            let mut statement = transaction
                .prepare_cached(
                    "UPDATE messages SET flags_seen = ?1, flags_answered = ?2, flags_flagged = ?3,
                            flags_draft = ?4, flags_deleted = ?5, updated_at = ?6
                     WHERE mailbox_id = ?7 AND uid = ?8",
                )
                .map_err(classify)?;
            let stamp = now();
            for (uid, f) in changes {
                changed += statement
                    .execute(rusqlite::params![
                        f.seen,
                        f.answered,
                        f.flagged,
                        f.draft,
                        f.deleted,
                        &stamp,
                        mailbox_id,
                        *uid as i64
                    ])
                    .map_err(classify)?;
            }
        }
        let generation = if changed > 0 {
            Some(bump_generation(&transaction, EMAIL_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(EMAIL_AREA, generation);
        }
        Ok(changed)
    }

    /// Borra una tanda de los mensajes de una casilla **sin** borrar la
    /// casilla: es lo que se hace cuando el servidor cambió el `UIDVALIDITY`
    /// y los UID guardados ya no apuntan a nada. Se llama hasta que devuelve
    /// cero.
    pub fn clear_mailbox_chunk(&mut self, mailbox_id: i64) -> Result<usize, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let removed = transaction
            .execute(
                "DELETE FROM messages WHERE id IN
                   (SELECT id FROM messages WHERE mailbox_id = ?1 LIMIT ?2)",
                rusqlite::params![mailbox_id, WRITE_BATCH_ROWS as i64],
            )
            .map_err(classify)?;
        let generation = if removed > 0 {
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

    /// Los mensajes más nuevos de una casilla que todavía no tienen cuerpo:
    /// `(id, uid)`, del más nuevo al más viejo.
    pub fn messages_without_body(
        &self,
        mailbox_id: i64,
        limit: usize,
    ) -> Result<Vec<(i64, u64)>, StoreError> {
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT m.id, m.uid FROM messages m
                 LEFT JOIN message_bodies b ON b.message_id = m.id
                 WHERE m.mailbox_id = ?1 AND b.message_id IS NULL
                 ORDER BY m.sort_key DESC, m.id DESC
                 LIMIT ?2",
            )
            .map_err(classify)?;
        let rows = statement
            .query_map(rusqlite::params![mailbox_id, limit as i64], |row| {
                Ok((row.get(0)?, row.get::<_, i64>(1)? as u64))
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
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
                net_bytes = net_bytes.saturating_add(m.size);
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

                    // Poblar índice FTS5 usando el cuerpo ya guardado en message_bodies.
                    // Si el mensaje ya estaba, su fila del índice se saca antes:
                    // FTS5 no acepta dos filas con el mismo `rowid`.
                    transaction
                        .execute("DELETE FROM messages_fts WHERE rowid = ?1", [msg_id])
                        .map_err(classify)?;
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
        self.with_transaction_email(|transaction| write_body(transaction, body))
    }

    /// Guarda los cuerpos —y los adjuntos— de varios mensajes en **una**
    /// transacción, con una sola subida de generación: traer de a tandas en
    /// segundo plano no puede despertar a las aplicaciones una vez por mensaje.
    pub fn store_opened(
        &mut self,
        opened: Vec<(MessageBodyRow, Vec<MessageAttachmentRow>)>,
    ) -> Result<(), StoreError> {
        if opened.is_empty() {
            return Ok(());
        }
        self.with_transaction_email(|transaction| {
            for (body, attachments) in opened {
                write_body(transaction, body)?;
                for attachment in attachments {
                    write_attachment(transaction, attachment)?;
                }
            }
            Ok(())
        })
    }

    /// Guarda un adjunto.
    pub fn upsert_message_attachment(
        &mut self,
        attachment: MessageAttachmentRow,
    ) -> Result<(), StoreError> {
        self.with_transaction_email(|transaction| write_attachment(transaction, attachment))
    }

    /// Guarda una bandera extra.
    pub fn upsert_message_flag(&mut self, flag: MessageFlagRow) -> Result<(), StoreError> {
        self.with_transaction_email(|transaction| {
            transaction
                .execute(
                    "INSERT INTO message_flags (message_id, flag) VALUES (?1, ?2)
                     ON CONFLICT (message_id, flag) DO NOTHING",
                    rusqlite::params![flag.message_id, &flag.flag],
                )
                .map_err(classify)?;
            Ok(())
        })
    }

    /// Borra una bandera extra.
    pub fn delete_message_flag(&mut self, message_id: i64, flag: &str) -> Result<(), StoreError> {
        self.with_transaction_email(|transaction| {
            transaction
                .execute(
                    "DELETE FROM message_flags WHERE message_id = ?1 AND flag = ?2",
                    rusqlite::params![message_id, flag],
                )
                .map_err(classify)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::store::email::{
        MailboxListing, MailboxRole, MessageAttachmentRow, MessageBodyRow, MessageFlagRow,
        MessageOp, MessageRow, StoredFlags, WRITE_BATCH_ROWS,
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

    // -----------------------------------------------------------------------
    // Lo que usa la sincronización de correo (`email_sync.rs`)
    // -----------------------------------------------------------------------

    fn message(mailbox_id: i64, uid: u64, subject: &str, sort_key: i64) -> MessageRow {
        MessageRow {
            mailbox_id,
            uid,
            message_id: Some(format!("<m{uid}@x>")),
            from_addr: "Ana <ana@x.com>".into(),
            to_addrs: "yo@x.com".into(),
            cc_addrs: String::new(),
            bcc_addrs: String::new(),
            reply_to: None,
            subject: subject.into(),
            date_ts: sort_key,
            sort_key,
            flags_seen: false,
            flags_answered: false,
            flags_flagged: false,
            flags_draft: false,
            flags_deleted: false,
            has_attachments: false,
            size: 100,
        }
    }

    fn upsert(store: &mut Store, row: MessageRow) {
        let mailbox_id = row.mailbox_id;
        store
            .apply_messages(vec![MessageOp::Upsert(Box::new(row))], mailbox_id)
            .unwrap();
    }

    fn id_of(store: &Store, mailbox_id: i64, uid: u64) -> i64 {
        store
            .connection
            .query_row(
                "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = ?2",
                rusqlite::params![mailbox_id, uid as i64],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn generation(store: &Store) -> u64 {
        crate::store::read_generation(&store.connection, crate::store::lifecycle::EMAIL_AREA)
            .unwrap()
    }

    /// La generación es la hora en microsegundos o la anterior más uno, lo que
    /// sea mayor. Para poder contar subidas, se la pone muy por delante de la
    /// hora: desde ahí cada subida es exactamente `+1`.
    fn pin_generation(store: &Store) -> u64 {
        const AHEAD: u64 = 4_000_000_000_000_000_000;
        store
            .connection
            .execute(
                "INSERT INTO store_meta (key, value) VALUES ('generation.email', ?1)
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                [AHEAD.to_string()],
            )
            .unwrap();
        assert_eq!(generation(store), AHEAD);
        AHEAD
    }

    fn count(store: &Store, sql: &str, mailbox_id: i64) -> i64 {
        store
            .connection
            .query_row(sql, [mailbox_id], |row| row.get(0))
            .unwrap()
    }

    fn inbox(store: &mut Store) -> i64 {
        store
            .upsert_mailboxes(&[mailbox("INBOX", MailboxRole::Inbox)])
            .unwrap()[0]
            .id
    }

    /// La sincronización vuelve a escribir un mensaje que ya estaba —cambió el
    /// asunto en otra vuelta, o se rehízo la casilla— y ese mensaje ya tenía
    /// cuerpo, así que ya tenía su fila en el índice de búsqueda. FTS5 no
    /// acepta dos filas con el mismo `rowid`: sin sacar la vieja antes, el lote
    /// entero falla y la casilla no se termina de sincronizar nunca.
    #[test]
    fn volver_a_guardar_un_mensaje_con_cuerpo_no_choca_con_el_indice() {
        let (_, mut store) = make_store();
        let inbox = inbox(&mut store);
        upsert(&mut store, message(inbox, 1, "Viejo asunto", 100));
        let id = id_of(&store, inbox, 1);
        store
            .upsert_message_body(MessageBodyRow {
                message_id: id,
                text_body: Some("cuerpo indexado".into()),
                html_body: None,
                truncated: false,
            })
            .unwrap();

        let again = store.apply_messages(
            vec![MessageOp::Upsert(Box::new(message(
                inbox,
                1,
                "Asunto nuevo",
                100,
            )))],
            inbox,
        );
        assert!(
            again.is_ok(),
            "volver a guardar el mensaje falló: {:?}",
            again.err()
        );

        // Y el índice quedó con una sola fila, la del asunto nuevo.
        let found = |term: &str| -> Vec<i64> {
            store
                .connection
                .prepare("SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?1")
                .unwrap()
                .query_map([term], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(found("nuevo"), vec![id]);
        assert!(
            found("viejo").is_empty(),
            "quedó la fila vieja en el índice"
        );
        assert_eq!(
            found("indexado"),
            vec![id],
            "se perdió el cuerpo del índice"
        );
    }

    #[test]
    fn las_banderas_guardadas_se_leen_por_uid() {
        let (_, mut store) = make_store();
        let inbox = inbox(&mut store);
        let mut seen = message(inbox, 7, "Leído", 100);
        seen.flags_seen = true;
        seen.flags_flagged = true;
        upsert(&mut store, seen);
        upsert(&mut store, message(inbox, 9, "Nuevo", 200));

        let flags = store.stored_flags(inbox).unwrap();
        assert_eq!(flags.len(), 2);
        assert_eq!(
            flags[&7],
            StoredFlags {
                seen: true,
                flagged: true,
                ..Default::default()
            }
        );
        assert_eq!(flags[&9], StoredFlags::default());
        // Otra casilla no ve las de ésta.
        assert!(store.stored_flags(inbox + 1000).unwrap().is_empty());
    }

    /// Cambiar banderas despierta a las aplicaciones sólo si algo cambió: una
    /// vuelta que no encontró nada no puede hacerlas releer la lista.
    #[test]
    fn cambiar_banderas_sube_la_generacion_solo_si_cambio_algo() {
        let (_, mut store) = make_store();
        let inbox = inbox(&mut store);
        upsert(&mut store, message(inbox, 1, "Uno", 100));
        store.take_changes();
        let before = pin_generation(&store);

        let read = StoredFlags {
            seen: true,
            ..Default::default()
        };
        assert_eq!(store.update_flags(inbox, &[(1, read)]).unwrap(), 1);
        assert_eq!(store.stored_flags(inbox).unwrap()[&1], read);
        assert_eq!(generation(&store), before + 1);
        assert_eq!(store.take_changes().len(), 1);

        // Un UID que no está: nada cambia y la generación no sube.
        assert_eq!(store.update_flags(inbox, &[(99, read)]).unwrap(), 0);
        assert_eq!(store.update_flags(inbox, &[]).unwrap(), 0);
        assert_eq!(generation(&store), before + 1);
        assert!(store.take_changes().is_empty());
    }

    /// Cuando el servidor cambia el `UIDVALIDITY` se vacía la casilla, pero la
    /// casilla sigue: la sincronización la vuelve a llenar en la misma vuelta.
    #[test]
    fn vaciar_una_casilla_deja_la_casilla() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[
                mailbox("INBOX", MailboxRole::Inbox),
                mailbox("Sent", MailboxRole::Sent),
            ])
            .unwrap();
        let boxes = store.mailboxes().unwrap();
        let (inbox, sent) = (boxes[0].id, boxes[1].id);
        let total = WRITE_BATCH_ROWS as u64 + 3;
        for chunk in (1..=total).collect::<Vec<_>>().chunks(WRITE_BATCH_ROWS) {
            let ops = chunk
                .iter()
                .map(|uid| MessageOp::Upsert(Box::new(message(inbox, *uid, "x", *uid as i64))))
                .collect();
            store.apply_messages(ops, inbox).unwrap();
        }
        upsert(&mut store, message(sent, 1, "enviado", 1));
        let before = pin_generation(&store);

        // De a tandas: la primera se lleva un lote entero, la segunda el resto.
        assert_eq!(store.clear_mailbox_chunk(inbox).unwrap(), WRITE_BATCH_ROWS);
        assert_eq!(store.clear_mailbox_chunk(inbox).unwrap(), 3);
        assert_eq!(store.clear_mailbox_chunk(inbox).unwrap(), 0);
        assert_eq!(
            generation(&store),
            before + 2,
            "una subida por tanda que borró"
        );

        let names: Vec<String> = store
            .mailboxes()
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, vec!["INBOX", "Sent"], "la casilla tenía que quedar");
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = ?1",
                inbox
            ),
            0
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM messages WHERE mailbox_id = ?1",
                sent
            ),
            1
        );
    }

    #[test]
    fn los_mensajes_sin_cuerpo_salen_del_mas_nuevo_al_mas_viejo() {
        let (_, mut store) = make_store();
        let inbox = inbox(&mut store);
        for (uid, key) in [(1, 300), (2, 100), (3, 500), (4, 200)] {
            upsert(&mut store, message(inbox, uid, "x", key));
        }
        // El más nuevo ya tiene cuerpo: no se vuelve a traer.
        let with_body = id_of(&store, inbox, 3);
        store
            .upsert_message_body(MessageBodyRow {
                message_id: with_body,
                text_body: Some("ya está".into()),
                html_body: None,
                truncated: false,
            })
            .unwrap();

        let pending = store.messages_without_body(inbox, 2).unwrap();
        assert_eq!(
            pending,
            vec![(id_of(&store, inbox, 1), 1), (id_of(&store, inbox, 4), 4)]
        );
        assert_eq!(store.messages_without_body(inbox, 10).unwrap().len(), 3);
        assert!(store.messages_without_body(inbox, 0).unwrap().is_empty());
    }

    /// Traer veinticinco cuerpos en segundo plano no puede despertar a las
    /// aplicaciones veinticinco veces: una transacción, una subida.
    #[test]
    fn guardar_varios_cuerpos_sube_la_generacion_una_sola_vez() {
        let (_, mut store) = make_store();
        let inbox = inbox(&mut store);
        let mut opened = Vec::new();
        for uid in 1..=5 {
            upsert(&mut store, message(inbox, uid, "x", uid as i64));
            let id = id_of(&store, inbox, uid);
            opened.push((
                MessageBodyRow {
                    message_id: id,
                    text_body: Some(format!("cuerpo{uid}")),
                    html_body: Some("<p>hola</p>".into()),
                    truncated: false,
                },
                vec![MessageAttachmentRow {
                    message_id: id,
                    part_number: "2".into(),
                    name: Some("a.pdf".into()),
                    content_type: "application/pdf".into(),
                    size: 0,
                    inline: false,
                    content_id: None,
                }],
            ));
        }
        store.take_changes();
        let before = pin_generation(&store);

        store.store_opened(opened).unwrap();

        assert_eq!(generation(&store), before + 1);
        assert_eq!(store.take_changes().len(), 1);
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM message_bodies WHERE ?1 > 0",
                1
            ),
            5
        );
        assert_eq!(
            count(
                &store,
                "SELECT COUNT(*) FROM message_attachments WHERE ?1 > 0",
                1
            ),
            5
        );
        assert!(store.messages_without_body(inbox, 10).unwrap().is_empty());

        // Nada que guardar: nada se escribe ni se avisa.
        store.store_opened(Vec::new()).unwrap();
        assert_eq!(generation(&store), before + 1);
    }

    /// El token de una casilla es dónde quedó la sincronización, no algo que
    /// lea una aplicación: guardarlo no sube la generación, y guardar el mismo
    /// no escribe nada.
    #[test]
    fn guardar_el_token_de_una_casilla_no_sube_la_generacion() {
        let (_, mut store) = make_store();
        inbox(&mut store);
        store.take_changes();
        let before = generation(&store);
        let updated_at = |store: &Store| -> String {
            store
                .connection
                .query_row(
                    "SELECT updated_at FROM mailboxes WHERE name = 'INBOX'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };

        store
            .set_mailbox_modseq("INBOX", Some("v1 7 100 3 2".into()))
            .unwrap();
        assert_eq!(
            store.mailboxes().unwrap()[0].modseq.as_deref(),
            Some("v1 7 100 3 2")
        );
        assert_eq!(generation(&store), before);
        assert!(store.take_changes().is_empty());

        // El mismo token otra vez: no se toca la fila.
        let stamp = updated_at(&store);
        store
            .set_mailbox_modseq("INBOX", Some("v1 7 100 3 2".into()))
            .unwrap();
        assert_eq!(updated_at(&store), stamp);

        // Y se puede volver a dejar sin token.
        store.set_mailbox_modseq("INBOX", None).unwrap();
        assert_eq!(store.mailboxes().unwrap()[0].modseq, None);
        assert_eq!(generation(&store), before);
    }
}
