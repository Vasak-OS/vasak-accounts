//! Lecturas de correo para las aplicaciones: lista, busca y abre.
//!
//! Sobre las conexiones de **sólo lectura** del almacén ([`ReadPool`]). No toma
//! la cerradura del administrador: un lote de escritura largo no la hace
//! esperar, y ve lo último que se confirmó en WAL.
//!
//! ── Lo que se lee ────────────────────────────────────────────────────────────
//!
//! - **Casillas**: `ListMailboxes` — las casillas de la cuenta con su rol.
//! - **Mensajes**: `ListMessages` — una página de resúmenes por casilla, por
//!   `(sort_key DESC, id)`.
//! - **Búsqueda**: `SearchMessages` — FTS5 sobre asunto, remitente, destinatarios
//!   y cuerpo (texto plano).
//! - **Cuerpo**: `GetMessageBody` — el texto plano y el HTML saneado de un
//!   mensaje, con su bandera de truncado.
//! - **Adjuntos**: `ListAttachments` — los adjuntos de un mensaje.
//! - **Banderas**: `GetFlags` — las banderas extra de un mensaje.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use rusqlite::{OptionalExtension, Row};
use serde::Serialize;

use super::lifecycle::EMAIL_AREA;
use super::{classify, Store, StoreError};

/// El cursor estable para paginar: `(sort_key DESC, id)`.
///
/// Se codifica como `"<sort_key>:<id>"` en base64 URL-safe sin padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub sort_key: i64,
    pub id: i64,
}

impl Cursor {
    pub fn encode(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{}:{}", self.sort_key, self.id))
    }

    pub fn encode_decode(&self) -> (i64, i64) {
        (self.sort_key, self.id)
    }

    pub fn decode(text: &str) -> Result<Option<Self>, InvalidArgument> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| InvalidArgument("cursor inválido".into()))?;
        if bytes.is_empty() {
            return Ok(None);
        }
        let text =
            String::from_utf8(bytes).map_err(|_| InvalidArgument("cursor inválido".into()))?;
        let (sk, id) = text
            .split_once(':')
            .ok_or_else(|| InvalidArgument("cursor inválido".into()))?;
        Ok(Some(Self {
            sort_key: sk
                .parse()
                .map_err(|_| InvalidArgument("cursor inválido".into()))?,
            id: id
                .parse()
                .map_err(|_| InvalidArgument("cursor inválido".into()))?,
        }))
    }
}

/// Límite de página: 0 pide 100, nada pasa de 1000.
pub fn page_limit(limit: u32) -> usize {
    match limit {
        0 => 100,
        l if l > 1000 => 1000,
        l => l as usize,
    }
}

/// Tope de bytes de una página de respuesta (medido en JSON serializado).
pub const MAX_PAGE_BYTES: usize = 512 * 1024;

/// Tope de bytes de respuesta de lista (más grande que página individual).
pub const MAX_PAGE_REPLY_BYTES: usize = MAX_PAGE_BYTES * 2;

/// Tope de bytes de un mensaje individual (cuando se abre entero).
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Tope de bytes de la lista de casillas.
pub const MAX_MAILBOXES_BYTES: usize = 128 * 1024;

/// Lo que devuelve una página: items y `next_cursor` (`null` = fin).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Resumen de un mensaje (para la lista).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageSummary {
    pub id: i64,
    pub mailbox_id: i64,
    pub mailbox_name: String,
    pub uid: u64,
    pub message_id: Option<String>,
    pub from_addr: String,
    pub to_addrs: String,
    pub cc_addrs: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub date_ts: i64,
    pub flags_seen: bool,
    pub flags_answered: bool,
    pub flags_flagged: bool,
    pub flags_draft: bool,
    pub flags_deleted: bool,
    pub has_attachments: bool,
    pub size: i64,
}

/// Un mensaje entero (cuando se abre).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageFull {
    pub id: i64,
    pub mailbox_id: i64,
    pub mailbox_name: String,
    pub uid: u64,
    pub message_id: Option<String>,
    pub from_addr: String,
    pub to_addrs: String,
    pub cc_addrs: String,
    pub bcc_addrs: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub date_ts: i64,
    pub flags_seen: bool,
    pub flags_answered: bool,
    pub flags_flagged: bool,
    pub flags_draft: bool,
    pub flags_deleted: bool,
    pub has_attachments: bool,
    pub size: i64,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub truncated: bool,
    pub attachments: Vec<AttachmentSummary>,
    pub flags: Vec<String>,
}

/// Resumen de un adjunto.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttachmentSummary {
    pub part_number: String,
    pub name: Option<String>,
    pub content_type: String,
    pub size: i64,
    pub inline: bool,
    pub content_id: Option<String>,
}

/// Una casilla.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MailboxSummary {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub role: String,
}

/// Error de argumento inválido (viene de afuera: cursor, query, ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidArgument(pub String);

impl std::fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidArgument {}

impl InvalidArgument {
    fn query() -> Self {
        Self("consulta vacía, muy larga o con muchas palabras".into())
    }
}

impl Store {
    /// Las casillas de la cuenta.
    pub fn list_mailboxes(&self) -> Result<Vec<MailboxSummary>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, name, display_name, role FROM mailboxes ORDER BY
                CASE role
                    WHEN 'inbox' THEN 0
                    WHEN 'sent' THEN 1
                    WHEN 'drafts' THEN 2
                    WHEN 'trash' THEN 3
                    WHEN 'archive' THEN 4
                    WHEN 'junk' THEN 5
                    WHEN 'outbox' THEN 6
                    ELSE 7
                END, name",
            )
            .map_err(classify)?;
        let rows = statement
            .query_map([], |row| {
                Ok(MailboxSummary {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    display_name: row.get(2)?,
                    role: row.get(3)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Una página de mensajes de una casilla.
    ///
    /// `mailbox_id` 0 significa "todas las casillas" (para búsqueda global
    /// futura). `after` es el cursor devuelto por la página anterior.
    pub fn list_messages(
        &self,
        mailbox_id: i64,
        after: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page<MessageSummary>, StoreError> {
        let (sql, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if mailbox_id == 0 {
            // Todas las casillas (búsqueda global futura)
            if after.is_some() {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          WHERE (m.sort_key, m.id) < (?1, ?2)
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?3";
                let (sk, id) = after.unwrap().encode_decode();
                (
                    base.into(),
                    vec![Box::new(sk), Box::new(id), Box::new(limit as i64 + 1)],
                )
            } else {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?1";
                (base.into(), vec![Box::new(limit as i64 + 1)])
            }
        } else {
            if after.is_some() {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          WHERE m.mailbox_id = ?1
                            AND (m.sort_key, m.id) < (?2, ?3)
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?4";
                let (sk, id) = after.unwrap().encode_decode();
                (
                    base.into(),
                    vec![
                        Box::new(mailbox_id),
                        Box::new(sk),
                        Box::new(id),
                        Box::new(limit as i64 + 1),
                    ],
                )
            } else {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          WHERE m.mailbox_id = ?1
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?2";
                (
                    base.into(),
                    vec![Box::new(mailbox_id), Box::new(limit as i64 + 1)],
                )
            }
        };

        let mut statement = self.connection.prepare(&sql).map_err(classify)?;
        let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
        let mut rows = statement.query(&params_ref[..]).map_err(classify)?;

        let mut items = Vec::new();
        let mut last: Option<Cursor> = None;
        let mut has_more = false;
        while let Some(row) = rows.next().map_err(classify)? {
            if items.len() == limit {
                has_more = true;
                break;
            }
            items.push(message_from_row(&row)?);
            last = Some(Cursor {
                sort_key: row.get::<_, i64>(18).map_err(classify)?,
                id: row.get::<_, i64>(0).map_err(classify)?,
            });
        }
        Ok(Page {
            items,
            next_cursor: if has_more {
                last.map(|c| c.encode())
            } else {
                None
            },
        })
    }

    /// Una página de búsqueda FTS5.
    ///
    /// Busca por el principio de cada palabra, sin acentos ni mayúsculas,
    /// en subject, from_addr, to_addrs, cc_addrs y text_body. Todas las
    /// palabras tienen que estar. Lo que se escribe es texto, nunca lenguaje
    /// de consulta. Vacía, de más de 256 bytes o de más de 8 palabras:
    /// `InvalidArgument`.
    pub fn search_messages(
        &self,
        fts_query: &str,
        mailbox_id: i64,
        after: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page<MessageSummary>, StoreError> {
        let fts = cached_fts_query(fts_query).ok_or(InvalidArgument::query())?;

        let (sql, params): (String, Vec<Box<dyn rusqlite::ToSql>>) = if mailbox_id == 0 {
            if after.is_some() {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          JOIN messages_fts fts ON m.id = fts.rowid
                          WHERE messages_fts MATCH ?1
                            AND (m.sort_key, m.id) < (?2, ?3)
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?4";
                let (sk, id) = after.unwrap().encode_decode();
                (
                    base.into(),
                    vec![
                        Box::new(fts),
                        Box::new(sk),
                        Box::new(id),
                        Box::new(limit as i64 + 1),
                    ],
                )
            } else {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          JOIN messages_fts fts ON m.id = fts.rowid
                          WHERE messages_fts MATCH ?1
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?2";
                (base.into(), vec![Box::new(fts), Box::new(limit as i64 + 1)])
            }
        } else {
            if after.is_some() {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          JOIN messages_fts fts ON m.id = fts.rowid
                          WHERE m.mailbox_id = ?1
                            AND messages_fts MATCH ?2
                            AND (m.sort_key, m.id) < (?3, ?4)
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?5";
                let (sk, id) = after.unwrap().encode_decode();
                (
                    base.into(),
                    vec![
                        Box::new(mailbox_id),
                        Box::new(fts),
                        Box::new(sk),
                        Box::new(id),
                        Box::new(limit as i64 + 1),
                    ],
                )
            } else {
                let base = "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                            m.from_addr, m.to_addrs, m.cc_addrs, m.reply_to, m.subject,
                            m.date_ts, m.flags_seen, m.flags_answered, m.flags_flagged,
                            m.flags_draft, m.flags_deleted, m.has_attachments, m.size,
                            m.sort_key
                          FROM messages m
                          JOIN mailboxes mb ON m.mailbox_id = mb.id
                          JOIN messages_fts fts ON m.id = fts.rowid
                          WHERE m.mailbox_id = ?1
                            AND messages_fts MATCH ?2
                          ORDER BY m.sort_key DESC, m.id
                          LIMIT ?3";
                (
                    base.into(),
                    vec![
                        Box::new(mailbox_id),
                        Box::new(fts),
                        Box::new(limit as i64 + 1),
                    ],
                )
            }
        };

        let mut statement = self.connection.prepare(&sql).map_err(classify)?;
        let params_ref: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
        let mut rows = statement.query(&params_ref[..]).map_err(classify)?;

        let mut items = Vec::new();
        let mut last: Option<Cursor> = None;
        let mut has_more = false;
        while let Some(row) = rows.next().map_err(classify)? {
            if items.len() == limit {
                has_more = true;
                break;
            }
            items.push(message_from_row(&row)?);
            last = Some(Cursor {
                sort_key: row.get::<_, i64>(18).map_err(classify)?,
                id: row.get::<_, i64>(0).map_err(classify)?,
            });
        }
        Ok(Page {
            items,
            next_cursor: if has_more {
                last.map(|c| c.encode())
            } else {
                None
            },
        })
    }

    /// Un mensaje entero (para abrir).
    pub fn get_message(&self, message_id: i64) -> Result<Option<MessageFull>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT m.id, m.mailbox_id, mb.name, m.uid, m.message_id,
                        m.from_addr, m.to_addrs, m.cc_addrs, m.bcc_addrs, m.reply_to,
                        m.subject, m.date_ts, m.flags_seen, m.flags_answered,
                        m.flags_flagged, m.flags_draft, m.flags_deleted,
                        m.has_attachments, m.size,
                        b.text_body, b.html_body, b.truncated
                 FROM messages m
                 JOIN mailboxes mb ON m.mailbox_id = mb.id
                 LEFT JOIN message_bodies b ON m.id = b.message_id
                 WHERE m.id = ?1",
            )
            .map_err(classify)?;

        let mut rows = statement.query([message_id]).map_err(classify)?;
        let message = if let Some(row) = rows.next().map_err(classify)? {
            Some(message_full_from_row(&row)?)
        } else {
            None
        };

        // Adjuntos
        let attachments = if let Some(ref msg) = message {
            let mut stmt = self
                .connection
                .prepare(
                    "SELECT part_number, name, content_type, size, inline, content_id
                     FROM message_attachments WHERE message_id = ?1 ORDER BY part_number",
                )
                .map_err(classify)?;
            let rows = stmt
                .query_map([message_id], |row| {
                    Ok(AttachmentSummary {
                        part_number: row.get(0)?,
                        name: row.get(1)?,
                        content_type: row.get(2)?,
                        size: row.get(3)?,
                        inline: row.get::<_, i64>(4)? != 0,
                        content_id: row.get(5)?,
                    })
                })
                .map_err(classify)?;
            rows.collect::<Result<_, _>>().map_err(classify)?
        } else {
            Vec::new()
        };

        // Banderas extra
        let flags = if let Some(ref msg) = message {
            let mut stmt = self
                .connection
                .prepare("SELECT flag FROM message_flags WHERE message_id = ?1 ORDER BY flag")
                .map_err(classify)?;
            let rows = stmt
                .query_map([message_id], |row| row.get(0))
                .map_err(classify)?;
            rows.collect::<Result<_, _>>().map_err(classify)?
        } else {
            Vec::new()
        };

        if let Some(mut msg) = message {
            msg.attachments = attachments;
            msg.flags = flags;
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    /// Los adjuntos de un mensaje.
    pub fn list_attachments(&self, message_id: i64) -> Result<Vec<AttachmentSummary>, StoreError> {
        let mut stmt = self
            .connection
            .prepare(
                "SELECT part_number, name, content_type, size, inline, content_id
                 FROM message_attachments WHERE message_id = ?1 ORDER BY part_number",
            )
            .map_err(classify)?;
        let rows = stmt
            .query_map([message_id], |row| {
                Ok(AttachmentSummary {
                    part_number: row.get(0)?,
                    name: row.get(1)?,
                    content_type: row.get(2)?,
                    size: row.get(3)?,
                    inline: row.get::<_, i64>(4)? != 0,
                    content_id: row.get(5)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Las banderas extra de un mensaje.
    pub fn get_flags(&self, message_id: i64) -> Result<Vec<String>, StoreError> {
        let mut stmt = self
            .connection
            .prepare("SELECT flag FROM message_flags WHERE message_id = ?1 ORDER BY flag")
            .map_err(classify)?;
        let rows = stmt
            .query_map([message_id], |row| row.get(0))
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }
}

fn message_from_row(row: &Row) -> Result<MessageSummary, StoreError> {
    Ok(MessageSummary {
        id: row.get(0).map_err(classify)?,
        mailbox_id: row.get(1).map_err(classify)?,
        mailbox_name: row.get(2).map_err(classify)?,
        uid: row.get::<_, i64>(3).map_err(classify)? as u64,
        message_id: row.get(4).map_err(classify)?,
        from_addr: row.get(5).map_err(classify)?,
        to_addrs: row.get(6).map_err(classify)?,
        cc_addrs: row.get(7).map_err(classify)?,
        reply_to: row.get(8).map_err(classify)?,
        subject: row.get(9).map_err(classify)?,
        date_ts: row.get(10).map_err(classify)?,
        flags_seen: row.get::<_, i64>(11).map_err(classify)? != 0,
        flags_answered: row.get::<_, i64>(12).map_err(classify)? != 0,
        flags_flagged: row.get::<_, i64>(13).map_err(classify)? != 0,
        flags_draft: row.get::<_, i64>(14).map_err(classify)? != 0,
        flags_deleted: row.get::<_, i64>(15).map_err(classify)? != 0,
        has_attachments: row.get::<_, i64>(16).map_err(classify)? != 0,
        size: row.get(17).map_err(classify)?,
    })
}

fn message_full_from_row(row: &Row) -> Result<MessageFull, StoreError> {
    Ok(MessageFull {
        id: row.get(0).map_err(classify)?,
        mailbox_id: row.get(1).map_err(classify)?,
        mailbox_name: row.get(2).map_err(classify)?,
        uid: row.get::<_, i64>(3).map_err(classify)? as u64,
        message_id: row.get(4).map_err(classify)?,
        from_addr: row.get(5).map_err(classify)?,
        to_addrs: row.get(6).map_err(classify)?,
        cc_addrs: row.get(7).map_err(classify)?,
        bcc_addrs: row.get(8).map_err(classify)?,
        reply_to: row.get(9).map_err(classify)?,
        subject: row.get(10).map_err(classify)?,
        date_ts: row.get(11).map_err(classify)?,
        flags_seen: row.get::<_, i64>(12).map_err(classify)? != 0,
        flags_answered: row.get::<_, i64>(13).map_err(classify)? != 0,
        flags_flagged: row.get::<_, i64>(14).map_err(classify)? != 0,
        flags_draft: row.get::<_, i64>(15).map_err(classify)? != 0,
        flags_deleted: row.get::<_, i64>(16).map_err(classify)? != 0,
        has_attachments: row.get::<_, i64>(17).map_err(classify)? != 0,
        size: row.get(18).map_err(classify)?,
        text_body: row.get(19).map_err(classify)?,
        html_body: row.get(20).map_err(classify)?,
        truncated: row.get::<_, i64>(21).map_err(classify)? != 0,
        attachments: Vec::new(),
        flags: Vec::new(),
    })
}

fn collect_messages(
    rows: &mut rusqlite::Rows<'_>,
    limit: usize,
) -> Result<Vec<MessageSummary>, StoreError> {
    let mut items = Vec::new();
    while let Some(row) = rows.next().map_err(classify)? {
        if items.len() == limit {
            break;
        }
        items.push(message_from_row(&row)?);
    }
    Ok(items)
}

/// Convierte una consulta de texto plano a FTS5: palabras con prefijo `*`,
/// acentos y mayúsculas ya los quita el tokenizador unicode61.
pub fn fts_query_str(text: &str) -> Option<String> {
    let words: Vec<&str> = text
        .split_whitespace()
        .filter(|w| !w.is_empty())
        .take(8)
        .collect();
    if words.is_empty() {
        return None;
    }
    if text.len() > 256 {
        return None;
    }
    Some(
        words
            .into_iter()
            .map(|w| format!("{w}*"))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Caché global para la conversión de consultas FTS. Evita que la misma
/// consulta de búsqueda sea convertida una y otra vez.
pub fn cached_fts_query(text: &str) -> Option<String> {
    static CACHE: once_cell::sync::Lazy<std::sync::Mutex<HashMap<String, String>>> =
        once_cell::sync::Lazy::new(|| std::sync::Mutex::new(HashMap::new()));
    let mut cache = CACHE.lock().unwrap();
    if let Some(fts) = cache.get(text) {
        return Some(fts.clone());
    }
    let fts = fts_query_str(text)?;
    cache.insert(text.to_string(), fts.clone());
    Some(fts)
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
    use crate::store::email::{
        MailboxListing, MailboxRole, MessageAttachmentRow, MessageBodyRow, MessageFlagRow,
        MessageOp, MessageRow,
    };
    use crate::store::email_read::Cursor;
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
        let temp = TempDir::new("email_read");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'r')).unwrap();
        (temp, store)
    }

    #[test]
    fn lista_casillas_ordenadas_por_rol() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[
                MailboxListing {
                    name: "Junk".into(),
                    display_name: "Spam".into(),
                    role: MailboxRole::Junk,
                },
                MailboxListing {
                    name: "INBOX".into(),
                    display_name: "Bandeja".into(),
                    role: MailboxRole::Inbox,
                },
                MailboxListing {
                    name: "Sent".into(),
                    display_name: "Enviados".into(),
                    role: MailboxRole::Sent,
                },
            ])
            .unwrap();
        let boxes = store.list_mailboxes().unwrap();
        assert_eq!(boxes.len(), 3);
        assert_eq!(boxes[0].role, "inbox");
        assert_eq!(boxes[1].role, "sent");
        assert_eq!(boxes[2].role, "junk");
    }

    #[test]
    fn lista_mensajes_paginados_por_fecha_desc() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[MailboxListing {
                name: "INBOX".into(),
                display_name: "Bandeja".into(),
                role: MailboxRole::Inbox,
            }])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        for i in 1..=5 {
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

        // Primera página (2)
        let page1 = store.list_messages(inbox_id, None, 2).unwrap();
        assert_eq!(page1.items.len(), 2);
        assert_eq!(page1.items[0].subject, "Hola 5");
        assert_eq!(page1.items[1].subject, "Hola 4");
        assert!(page1.next_cursor.is_some());

        // Segunda página
        let cursor = Cursor::decode(&page1.next_cursor.unwrap()).unwrap();
        let page2 = store.list_messages(inbox_id, cursor.as_ref(), 2).unwrap();
        assert_eq!(page2.items.len(), 2);
        assert_eq!(page2.items[0].subject, "Hola 3");
        assert_eq!(page2.items[1].subject, "Hola 2");

        // Tercera página (la última)
        let cursor = Cursor::decode(&page2.next_cursor.unwrap()).unwrap();
        let page3 = store.list_messages(inbox_id, cursor.as_ref(), 2).unwrap();
        assert_eq!(page3.items.len(), 1);
        assert_eq!(page3.items[0].subject, "Hola 1");
        assert!(page3.next_cursor.is_none());
    }

    #[test]
    fn busca_mensajes_fts5() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[MailboxListing {
                name: "INBOX".into(),
                display_name: "Bandeja".into(),
                role: MailboxRole::Inbox,
            }])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        for (i, (subj, body)) in [
            ("Reunión mañana", "Nos vemos mañana"),
            ("Factura adjunta", "La factura del mes"),
            ("Otro tema", "Nada que ver"),
        ]
        .into_iter()
        .enumerate()
        {
            store
                .apply_messages(
                    vec![MessageOp::Upsert(Box::new(MessageRow {
                        mailbox_id: inbox_id,
                        uid: (i + 1) as u64,
                        message_id: Some(format!("<msg{i}@x>")),
                        from_addr: "ana@x.com".into(),
                        to_addrs: "yo@x.com".into(),
                        cc_addrs: "".into(),
                        bcc_addrs: "".into(),
                        reply_to: None,
                        subject: subj.into(),
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
            // Cuerpo para FTS
            let msg_id = store
                .connection
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = ?2",
                    rusqlite::params![inbox_id, (i + 1) as i64],
                    |row| row.get(0),
                )
                .unwrap();
            store
                .upsert_message_body(MessageBodyRow {
                    message_id: msg_id,
                    text_body: Some(body.into()),
                    html_body: None,
                    truncated: false,
                })
                .unwrap();
        }

        // Buscar "reunion" (sin acento)
        let page = store
            .search_messages("reunion", inbox_id, None, 10)
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].subject, "Reunión mañana");

        // Buscar "factura"
        let page = store
            .search_messages("factura", inbox_id, None, 10)
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].subject, "Factura adjunta");

        // Buscar "mañana factura" (ambas palabras)
        let page = store
            .search_messages("mañana factura", inbox_id, None, 10)
            .unwrap();
        assert_eq!(page.items.len(), 0);
    }

    #[test]
    fn mensaje_entero_con_cuerpo_adjuntos_banderas() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[MailboxListing {
                name: "INBOX".into(),
                display_name: "Bandeja".into(),
                role: MailboxRole::Inbox,
            }])
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
                    cc_addrs: "cc@x.com".into(),
                    bcc_addrs: "bcc@x.com".into(),
                    reply_to: Some("reply@x.com".into()),
                    subject: "Hola".into(),
                    date_ts: 1000,
                    sort_key: 1000,
                    flags_seen: true,
                    flags_answered: false,
                    flags_flagged: true,
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

        store
            .upsert_message_body(MessageBodyRow {
                message_id: msg_id,
                text_body: Some("Texto plano".into()),
                html_body: Some("<p>HTML</p>".into()),
                truncated: false,
            })
            .unwrap();
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
        store
            .upsert_message_flag(MessageFlagRow {
                message_id: msg_id,
                flag: "\\Flagged".into(),
            })
            .unwrap();

        let msg = store.get_message(msg_id).unwrap().unwrap();
        assert_eq!(msg.subject, "Hola");
        assert_eq!(msg.text_body, Some("Texto plano".into()));
        assert_eq!(msg.html_body, Some("<p>HTML</p>".into()));
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].part_number, "2");
        assert_eq!(msg.flags, vec!["\\Flagged"]);
    }

    #[test]
    fn cursor_encode_decode() {
        let c = Cursor {
            sort_key: 1000,
            id: 42,
        };
        let encoded = c.encode();
        assert_eq!(Cursor::decode(&encoded), Ok(Some(c)));

        // Inválido
        assert!(matches!(Cursor::decode("basura"), Err(_)));
    }
}
