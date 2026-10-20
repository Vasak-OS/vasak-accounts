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

use rusqlite::Row;
use serde::Serialize;

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
    /// Codifica el cursor como base64 URL-safe sin padding: `"<sort_key>:<id>"`.
    pub fn encode(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!("{}:{}", self.sort_key, self.id))
    }

    /// Devuelve la tupla `(sort_key, id)` sin codificar.
    pub fn encode_decode(&self) -> (i64, i64) {
        (self.sort_key, self.id)
    }

    /// Decodifica un cursor base64 URL-safe.
    ///
    /// Retorna `Ok(None)` si el cursor está vacío (primera página).
    /// Retorna `Err(InvalidArgument)` si el formato es inválido.
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

/// Resumen acotado de una interacción de correo con una dirección.
///
/// Lo mínimo para pintar el historial en la ficha de un contacto: cuándo, de
/// qué, de quién, y con qué UID se abre después en la aplicación de correo.
/// **Sin cuerpo** y sin el resto de la casilla: lo que ve otra aplicación es un
/// índice, no el correo.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InteractionSummary {
    pub uid: u64,
    pub date_ts: i64,
    pub subject: String,
    pub from_addr: String,
}

/// Cuántas filas candidatas (las que el prefiltro `LIKE` deja pasar) recorre
/// [`Store::messages_with`] como mucho antes de cortar.
pub const INTERACTIONS_SCAN_CAP: usize = 2000;

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
    /// El estado S/MIME: `None` si no venía firmado, si no «firmado» con si la
    /// firma se verificó y quién firma. Ver `smime_sign`.
    pub smime: Option<crate::smime_sign::SmimeStatus>,
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

    /// Los últimos `limit` mensajes intercambiados con `address`: los que esa
    /// dirección mandó (en `from`) o recibió (en `to` o `cc`), de **todas** las
    /// casillas, más nuevos primero. Es el historial de correo con una persona
    /// que muestra la ficha de un contacto.
    ///
    /// `address` se compara **entera** (ver [`header_has_address`]): `ana@x.com`
    /// no empareja con `ana@x.com.ar` ni con `bana@x.com`. Es lo que separa
    /// «me escribí con esta persona» de «con alguien de un dominio parecido», y
    /// la diferencia importa porque esto decide qué correo ve otra aplicación.
    ///
    /// Devuelve metadatos acotados ([`InteractionSummary`]): fecha, asunto,
    /// remitente y UID. **Nunca el cuerpo** ni el resto de la casilla.
    ///
    /// El `LIKE` del SQL es sólo un prefiltro barato —acota a las filas que
    /// contienen la dirección como subcadena—; la igualdad la decide
    /// [`header_has_address`] en Rust. Se recorren como mucho
    /// [`INTERACTIONS_SCAN_CAP`] filas candidatas.
    ///
    /// shortcut: con más de INTERACTIONS_SCAN_CAP coincidencias de subcadena
    /// podría saltarse una exacta muy vieja; subir el tope o paginar si una
    /// casilla real lo alcanza (hoy `limit` es chico y el prefiltro muy selectivo).
    pub fn messages_with(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<InteractionSummary>, StoreError> {
        let needle = address.trim().to_ascii_lowercase();
        if needle.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let like = format!("%{}%", like_escape(&needle));

        let mut statement = self
            .connection
            .prepare(
                "SELECT m.uid, m.date_ts, m.subject, m.from_addr, m.to_addrs, m.cc_addrs
                 FROM messages m
                 WHERE lower(m.from_addr) LIKE ?1 ESCAPE '\\'
                    OR lower(m.to_addrs)  LIKE ?1 ESCAPE '\\'
                    OR lower(m.cc_addrs)  LIKE ?1 ESCAPE '\\'
                 ORDER BY m.sort_key DESC, m.id
                 LIMIT ?2",
            )
            .map_err(classify)?;
        let mut rows = statement
            .query(rusqlite::params![like, INTERACTIONS_SCAN_CAP as i64])
            .map_err(classify)?;

        let mut items = Vec::new();
        while let Some(row) = rows.next().map_err(classify)? {
            let from_addr: String = row.get(3).map_err(classify)?;
            let to_addrs: String = row.get(4).map_err(classify)?;
            let cc_addrs: String = row.get(5).map_err(classify)?;
            if !(header_has_address(&from_addr, &needle)
                || header_has_address(&to_addrs, &needle)
                || header_has_address(&cc_addrs, &needle))
            {
                continue;
            }
            items.push(InteractionSummary {
                uid: row.get::<_, i64>(0).map_err(classify)? as u64,
                date_ts: row.get(1).map_err(classify)?,
                subject: row.get(2).map_err(classify)?,
                from_addr,
            });
            if items.len() == limit {
                break;
            }
        }
        Ok(items)
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
                        b.text_body, b.html_body, b.truncated,
                        b.smime_status, b.smime_signer, b.smime_encrypted
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
        let attachments = if let Some(ref _msg) = message {
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
        let flags = if let Some(ref _msg) = message {
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

/// Si `address` (ya normalizada: minúsculas, sin espacios al borde) aparece
/// como una dirección **completa** dentro de `field` —el valor crudo de un
/// encabezado `From`, `To` o `Cc`, que puede traer nombres y varias
/// direcciones, p. ej. `"Ana Pérez <ana@x.com>, Bob <bob@y.com>"`—.
///
/// Compara la dirección entera, no una subcadena: exige que a cada lado del
/// match haya un **borde** y no otro carácter de dirección, así `ana@x.com` no
/// empareja con `ana@x.com.ar` (lo que sigue es `.`) ni con `bana@x.com` (lo que
/// precede es `b`). Esa es la propiedad que cuida la privacidad acá: una
/// aplicación que pide el historial con una persona no termina viendo el de otra
/// de un dominio parecido.
fn header_has_address(field: &str, address: &str) -> bool {
    if address.is_empty() {
        return false;
    }
    let haystack = field.to_ascii_lowercase();
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(offset) = haystack[from..].find(address) {
        let start = from + offset;
        let end = start + address.len();
        let before_is_border = start == 0 || !is_address_char(bytes[start - 1] as char);
        let after_is_border = end == bytes.len() || !is_address_char(bytes[end] as char);
        if before_is_border && after_is_border {
            return true;
        }
        // Un carácter entero, no un byte: `start + 1` caería dentro de uno multibyte.
        from = start + haystack[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Los caracteres que pueden formar parte de una dirección (`atext` de RFC 5322
/// más `@` y `.`). Un byte que no es uno de éstos separa una dirección de lo que
/// la rodea en un encabezado. Un byte no ASCII —una tilde de un nombre— no es
/// uno de éstos, así que también cuenta como borde, que es lo correcto.
fn is_address_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "@.!#$%&'*+-/=?^_`{|}~".contains(c)
}

/// Escapa `%`, `_` y `\` para que viajen como literales en un patrón `LIKE`
/// (con `ESCAPE '\'`). Una dirección rara vez los trae, pero `_` es válido en la
/// parte local y sin esto emparejaría cualquier carácter en el prefiltro.
fn like_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
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
        smime: smime_from_row(
            row.get::<_, Option<i64>>(22).map_err(classify)?,
            row.get::<_, Option<String>>(23).map_err(classify)?,
            row.get::<_, Option<i64>>(24).map_err(classify)?,
        ),
        attachments: Vec::new(),
        flags: Vec::new(),
    })
}

/// Arma el estado S/MIME de las dos columnas: `None` si no venía firmado.
fn smime_from_row(
    status: Option<i64>,
    signer: Option<String>,
    encrypted: Option<i64>,
) -> Option<crate::smime_sign::SmimeStatus> {
    // `None` sólo si no venía ni firmado ni cifrado.
    if status.is_none() && encrypted.is_none() {
        return None;
    }
    let encryption = encrypted.map(|e| match e {
        1 => crate::smime_sign::Encryption::Opened,
        _ => crate::smime_sign::Encryption::Unavailable,
    });
    Some(crate::smime_sign::SmimeStatus {
        valid: status == Some(1),
        // El firmante va tanto en «firmado, no verificado» (estado 0) como en el
        // futuro «válido» (estado 1): sólo se guardó cuando la firma ligó el From.
        signer,
        encryption,
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
    use crate::store::email_read::{cached_fts_query, Cursor};
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
                    smime_status: None,
                    smime_signer: None,
                    smime_encrypted: None,
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
                smime_status: None,
                smime_signer: None,
                smime_encrypted: None,
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

    /// **De punta a punta, como lo ve la ventana**: el crudo entra por
    /// `opened_rows`, se guarda, y `get_message` devuelve el estado S/MIME. Un
    /// mensaje firmado se lee «firmado, no verificado» con su firmante y **nunca
    /// `valid`**; uno manipulado o sin firma se lee sin estado; y volver a bajar el
    /// mensaje pisa el estado anterior.
    #[test]
    fn el_estado_smime_llega_a_la_ventana_firmado_no_verificado_nunca_valido() {
        use crate::smime_sign::test_support::*;
        use crate::smime_sign::SmimeStatus;

        let signed = sign(RSA_P12, &draft(RSA_ADDRESS, "hola firmado")).message;
        let tampered = signed.replace("hola firmado", "hola cambiado");
        let plain = "From: ana@x.com\r\nContent-Type: text/plain\r\n\r\nhola\r\n".to_string();

        let (_temp, mut store, inbox, _sent) = store_with_inbox_and_sent();
        let mut ids = Vec::new();
        for uid in 1..=3u32 {
            store
                .apply_messages(
                    vec![mail(inbox, uid, "ana@x.com", "yo@x.com", "", "s", 1000)],
                    inbox,
                )
                .unwrap();
            ids.push(
                store
                    .connection
                    .query_row(
                        "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = ?2",
                        rusqlite::params![inbox, uid],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
            );
        }
        let ingest = |store: &mut Store, id: i64, raw: &str| {
            let (body, _) =
                crate::email_sync::opened_rows_decrypting(id, raw.as_bytes(), false, None);
            store.upsert_message_body(body).unwrap();
        };
        let smime = |store: &Store, id: i64| store.get_message(id).unwrap().unwrap().smime;

        ingest(&mut store, ids[0], &signed);
        ingest(&mut store, ids[1], &tampered);
        ingest(&mut store, ids[2], &plain);
        assert_eq!(
            smime(&store, ids[0]),
            Some(SmimeStatus {
                valid: false,
                signer: Some(RSA_ADDRESS.into()),
                encryption: None,
            })
        );
        assert_eq!(smime(&store, ids[1]), None);
        assert_eq!(smime(&store, ids[2]), None);

        // Lo que sale por el bus: la clave `smime` con `valid` y `signer`.
        let json = serde_json::to_value(store.get_message(ids[0]).unwrap().unwrap()).unwrap();
        assert_eq!(json["smime"]["valid"], false);
        assert_eq!(json["smime"]["signer"], RSA_ADDRESS);
        let json = serde_json::to_value(store.get_message(ids[2]).unwrap().unwrap()).unwrap();
        assert!(json["smime"].is_null());

        // Volver a bajar el mensaje pisa el estado: de firmado a manipulado, y de
        // sin firma a firmado.
        ingest(&mut store, ids[0], &tampered);
        ingest(&mut store, ids[2], &signed);
        assert_eq!(smime(&store, ids[0]), None);
        assert_eq!(
            smime(&store, ids[2]).map(|s| (s.valid, s.signer)),
            Some((false, Some(RSA_ADDRESS.into())))
        );
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

        // Cursor vacío
        assert_eq!(Cursor::decode(""), Ok(None));
    }

    #[test]
    fn cached_fts_query_simple() {
        let q1 = cached_fts_query("hola mundo").unwrap();
        assert_eq!(q1, "hola* mundo*");

        // Segunda llamada debe usar caché
        let q2 = cached_fts_query("hola mundo").unwrap();
        assert_eq!(q1, q2);

        // Consulta distinta
        let q3 = cached_fts_query("otro término").unwrap();
        assert_eq!(q3, "otro* término*");
    }

    #[test]
    fn search_messages_paginacion_limit_plus_1() {
        let (_, mut store) = make_store();
        store
            .upsert_mailboxes(&[MailboxListing {
                name: "INBOX".into(),
                display_name: "Bandeja".into(),
                role: MailboxRole::Inbox,
            }])
            .unwrap();
        let inbox_id = store.mailboxes().unwrap()[0].id;

        // Insertar 5 mensajes con cuerpos para FTS
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
            let msg_id = store
                .connection
                .query_row(
                    "SELECT id FROM messages WHERE mailbox_id = ?1 AND uid = ?2",
                    rusqlite::params![inbox_id, i as i64],
                    |row| row.get(0),
                )
                .unwrap();
            store
                .upsert_message_body(MessageBodyRow {
                    message_id: msg_id,
                    text_body: Some(format!("Cuerpo {i}")),
                    html_body: None,
                    truncated: false,
                    smime_status: None,
                    smime_signer: None,
                    smime_encrypted: None,
                })
                .unwrap();
        }

        // Buscar "hola" con límite 2 -> debería devolver 2 items y next_cursor
        let page1 = store.search_messages("hola", inbox_id, None, 2).unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());

        // Segunda página
        let cursor = Cursor::decode(&page1.next_cursor.unwrap())
            .unwrap()
            .unwrap();
        let page2 = store
            .search_messages("hola", inbox_id, Some(&cursor), 2)
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        assert!(page2.next_cursor.is_some());

        // Tercera página (última)
        let cursor = Cursor::decode(&page2.next_cursor.unwrap())
            .unwrap()
            .unwrap();
        let page3 = store
            .search_messages("hola", inbox_id, Some(&cursor), 2)
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert!(page3.next_cursor.is_none());
    }

    // ---- MessagesWith: historial de correo con una dirección ----

    use super::{header_has_address, INTERACTIONS_SCAN_CAP};

    /// Un mensaje con los tres encabezados de dirección a mano.
    fn mail(
        mailbox_id: i64,
        uid: u32,
        from: &str,
        to: &str,
        cc: &str,
        subject: &str,
        date_ts: i64,
    ) -> MessageOp {
        MessageOp::Upsert(Box::new(MessageRow {
            mailbox_id,
            uid: uid.into(),
            message_id: Some(format!("<m{mailbox_id}-{uid}@x>")),
            from_addr: from.into(),
            to_addrs: to.into(),
            cc_addrs: cc.into(),
            bcc_addrs: "".into(),
            reply_to: None,
            subject: subject.into(),
            date_ts,
            sort_key: date_ts,
            flags_seen: false,
            flags_answered: false,
            flags_flagged: false,
            flags_draft: false,
            flags_deleted: false,
            has_attachments: false,
            size: 100,
        }))
    }

    /// Una base con dos casillas (Recibidos y Enviados); devuelve sus ids.
    fn store_with_inbox_and_sent() -> (TempDir, Store, i64, i64) {
        let (temp, mut store) = make_store();
        store
            .upsert_mailboxes(&[
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
        let boxes = store.mailboxes().unwrap();
        let id_of = |name: &str| boxes.iter().find(|b| b.name == name).unwrap().id;
        let (inbox, sent) = (id_of("INBOX"), id_of("Sent"));
        (temp, store, inbox, sent)
    }

    #[test]
    fn la_direccion_se_compara_entera_y_sin_distinguir_mayusculas() {
        // Coinciden.
        for field in [
            "ana@x.com",
            "ANA@X.COM",
            "Ana Pérez <ana@x.com>",
            "\"Pérez, Ana\" <Ana@X.com>",
            "bob@y.com, ana@x.com",
            "Bob <bob@y.com>,Ana <ana@x.com>, Eva <eva@z.com>",
            "<ana@x.com>",
            "ana@x.com;bob@y.com",
        ] {
            assert!(
                header_has_address(field, "ana@x.com"),
                "{field} tenía que coincidir"
            );
        }
        // Vecinos que NO son la persona: por dominio, por parte local, por
        // prefijo y por sufijo.
        for field in [
            "ana@x.com.ar",
            "bana@x.com",
            "ana@x.co",
            "ana@xx.com",
            "mana@x.com.mx, <ana@x.org>",
            "ana+promo@x.com",
            "sub.ana@x.com",
            "ana@x.com-old",
            "Nombre <bana@x.com>",
            "",
        ] {
            assert!(
                !header_has_address(field, "ana@x.com"),
                "{field} NO tenía que coincidir"
            );
        }
        // Una dirección vacía no empareja con nada.
        assert!(!header_has_address("ana@x.com", ""));
    }

    #[test]
    fn una_direccion_que_empieza_con_un_caracter_no_ascii_no_hace_caer_la_busqueda() {
        // El avance por bytes tras un match descartado no puede partir un
        // carácter UTF-8: caería con un panic en el servicio.
        assert!(!header_has_address("xñandu@x.com", "ñandu@x.com"));
        assert!(header_has_address("Ñandú <ñandu@x.com>", "ñandu@x.com"));
    }

    #[test]
    fn el_historial_junta_recibidos_y_enviados_mas_nuevos_primero_y_sin_vecinos() {
        let (_t, mut store, inbox, sent) = store_with_inbox_and_sent();
        store
            .apply_messages(
                vec![
                    // Ana escribe (from).
                    mail(
                        inbox,
                        1,
                        "Ana Pérez <ana@x.com>",
                        "yo@x.com",
                        "",
                        "recibido viejo",
                        100,
                    ),
                    mail(inbox, 2, "ana@x.com", "yo@x.com", "", "recibido nuevo", 400),
                    // Vecinos que no son Ana.
                    mail(
                        inbox,
                        3,
                        "ana@x.com.ar",
                        "yo@x.com",
                        "",
                        "vecino dominio",
                        450,
                    ),
                    mail(
                        inbox,
                        4,
                        "bana@x.com",
                        "yo@x.com",
                        "",
                        "vecino prefijo",
                        460,
                    ),
                    mail(inbox, 5, "ana@x.co", "yo@x.com", "", "vecino tld", 470),
                    // Un tercero.
                    mail(inbox, 6, "eva@z.com", "yo@x.com", "", "ajeno", 480),
                ],
                inbox,
            )
            .unwrap();
        store
            .apply_messages(
                vec![
                    // Yo le escribo (to, con más destinatarios) y la copio (cc).
                    mail(
                        sent,
                        1,
                        "yo@x.com",
                        "Bob <bob@y.com>, Ana <ANA@x.com>",
                        "",
                        "enviado to",
                        300,
                    ),
                    mail(
                        sent,
                        2,
                        "yo@x.com",
                        "bob@y.com",
                        "ana@x.com",
                        "enviado cc",
                        200,
                    ),
                    mail(
                        sent,
                        3,
                        "yo@x.com",
                        "ana@x.com.ar",
                        "bana@x.com",
                        "enviado vecino",
                        500,
                    ),
                ],
                sent,
            )
            .unwrap();

        let items = store.messages_with("ana@x.com", 50).unwrap();
        let subjects: Vec<&str> = items.iter().map(|i| i.subject.as_str()).collect();
        assert_eq!(
            subjects,
            vec![
                "recibido nuevo",
                "enviado to",
                "enviado cc",
                "recibido viejo"
            ],
            "from + to + cc de las dos casillas, desc por fecha, sin vecinos"
        );
        assert!(items.windows(2).all(|w| w[0].date_ts >= w[1].date_ts));

        // La comparación no distingue mayúsculas en lo que se pide.
        assert_eq!(store.messages_with("  ANA@X.COM ", 50).unwrap().len(), 4);

        // Un N chico corta los más viejos, no los nuevos.
        let top2 = store.messages_with("ana@x.com", 2).unwrap();
        let subjects: Vec<&str> = top2.iter().map(|i| i.subject.as_str()).collect();
        assert_eq!(subjects, vec!["recibido nuevo", "enviado to"]);

        // Sin dirección o sin cupo: nada.
        assert!(store.messages_with("", 50).unwrap().is_empty());
        assert!(store.messages_with("   ", 50).unwrap().is_empty());
        assert!(store.messages_with("ana@x.com", 0).unwrap().is_empty());
        // Una dirección que nadie usó: vacío, no error.
        assert!(store.messages_with("nadie@x.com", 50).unwrap().is_empty());
    }

    #[test]
    fn el_guion_bajo_y_el_porcentaje_de_la_direccion_no_son_comodines() {
        let (_t, mut store, inbox, _sent) = store_with_inbox_and_sent();
        store
            .apply_messages(
                vec![
                    mail(
                        inbox,
                        1,
                        "ana_b@x.com",
                        "yo@x.com",
                        "",
                        "con guion bajo",
                        100,
                    ),
                    mail(inbox, 2, "anaxb@x.com", "yo@x.com", "", "otra persona", 200),
                ],
                inbox,
            )
            .unwrap();
        let items = store.messages_with("ana_b@x.com", 10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].subject, "con guion bajo");
        // `%` tampoco abre el filtro a todo el buzón.
        assert!(store.messages_with("%", 10).unwrap().is_empty());
        assert!(store.messages_with("_", 10).unwrap().is_empty());
    }

    #[test]
    fn el_resumen_del_historial_no_lleva_el_cuerpo() {
        let (_t, mut store, inbox, _sent) = store_with_inbox_and_sent();
        store
            .apply_messages(
                vec![mail(inbox, 1, "ana@x.com", "yo@x.com", "", "hola", 100)],
                inbox,
            )
            .unwrap();
        let id = store.list_messages(inbox, None, 10).unwrap().items[0].id;
        store
            .upsert_message_body(MessageBodyRow {
                message_id: id,
                text_body: Some("CUERPO-SECRETO".into()),
                html_body: Some("<p>CUERPO-SECRETO</p>".into()),
                truncated: false,
                smime_status: None,
                smime_signer: None,
                smime_encrypted: None,
            })
            .unwrap();
        let items = store.messages_with("ana@x.com", 10).unwrap();
        let json = serde_json::to_string(&items).unwrap();
        assert!(
            !json.contains("CUERPO-SECRETO"),
            "el resumen filtró el cuerpo: {json}"
        );
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut keys: Vec<&str> = value[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(keys, vec!["date_ts", "from_addr", "subject", "uid"]);
        assert_eq!(value[0]["uid"], 1);
    }

    /// Si el `_` de la dirección no se escapara en el `LIKE`, el prefiltro
    /// dejaría pasar a cualquiera con un carácter en su lugar, y esas filas
    /// —más nuevas— agotarían el tope antes de llegar a la exacta.
    #[test]
    fn el_guion_bajo_sin_escapar_gastaria_el_tope_con_filas_ajenas() {
        let (_t, mut store, inbox, _sent) = store_with_inbox_and_sent();
        let mut ops = vec![mail(
            inbox,
            1,
            "ana_b@x.com",
            "yo@x.com",
            "",
            "la exacta",
            10,
        )];
        for i in 0..(INTERACTIONS_SCAN_CAP + 10) {
            ops.push(mail(
                inbox,
                (i + 2) as u32,
                "anaxb@x.com",
                "yo@x.com",
                "",
                "ajena",
                1_000 + i as i64,
            ));
        }
        store.apply_messages(ops, inbox).unwrap();
        let items = store.messages_with("ana_b@x.com", 5).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].subject, "la exacta");
    }

    #[test]
    fn con_mas_candidatos_que_el_tope_no_explota_y_devuelve_los_mas_nuevos() {
        let (_t, mut store, inbox, _sent) = store_with_inbox_and_sent();
        let extra = 50;
        // Más candidatos de subcadena que el tope: ninguno es Ana exacta salvo
        // los más nuevos.
        let mut ops = Vec::new();
        for i in 0..(INTERACTIONS_SCAN_CAP + extra) {
            ops.push(mail(
                inbox,
                (i + 1) as u32,
                "ana@x.com.ar",
                "yo@x.com",
                "",
                "vecino",
                1_000 + i as i64,
            ));
        }
        // Las exactas, más nuevas que todas las del vecino.
        ops.push(mail(
            inbox,
            90_001,
            "ana@x.com",
            "yo@x.com",
            "",
            "exacta 1",
            900_000,
        ));
        ops.push(mail(
            inbox,
            90_002,
            "ana@x.com",
            "yo@x.com",
            "",
            "exacta 2",
            900_001,
        ));
        store.apply_messages(ops, inbox).unwrap();

        let items = store.messages_with("ana@x.com", 10).unwrap();
        let subjects: Vec<&str> = items.iter().map(|i| i.subject.as_str()).collect();
        assert_eq!(subjects, vec!["exacta 2", "exacta 1"]);
    }
}
