//! Los contactos en la base: lo que escribe la sincronización.
//!
//! Sólo escritura y lo que la sincronización necesita leer para decidir qué
//! pedir (los ETag y el token de cada libreta). Listar y buscar para las
//! aplicaciones vive en `contacts_read.rs`, sobre las conexiones de lectura.
//!
//! **Todo en lotes**: una transacción lleva como mucho [`WRITE_BATCH_ROWS`]
//! contactos —cada uno con sus correos, sus teléfonos y su entrada del
//! índice—, así que tener la base tomada nunca dura más que eso. El token de
//! la libreta se guarda **en la misma transacción que el último lote**: si la
//! sincronización se corta a mitad, lo escrito queda y el token es el de
//! antes, y la próxima vuelta repite desde ahí sin perder nada. Escribir dos
//! veces la misma tarjeta es escribirla una.
//!
//! **Cada lote que cambia algo sube la generación de los contactos** (ver
//! [`super::read_generation`]), en su misma transacción, y lo anota para que
//! `with_store` lo anuncie con la señal `Changed`. Un lote que no cambió nada
//! —el último de una libreta al día, que sólo guarda el token— no la sube.

use std::collections::HashMap;

use rusqlite::OptionalExtension;

use super::lifecycle::CONTACTS_AREA;
use super::{bump_generation, classify, Store, StoreError};
use crate::vcard::{self, Contact};

/// Cuántos contactos entran en una transacción, como mucho.
pub const WRITE_BATCH_ROWS: usize = 500;

/// Y cuánto texto crudo, como mucho: quinientas tarjetas con foto son cientos
/// de megabytes, y el lote se corta antes.
pub const WRITE_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Una libreta tal como está en la base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAddressBook {
    pub id: i64,
    pub href: String,
    pub ctag: Option<String>,
}

/// Una tarjeta para guardar: la cruda y lo que se sacó de ella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRow {
    pub href: String,
    pub etag: Option<String>,
    pub raw_vcard: String,
    /// Lo derivado. Una tarjeta sin nada que mostrar se guarda igual —es del
    /// servidor, y sin su ETag se volvería a pedir en cada vuelta— con lo
    /// derivado vacío.
    pub contact: Contact,
}

/// Lo que se hace con una tarjeta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactOp {
    Upsert(Box<ContactRow>),
    Delete(String),
}

/// Dónde quedó una libreta al terminar: va con el último lote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookProgress {
    /// El `sync-token` nuevo. `None` en el camino por ETag, o si el servidor no
    /// dio ninguno: se borra el que hubiera, y la próxima vuelta es completa.
    pub token: Option<String>,
    pub ctag: Option<String>,
}

/// Cómo quedó un lote de [`Store::apply_contacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Escrito. Cuántos bytes de tarjetas crudas sumó a la cuenta —negativo si
    /// borró o achicó más de lo que agregó—.
    Written { net_bytes: i64 },
    /// No se escribió nada: la cuenta crecería más de lo que había lugar.
    OverCap,
}

/// El enlace de un contacto local con su persona de la People API de Google
/// (P5, `vasak-accounts#111`): el `resourceName` con el que se la vuelve a pedir
/// y los testigos con los que una corrida incremental decide si la persona o su
/// foto cambiaron. Vive en la tabla `contact_enrichment`, **fuera del
/// `raw_vcard`**, para no pisar una edición local sin confirmar al reescribir el
/// crudo (ver la migración `V7`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactEnrichment {
    pub contact_id: i64,
    pub resource_name: String,
    pub etag: Option<String>,
    pub photo_etag: Option<String>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl Store {
    /// Las libretas guardadas.
    pub fn address_books(&self) -> Result<Vec<StoredAddressBook>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, href, ctag FROM address_books ORDER BY id")
            .map_err(classify)?;
        let rows = statement
            .query_map([], |row| {
                Ok(StoredAddressBook {
                    id: row.get(0)?,
                    href: row.get(1)?,
                    ctag: row.get(2)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Da de alta las libretas que listó el servidor, o les actualiza el
    /// nombre. No toca el `getctag`: ése cambia sólo al terminar una libreta
    /// (ver [`BookProgress`]), para que una vuelta cortada no la dé por al día.
    ///
    /// No borra las que faltan: eso va por [`Self::remove_address_book_chunk`],
    /// de a lotes.
    pub fn upsert_address_books(
        &mut self,
        books: &[(String, String)],
    ) -> Result<Vec<StoredAddressBook>, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let mut stored = Vec::with_capacity(books.len());
        // Si alguna es nueva o cambió de nombre: volver a listar las mismas
        // libretas no es un cambio.
        let mut changed = false;
        {
            let mut current = transaction
                .prepare_cached("SELECT display_name FROM address_books WHERE href = ?1")
                .map_err(classify)?;
            for (href, name) in books {
                let before: Option<String> = current
                    .query_row([href], |row| row.get(0))
                    .optional()
                    .map_err(classify)?;
                changed |= before.as_deref() != Some(name.as_str());
            }
        }
        {
            let mut statement = transaction
                .prepare_cached(
                    "INSERT INTO address_books (href, display_name, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT (href) DO UPDATE SET display_name = excluded.display_name
                     RETURNING id, href, ctag",
                )
                .map_err(classify)?;
            for (href, name) in books {
                stored.push(
                    statement
                        .query_row(rusqlite::params![href, name, now()], |row| {
                            Ok(StoredAddressBook {
                                id: row.get(0)?,
                                href: row.get(1)?,
                                ctag: row.get(2)?,
                            })
                        })
                        .map_err(classify)?,
                );
            }
        }
        let generation = if changed {
            Some(bump_generation(&transaction, CONTACTS_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CONTACTS_AREA, generation);
        }
        Ok(stored)
    }

    /// Borra una tanda de los contactos de una libreta que ya no está, y la
    /// libreta misma cuando no le queda ninguno. Devuelve cuántos contactos se
    /// borraron: se llama hasta que devuelve cero.
    ///
    /// De a tandas y no con la cascada de una vez: una libreta de diez mil
    /// contactos sería una sola transacción de diez mil filas.
    pub fn remove_address_book_chunk(&mut self, book_id: i64) -> Result<usize, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        // No se lleva un cambio local sin confirmar: una fila marcada
        // (`pending_op`) se deja, igual que el guard de `apply_contacts` en la
        // bajada. El empuje la resuelve y un re-sync posterior la limpia.
        let removed = transaction
            .execute(
                "DELETE FROM contacts WHERE id IN
                   (SELECT id FROM contacts
                     WHERE address_book_id = ?1 AND pending_op IS NULL LIMIT ?2)",
                rusqlite::params![book_id, WRITE_BATCH_ROWS as i64],
            )
            .map_err(classify)?;
        let mut changed = removed > 0;
        if removed == 0 {
            // La libreta se borra sólo cuando no le queda ningún contacto: si
            // sobreviven filas marcadas, borrarla las arrastraría por la cascada
            // (`ON DELETE CASCADE`) y perdería el cambio local que el guard de
            // arriba acaba de proteger.
            changed |= transaction
                .execute(
                    "DELETE FROM address_books WHERE id = ?1
                      AND NOT EXISTS
                        (SELECT 1 FROM contacts WHERE address_book_id = ?1)",
                    [book_id],
                )
                .map_err(classify)?
                > 0;
        }
        let generation = if changed {
            Some(bump_generation(&transaction, CONTACTS_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CONTACTS_AREA, generation);
        }
        Ok(removed)
    }

    /// El `sync-token` guardado de una libreta.
    pub fn contacts_sync_token(&self, href: &str) -> Result<Option<String>, StoreError> {
        self.connection
            .query_row(
                "SELECT token FROM sync_state WHERE area = 'contacts' AND collection = ?1",
                [href],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map(Option::flatten)
            .map_err(classify)
    }

    /// Cuántos bytes ocupan las tarjetas crudas de toda la cuenta.
    ///
    /// Bytes y no caracteres (`octet_length`, no `length`): con acentos no es lo
    /// mismo, y el tope es de disco.
    pub fn contacts_raw_bytes(&self) -> Result<u64, StoreError> {
        self.connection
            .query_row(
                "SELECT coalesce(sum(octet_length(raw_vcard)), 0) FROM contacts",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|bytes| bytes.max(0) as u64)
            .map_err(classify)
    }

    /// El ETag de cada tarjeta guardada de una libreta, por dirección.
    pub fn contact_etags(
        &self,
        book_id: i64,
    ) -> Result<HashMap<String, Option<String>>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT href, etag FROM contacts WHERE address_book_id = ?1")
            .map_err(classify)?;
        let rows = statement
            .query_map([book_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Escribe un lote en **una** transacción, y con el último, dónde quedó la
    /// libreta.
    ///
    /// Una tarjeta que ya estaba se actualiza en su lugar —mismo `id`, así que
    /// la entrada del índice se reemplaza y no se duplica—, y sus correos y
    /// teléfonos se rehacen. Borrar lo que no está no es un error.
    ///
    /// **La libreta tiene que estar en esta base**, con el mismo `id` y la
    /// misma dirección; si no, `Err(Missing)` sin escribir nada. Un
    /// `ClearStore` a mitad de una vuelta rehace la base vacía, y la vuelta
    /// sigue con las libretas que leyó de la vieja: sin esta comprobación, el
    /// último lote —vacío si no había cambios— guardaba en la base nueva el
    /// token de una libreta que ahí no existe, y la vuelta siguiente pedía
    /// sólo las diferencias desde él. Lo de antes no volvía nunca.
    ///
    /// **`room` es cuánto puede crecer la cuenta con este lote**, en bytes de
    /// tarjetas crudas, y lo que se mide es el cambio neto: una tarjeta que
    /// reemplaza a otra cuenta la diferencia, y una que se borra resta. Si el
    /// lote pasaría de `room`, [`Applied::OverCap`] y no queda nada escrito
    /// —tampoco el token—. Contar cada tarjeta traída entera hacía que la
    /// carga completa de una cuenta por encima de la mitad del tope contara
    /// todo dos veces y fallara en cada vuelta, sin guardar nunca el token.
    pub fn apply_contacts(
        &mut self,
        book: &StoredAddressBook,
        ops: &[ContactOp],
        finish: Option<&BookProgress>,
        room: u64,
    ) -> Result<Applied, StoreError> {
        if ops.len() > WRITE_BATCH_ROWS {
            return Err(StoreError::Sqlite(format!(
                "un lote de {} contactos pasa el tope de {WRITE_BATCH_ROWS}",
                ops.len()
            )));
        }
        let transaction = self.connection.transaction().map_err(classify)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM address_books WHERE id = ?1 AND href = ?2)",
                rusqlite::params![book.id, book.href],
                |row| row.get(0),
            )
            .map_err(classify)?;
        if !exists {
            return Err(StoreError::Missing);
        }
        let at = now();
        // Lo que ocupaba cada tarjeta se lee en el momento de tocarla, dentro de
        // la transacción: una dirección que aparece dos veces en el lote se
        // cuenta contra lo que dejó la anterior.
        let mut net: i64 = 0;
        // Si el lote cambió algo que se ve: borrar lo que no estaba no cuenta.
        let mut changed = false;
        for op in ops {
            match op {
                ContactOp::Delete(href) => {
                    // La bajada no borra una tarjeta creada local que todavía no
                    // subió (`pending_op = 'put'`). Un `'delete'` local coincide
                    // con el borrado del servidor.
                    let mark = super::queue::pending_mark(
                        &transaction,
                        "contacts",
                        "address_book_id",
                        book.id,
                        href,
                    )?;
                    if mark.as_deref() == Some("put") {
                        continue;
                    }
                    let freed: Option<i64> = transaction
                        .prepare_cached(
                            "DELETE FROM contacts WHERE address_book_id = ?1 AND href = ?2
                             RETURNING octet_length(raw_vcard)",
                        )
                        .and_then(|mut s| {
                            s.query_row(rusqlite::params![book.id, href], |r| r.get(0))
                                .optional()
                        })
                        .map_err(classify)?;
                    changed |= freed.is_some();
                    net -= freed.unwrap_or(0);
                }
                ContactOp::Upsert(row) => {
                    // La bajada no pisa un cambio local sin confirmar.
                    let mark = super::queue::pending_mark(
                        &transaction,
                        "contacts",
                        "address_book_id",
                        book.id,
                        &row.href,
                    )?;
                    if mark.is_some() {
                        continue;
                    }
                    let replaced: Option<i64> = transaction
                        .prepare_cached(
                            "SELECT octet_length(raw_vcard) FROM contacts
                             WHERE address_book_id = ?1 AND href = ?2",
                        )
                        .and_then(|mut s| {
                            s.query_row(rusqlite::params![book.id, row.href], |r| r.get(0))
                                .optional()
                        })
                        .map_err(classify)?;
                    net += row.raw_vcard.len() as i64 - replaced.unwrap_or(0);
                    upsert_contact(&transaction, book.id, row, &at)?;
                    changed = true;
                }
            }
        }
        if net > 0 && net as u64 > room {
            // Sin `commit`: al soltarse, la transacción se deshace entera.
            return Ok(Applied::OverCap);
        }

        if let Some(finish) = finish {
            match &finish.token {
                Some(token) => transaction.execute(
                    "INSERT INTO sync_state (area, collection, token, updated_at)
                     VALUES ('contacts', ?1, ?2, ?3)
                     ON CONFLICT (area, collection) DO UPDATE SET
                       token = excluded.token, updated_at = excluded.updated_at",
                    rusqlite::params![book.href, token, at],
                ),
                None => transaction.execute(
                    "DELETE FROM sync_state WHERE area = 'contacts' AND collection = ?1",
                    [&book.href],
                ),
            }
            .map_err(classify)?;
            transaction
                .execute(
                    "UPDATE address_books SET ctag = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![finish.ctag, at, book.id],
                )
                .map_err(classify)?;
        }

        let generation = if changed {
            Some(bump_generation(&transaction, CONTACTS_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CONTACTS_AREA, generation);
        }
        Ok(Applied::Written { net_bytes: net })
    }

    /// Encola un `put` de una tarjeta: escribe el crudo **ya mismo** en la base,
    /// marcado con `pending_op = 'put'`, y suma la op con el cuerpo y el
    /// `base_etag`. La fila queda con `etag = base_etag` (nulo al crear), no con
    /// el del servidor: así la bajada no cree que cambió hasta que el empuje lo
    /// confirme.
    ///
    /// La libreta tiene que estar en esta base (mismo `id` y dirección), como en
    /// [`Self::apply_contacts`]; si no, `Err(Missing)`.
    // Lo encola la superficie D-Bus de escritura (`PutContact` en
    // `store_api.rs`), y lo ejercitan también las pruebas.
    pub fn enqueue_contact_put(
        &mut self,
        book: &StoredAddressBook,
        row: &ContactRow,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM address_books WHERE id = ?1 AND href = ?2)",
                rusqlite::params![book.id, book.href],
                |row| row.get(0),
            )
            .map_err(classify)?;
        if !exists {
            return Err(StoreError::Missing);
        }
        let at = now();
        upsert_contact(&transaction, book.id, row, &at)?;
        transaction
            .execute(
                "UPDATE contacts SET pending_op = 'put'
                  WHERE address_book_id = ?1 AND href = ?2",
                rusqlite::params![book.id, row.href],
            )
            .map_err(classify)?;
        super::queue::enqueue_put_op(
            &transaction,
            CONTACTS_AREA,
            &book.href,
            &row.href,
            row.etag.as_deref(),
            row.raw_vcard.as_bytes(),
        )?;
        let generation = bump_generation(&transaction, CONTACTS_AREA)?;
        transaction.commit().map_err(classify)?;
        self.note_change(CONTACTS_AREA, generation);
        Ok(())
    }

    /// Una libreta por su `id`, para encolar una escritura en ella. `None` si no
    /// está en esta base. Lo usa la superficie D-Bus de escritura
    /// (`store_api.rs`): la ventana nombra la libreta por su `id`, y de acá sale
    /// su `href`, que es con lo que la cola habla con el servidor.
    pub fn address_book_by_id(&self, id: i64) -> Result<Option<StoredAddressBook>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, href, ctag FROM address_books WHERE id = ?1",
                [id],
                |row| {
                    Ok(StoredAddressBook {
                        id: row.get(0)?,
                        href: row.get(1)?,
                        ctag: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(classify)
    }

    /// La libreta, el `href` y la vCard cruda de un contacto por su `id`, para
    /// editarlo o borrarlo. `None` si no está. El crudo es la fuente sobre la que
    /// la escritura conservadora aplica el parche (decisión 3); el `href` y el de
    /// la libreta son el alcance con el que la cola lo identifica en el servidor.
    pub fn contact_target(
        &self,
        id: i64,
    ) -> Result<Option<(StoredAddressBook, String, String)>, StoreError> {
        self.connection
            .query_row(
                "SELECT b.id, b.href, b.ctag, c.href, c.raw_vcard
                   FROM contacts c JOIN address_books b ON b.id = c.address_book_id
                  WHERE c.id = ?1",
                [id],
                |row| {
                    let book = StoredAddressBook {
                        id: row.get(0)?,
                        href: row.get(1)?,
                        ctag: row.get(2)?,
                    };
                    Ok((book, row.get(3)?, row.get(4)?))
                },
            )
            .optional()
            .map_err(classify)
    }

    /// El `id` de un contacto por su libreta y su `href`, recién encolado un
    /// `put` que lo creó: es lo que la respuesta de D-Bus le devuelve a la
    /// ventana para que lo vuelva a pedir.
    pub fn contact_id_by_href(&self, book_id: i64, href: &str) -> Result<Option<i64>, StoreError> {
        self.connection
            .query_row(
                "SELECT id FROM contacts WHERE address_book_id = ?1 AND href = ?2",
                rusqlite::params![book_id, href],
                |row| row.get(0),
            )
            .optional()
            .map_err(classify)
    }

    /// El enlace de enriquecimiento de un contacto por su `id`. `None` si
    /// todavía no se lo casó con ninguna persona de People API.
    pub fn contact_enrichment(
        &self,
        contact_id: i64,
    ) -> Result<Option<ContactEnrichment>, StoreError> {
        self.connection
            .query_row(
                "SELECT contact_id, resource_name, etag, photo_etag
                   FROM contact_enrichment WHERE contact_id = ?1",
                [contact_id],
                |row| {
                    Ok(ContactEnrichment {
                        contact_id: row.get(0)?,
                        resource_name: row.get(1)?,
                        etag: row.get(2)?,
                        photo_etag: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(classify)
    }

    /// Guarda (o reemplaza) el enlace de un contacto: un enlace por contacto, así
    /// que una corrida nueva de People API pisa el `resourceName` y los testigos
    /// del anterior. Si el contacto no está en esta base, la clave foránea lo
    /// rechaza; si otra fila ya reclamó ese `resource_name`, lo rechaza el
    /// `UNIQUE`.
    pub fn upsert_contact_enrichment(&self, link: &ContactEnrichment) -> Result<(), StoreError> {
        self.connection
            .execute(
                "INSERT INTO contact_enrichment (contact_id, resource_name, etag, photo_etag)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (contact_id) DO UPDATE SET
                     resource_name = excluded.resource_name,
                     etag = excluded.etag,
                     photo_etag = excluded.photo_etag",
                rusqlite::params![
                    link.contact_id,
                    link.resource_name,
                    link.etag,
                    link.photo_etag
                ],
            )
            .map(|_| ())
            .map_err(classify)
    }
}

fn upsert_contact(
    transaction: &rusqlite::Transaction<'_>,
    book_id: i64,
    row: &ContactRow,
    at: &str,
) -> Result<(), StoreError> {
    let contact = &row.contact;
    let id: i64 = transaction
        .prepare_cached(
            "INSERT INTO contacts
               (address_book_id, href, etag, uid, display_name, sort_key, raw_vcard, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT (address_book_id, href) DO UPDATE SET
               etag = excluded.etag, uid = excluded.uid, display_name = excluded.display_name,
               sort_key = excluded.sort_key, raw_vcard = excluded.raw_vcard,
               updated_at = excluded.updated_at
             RETURNING id",
        )
        .and_then(|mut s| {
            s.query_row(
                rusqlite::params![
                    book_id,
                    row.href,
                    row.etag,
                    contact.uid,
                    contact.display_name,
                    vcard::sort_key(&contact.sort_name),
                    row.raw_vcard,
                    at
                ],
                |r| r.get(0),
            )
        })
        .map_err(classify)?;

    for (table, fields) in [
        ("contact_emails", &contact.emails),
        ("contact_phones", &contact.phones),
    ] {
        transaction
            .prepare_cached(&format!("DELETE FROM {table} WHERE contact_id = ?1"))
            .and_then(|mut s| s.execute([id]))
            .map_err(classify)?;
        let mut insert = transaction
            .prepare_cached(&format!(
                "INSERT INTO {table} (contact_id, position, label, value) VALUES (?1, ?2, ?3, ?4)"
            ))
            .map_err(classify)?;
        for (position, field) in fields.iter().enumerate() {
            insert
                .execute(rusqlite::params![
                    id,
                    position as i64,
                    field.label,
                    field.value
                ])
                .map_err(classify)?;
        }
    }

    let joined = |fields: &[vcard::Field]| {
        fields
            .iter()
            .map(|f| f.value.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };
    transaction
        .prepare_cached("DELETE FROM contacts_fts WHERE rowid = ?1")
        .and_then(|mut s| s.execute([id]))
        .map_err(classify)?;
    transaction
        .prepare_cached(
            "INSERT INTO contacts_fts (rowid, name, emails, phones, organization)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .and_then(|mut s| {
            s.execute(rusqlite::params![
                id,
                contact.display_name,
                joined(&contact.emails),
                joined(&contact.phones),
                contact.organization
            ])
        })
        .map_err(classify)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use zeroize::Zeroizing;

    use super::super::key::StoreKey;
    use super::super::paths::tests::TempDir;
    use super::super::paths::StorePaths;
    use super::*;

    pub(crate) fn open_store(temp: &TempDir) -> Store {
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let key = StoreKey::from_secret(Zeroizing::new(vec![b'a'; 64])).unwrap();
        Store::create(&paths, &key).unwrap()
    }

    pub(crate) fn row(href: &str, name: &str, email: &str) -> Box<ContactRow> {
        let raw = format!("BEGIN:VCARD\r\nFN:{name}\r\nEMAIL:{email}\r\nEND:VCARD");
        Box::new(ContactRow {
            href: href.into(),
            etag: Some("\"1\"".into()),
            contact: vcard::contact_from(&raw, href).unwrap(),
            raw_vcard: raw,
        })
    }

    fn count(store: &Store, sql: &str) -> i64 {
        store
            .connection()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    /// La generación de los contactos sube una vez por lote que cambió algo, y
    /// no con uno que no cambió nada: el último de una libreta al día, borrar
    /// lo que no estaba, volver a listar las mismas libretas, o un lote que no
    /// entró en el tope.
    #[test]
    fn cada_lote_que_cambia_sube_la_generacion_y_el_que_no_la_deja() {
        let temp = TempDir::new("generacion");
        let mut store = open_store(&temp);
        let generation = |store: &Store| {
            super::super::read_generation(store.connection(), CONTACTS_AREA).unwrap()
        };
        assert_eq!(generation(&store), 0);
        assert!(store.take_changes().is_empty());

        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        let first = store.take_changes();
        assert_eq!(first, vec![(CONTACTS_AREA, generation(&store))]);
        assert!(first[0].1 > 0);

        // Las mismas libretas otra vez: nada.
        store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap();
        assert!(store.take_changes().is_empty());

        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(
                    "https://x/a/1.vcf",
                    "Ana",
                    "a@x.com",
                ))],
                None,
                u64::MAX,
            )
            .unwrap();
        let second = store.take_changes();
        assert_eq!(second.len(), 1);
        assert!(second[0].1 > first[0].1, "sólo crece");

        // El último lote, vacío, que sólo guarda el token; y borrar lo que no
        // estaba.
        let finish = BookProgress {
            token: Some("t2".into()),
            ctag: None,
        };
        store
            .apply_contacts(&book, &[], Some(&finish), u64::MAX)
            .unwrap();
        store
            .apply_contacts(
                &book,
                &[ContactOp::Delete("https://x/a/nunca.vcf".into())],
                None,
                u64::MAX,
            )
            .unwrap();
        assert!(store.take_changes().is_empty());

        // Uno que no entra en el tope no escribió nada.
        let before = generation(&store);
        let over = store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(
                    "https://x/a/2.vcf",
                    "Beto",
                    "b@x.com",
                ))],
                None,
                1,
            )
            .unwrap();
        assert_eq!(over, Applied::OverCap);
        assert!(store.take_changes().is_empty());
        assert_eq!(generation(&store), before);

        // Borrar la libreta de a tandas: cambia.
        while store.remove_address_book_chunk(book.id).unwrap() > 0 {}
        assert_eq!(store.take_changes().len(), 1);
        assert!(generation(&store) > before);
    }

    /// La generación vive en la base: cerrar y volver a abrir no la vuelve a
    /// cero, y una base nueva empieza más arriba que la anterior.
    #[test]
    fn la_generacion_sobrevive_a_reabrir_y_una_base_nueva_empieza_mas_arriba() {
        let temp = TempDir::new("generacion-persiste");
        let mut store = open_store(&temp);
        store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap();
        let written = store.take_changes()[0].1;
        drop(store);

        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let key = StoreKey::from_secret(Zeroizing::new(vec![b'a'; 64])).unwrap();
        let store = Store::open(&paths, &key).unwrap();
        assert_eq!(
            super::super::read_generation(store.connection(), CONTACTS_AREA).unwrap(),
            written
        );
        drop(store);

        let other = TempDir::new("generacion-nueva");
        let mut fresh = open_store(&other);
        assert!(fresh.touch(CONTACTS_AREA).unwrap() > written);
    }

    /// Volver a escribir una tarjeta la reemplaza: mismo `id`, sus datos
    /// rehechos, una sola entrada en el índice.
    #[test]
    fn escribir_dos_veces_la_misma_tarjeta_es_escribirla_una() {
        let temp = TempDir::new("contactos-upsert");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);

        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(
                    "https://x/a/1.vcf",
                    "Ana",
                    "ana@x.com",
                ))],
                None,
                u64::MAX,
            )
            .unwrap();
        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(
                    "https://x/a/1.vcf",
                    "Ana María",
                    "am@x.com",
                ))],
                None,
                u64::MAX,
            )
            .unwrap();

        assert_eq!(count(&store, "SELECT count(*) FROM contacts"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM contact_emails"), 1);
        let email: String = store
            .connection()
            .query_row("SELECT value FROM contact_emails", [], |r| r.get(0))
            .unwrap();
        assert_eq!(email, "am@x.com");
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM contacts_fts WHERE contacts_fts MATCH 'maria'"
            ),
            1
        );
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM contacts_fts WHERE contacts_fts MATCH '\"ana x com\"'"
            ),
            0,
            "el correo viejo no queda en el índice"
        );
    }

    /// Lo que ocupan las tarjetas crudas se cuenta en bytes, de todas las
    /// libretas, y una tarjeta reescrita cuenta una vez.
    #[test]
    fn los_bytes_de_las_tarjetas_se_cuentan_en_bytes() {
        let temp = TempDir::new("contactos-bytes");
        let mut store = open_store(&temp);
        assert_eq!(store.contacts_raw_bytes().unwrap(), 0);
        let books = store
            .upsert_address_books(&[
                ("https://x/a/".into(), "A".into()),
                ("https://x/b/".into(), "B".into()),
            ])
            .unwrap();
        let ana = row("https://x/a/1.vcf", "Ñandú", "ana@x.com");
        let juan = row("https://x/b/1.vcf", "Juan", "juan@x.com");
        let expected = (ana.raw_vcard.len() + juan.raw_vcard.len()) as u64;
        assert!(ana.raw_vcard.len() > ana.raw_vcard.chars().count());
        store
            .apply_contacts(&books[0], &[ContactOp::Upsert(ana.clone())], None, u64::MAX)
            .unwrap();
        store
            .apply_contacts(&books[0], &[ContactOp::Upsert(ana)], None, u64::MAX)
            .unwrap();
        store
            .apply_contacts(&books[1], &[ContactOp::Upsert(juan)], None, u64::MAX)
            .unwrap();
        assert_eq!(store.contacts_raw_bytes().unwrap(), expected);
    }

    /// El token y el `getctag` van con el lote, y sin lote no cambian.
    #[test]
    fn el_token_se_guarda_con_el_ultimo_lote() {
        let temp = TempDir::new("contactos-token");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        assert_eq!(store.contacts_sync_token(&book.href).unwrap(), None);

        store
            .apply_contacts(
                &book,
                &[],
                Some(&BookProgress {
                    token: Some("t1".into()),
                    ctag: Some("c1".into()),
                }),
                u64::MAX,
            )
            .unwrap();
        assert_eq!(
            store.contacts_sync_token(&book.href).unwrap().as_deref(),
            Some("t1")
        );
        assert_eq!(
            store.address_books().unwrap()[0].ctag.as_deref(),
            Some("c1")
        );

        // Volver a listar las libretas no toca el `getctag`.
        store
            .upsert_address_books(&[("https://x/a/".into(), "Otro nombre".into())])
            .unwrap();
        assert_eq!(
            store.address_books().unwrap()[0].ctag.as_deref(),
            Some("c1")
        );

        // Y sin token nuevo, se borra el que había.
        store
            .apply_contacts(
                &book,
                &[],
                Some(&BookProgress {
                    token: None,
                    ctag: None,
                }),
                u64::MAX,
            )
            .unwrap();
        assert_eq!(store.contacts_sync_token(&book.href).unwrap(), None);
    }

    /// **El lugar que pide un lote es su cambio neto.** Reescribir una tarjeta
    /// cuenta la diferencia, borrar resta, y un lote que crece más que `room`
    /// no escribe nada, ni el token.
    #[test]
    fn el_lote_cuenta_el_cambio_neto_contra_el_lugar() {
        let temp = TempDir::new("contactos-neto");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        let ana = row("https://x/a/1.vcf", "Ana María López", "ana@x.com");
        let juan = row("https://x/a/2.vcf", "Juan", "j@x.com");
        let (ana_len, juan_len) = (ana.raw_vcard.len() as i64, juan.raw_vcard.len() as i64);
        assert!(juan_len < ana_len);

        assert_eq!(
            store
                .apply_contacts(&book, &[ContactOp::Upsert(ana.clone())], None, u64::MAX)
                .unwrap(),
            Applied::Written { net_bytes: ana_len }
        );
        // La misma tarjeta otra vez no crece: entra sin lugar.
        assert_eq!(
            store
                .apply_contacts(&book, &[ContactOp::Upsert(ana.clone())], None, 0)
                .unwrap(),
            Applied::Written { net_bytes: 0 }
        );

        // Una nueva que no entra: nada escrito, tampoco el token.
        let progress = BookProgress {
            token: Some("t2".into()),
            ctag: None,
        };
        assert_eq!(
            store
                .apply_contacts(
                    &book,
                    &[ContactOp::Upsert(juan.clone())],
                    Some(&progress),
                    juan_len as u64 - 1,
                )
                .unwrap(),
            Applied::OverCap
        );
        assert_eq!(count(&store, "SELECT count(*) FROM contacts"), 1);
        assert_eq!(store.contacts_sync_token(&book.href).unwrap(), None);
        assert_eq!(store.contacts_raw_bytes().unwrap(), ana_len as u64);

        // Borrar una y traer otra más chica en el mismo lote achica la cuenta,
        // y entra sin lugar.
        assert_eq!(
            store
                .apply_contacts(
                    &book,
                    &[ContactOp::Delete(ana.href.clone()), ContactOp::Upsert(juan),],
                    Some(&progress),
                    0,
                )
                .unwrap(),
            Applied::Written {
                net_bytes: juan_len - ana_len
            }
        );
        assert_eq!(store.contacts_raw_bytes().unwrap(), juan_len as u64);
        assert_eq!(
            store.contacts_sync_token(&book.href).unwrap().as_deref(),
            Some("t2")
        );
    }

    /// **Un lote de una libreta que no está en la base no escribe nada**, ni el
    /// token. Es la base que rehízo un `ClearStore` a mitad de una vuelta: la
    /// libreta leída de la vieja no existe en la nueva, o su `id` es ahora el
    /// de otra.
    #[test]
    fn un_lote_de_una_libreta_que_no_esta_no_guarda_el_token() {
        let old = TempDir::new("contactos-libreta-vieja");
        let book = open_store(&old)
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        let progress = BookProgress {
            token: Some("t9".into()),
            ctag: Some("c9".into()),
        };

        // La base nueva, vacía: el último lote de la libreta, sin cambios.
        let fresh = TempDir::new("contactos-libreta-nueva");
        let mut store = open_store(&fresh);
        assert!(matches!(
            store.apply_contacts(&book, &[], Some(&progress), u64::MAX),
            Err(StoreError::Missing)
        ));
        assert_eq!(store.contacts_sync_token(&book.href).unwrap(), None);
        assert_eq!(count(&store, "SELECT count(*) FROM sync_state"), 0);

        // Y con el mismo `id` ocupado por otra libreta, tampoco: ni el token
        // ni las tarjetas van a parar a ella.
        let other = store
            .upsert_address_books(&[("https://x/b/".into(), "B".into())])
            .unwrap()
            .remove(0);
        assert_eq!(other.id, book.id);
        assert!(matches!(
            store.apply_contacts(
                &book,
                &[ContactOp::Upsert(row(
                    "https://x/a/1.vcf",
                    "Ana",
                    "a@x.com"
                ))],
                Some(&progress),
                u64::MAX,
            ),
            Err(StoreError::Missing)
        ));
        assert_eq!(count(&store, "SELECT count(*) FROM contacts"), 0);
        assert_eq!(count(&store, "SELECT count(*) FROM sync_state"), 0);
        assert_eq!(store.address_books().unwrap()[0].ctag, None);
    }

    /// Un lote de más de quinientos no entra: el tope lo pone el que escribe,
    /// no la buena voluntad de quien arma los lotes.
    #[test]
    fn un_lote_de_mas_no_se_escribe() {
        let temp = TempDir::new("contactos-tope");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        let ops: Vec<ContactOp> = (0..=WRITE_BATCH_ROWS)
            .map(|i| ContactOp::Delete(format!("https://x/a/{i}.vcf")))
            .collect();
        assert!(store.apply_contacts(&book, &ops, None, u64::MAX).is_err());
    }

    /// Una libreta que se va se borra de a tandas, y con la última se va ella.
    #[test]
    fn una_libreta_se_borra_de_a_tandas() {
        let temp = TempDir::new("contactos-libreta");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        for start in [0, WRITE_BATCH_ROWS] {
            let ops: Vec<ContactOp> = (start..start + WRITE_BATCH_ROWS)
                .map(|i| ContactOp::Upsert(row(&format!("https://x/a/{i}.vcf"), "Ana", "a@x.com")))
                .collect();
            store.apply_contacts(&book, &ops, None, u64::MAX).unwrap();
        }
        store
            .apply_contacts(
                &book,
                &[],
                Some(&BookProgress {
                    token: Some("t".into()),
                    ctag: None,
                }),
                u64::MAX,
            )
            .unwrap();

        assert_eq!(
            store.remove_address_book_chunk(book.id).unwrap(),
            WRITE_BATCH_ROWS
        );
        assert_eq!(
            store.remove_address_book_chunk(book.id).unwrap(),
            WRITE_BATCH_ROWS
        );
        assert_eq!(store.address_books().unwrap().len(), 1);
        assert_eq!(store.remove_address_book_chunk(book.id).unwrap(), 0);
        assert!(store.address_books().unwrap().is_empty());
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM contacts_fts WHERE contacts_fts MATCH 'ana'"
            ),
            0
        );
        assert_eq!(store.contacts_sync_token(&book.href).unwrap(), None);
    }

    /// El borrado masivo de una libreta que se fue del servidor no se lleva un
    /// contacto con cambio local sin confirmar: los sin marca se borran, el
    /// marcado (`pending_op`) queda, y la libreta no se borra mientras le quede
    /// uno —la cascada se lo llevaría—.
    #[test]
    fn el_borrado_masivo_respeta_un_contacto_con_pending_op() {
        let temp = TempDir::new("contactos-remove-pending");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        store
            .apply_contacts(
                &book,
                &[
                    ContactOp::Upsert(row("https://x/a/a.vcf", "Ana", "a@x.com")),
                    ContactOp::Upsert(row("https://x/a/b.vcf", "Beto", "b@x.com")),
                ],
                None,
                u64::MAX,
            )
            .unwrap();
        // «b» tiene un borrado local todavía sin subir.
        store
            .enqueue_delete(
                CONTACTS_AREA,
                &book.href,
                "https://x/a/b.vcf",
                Some("\"1\""),
            )
            .unwrap();

        while store.remove_address_book_chunk(book.id).unwrap() > 0 {}

        // «a» (sin marca) se fue; «b» (marcada) quedó.
        assert_eq!(count(&store, "SELECT count(*) FROM contacts"), 1);
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM contacts WHERE href = 'https://x/a/b.vcf'"
            ),
            1
        );
        // La libreta no se borró: borrarla se habría llevado «b» por la cascada.
        assert_eq!(store.address_books().unwrap().len(), 1);
    }

    /// Guardar un enlace de enriquecimiento y leerlo de vuelta; y que una
    /// segunda escritura del mismo contacto pisa la anterior en vez de duplicar.
    #[test]
    fn el_enlace_de_enriquecimiento_va_y_vuelve_y_el_upsert_pisa() {
        let temp = TempDir::new("enriquecimiento");
        let mut store = open_store(&temp);
        let book = store
            .upsert_address_books(&[("https://x/a/".into(), "A".into())])
            .unwrap()
            .remove(0);
        store
            .apply_contacts(
                &book,
                &[ContactOp::Upsert(row(
                    "https://x/a/1.vcf",
                    "Ana",
                    "a@x.com",
                ))],
                None,
                u64::MAX,
            )
            .unwrap();
        let contact_id = store
            .contact_id_by_href(book.id, "https://x/a/1.vcf")
            .unwrap()
            .unwrap();

        // Antes de casar, no hay enlace.
        assert_eq!(store.contact_enrichment(contact_id).unwrap(), None);

        let link = ContactEnrichment {
            contact_id,
            resource_name: "people/c1".into(),
            etag: Some("\"e1\"".into()),
            photo_etag: None,
        };
        store.upsert_contact_enrichment(&link).unwrap();
        assert_eq!(store.contact_enrichment(contact_id).unwrap(), Some(link));

        // Una corrida nueva pisa el enlace: mismo contacto, una sola fila.
        let updated = ContactEnrichment {
            contact_id,
            resource_name: "people/c1".into(),
            etag: Some("\"e2\"".into()),
            photo_etag: Some("\"p2\"".into()),
        };
        store.upsert_contact_enrichment(&updated).unwrap();
        assert_eq!(store.contact_enrichment(contact_id).unwrap(), Some(updated));
        assert_eq!(count(&store, "SELECT count(*) FROM contact_enrichment"), 1);

        // Un contacto que no existe lo rechaza la clave foránea.
        let orphan = ContactEnrichment {
            contact_id: contact_id + 999,
            resource_name: "people/c2".into(),
            etag: None,
            photo_etag: None,
        };
        assert!(store.upsert_contact_enrichment(&orphan).is_err());
    }
}
