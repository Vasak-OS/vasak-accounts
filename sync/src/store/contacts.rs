//! Los contactos en la base: lo que escribe la sincronización.
//!
//! Sólo escritura y lo que la sincronización necesita leer para decidir qué
//! pedir (los ETag y el token de cada libreta). Listar y buscar para las
//! aplicaciones es del PR 3.
//!
//! **Todo en lotes**: una transacción lleva como mucho [`WRITE_BATCH_ROWS`]
//! contactos —cada uno con sus correos, sus teléfonos y su entrada del
//! índice—, así que tener la base tomada nunca dura más que eso. El token de
//! la libreta se guarda **en la misma transacción que el último lote**: si la
//! sincronización se corta a mitad, lo escrito queda y el token es el de
//! antes, y la próxima vuelta repite desde ahí sin perder nada. Escribir dos
//! veces la misma tarjeta es escribirla una.

use std::collections::HashMap;

use rusqlite::OptionalExtension;

use super::{classify, Store, StoreError};
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
        transaction.commit().map_err(classify)?;
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
        let removed = transaction
            .execute(
                "DELETE FROM contacts WHERE id IN
                   (SELECT id FROM contacts WHERE address_book_id = ?1 LIMIT ?2)",
                rusqlite::params![book_id, WRITE_BATCH_ROWS as i64],
            )
            .map_err(classify)?;
        if removed == 0 {
            transaction
                .execute("DELETE FROM address_books WHERE id = ?1", [book_id])
                .map_err(classify)?;
        }
        transaction.commit().map_err(classify)?;
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
    pub fn apply_contacts(
        &mut self,
        book: &StoredAddressBook,
        ops: &[ContactOp],
        finish: Option<&BookProgress>,
    ) -> Result<(), StoreError> {
        if ops.len() > WRITE_BATCH_ROWS {
            return Err(StoreError::Sqlite(format!(
                "un lote de {} contactos pasa el tope de {WRITE_BATCH_ROWS}",
                ops.len()
            )));
        }
        let transaction = self.connection.transaction().map_err(classify)?;
        let at = now();
        for op in ops {
            match op {
                ContactOp::Delete(href) => {
                    transaction
                        .prepare_cached(
                            "DELETE FROM contacts WHERE address_book_id = ?1 AND href = ?2",
                        )
                        .and_then(|mut s| s.execute(rusqlite::params![book.id, href]))
                        .map_err(classify)?;
                }
                ContactOp::Upsert(row) => upsert_contact(&transaction, book.id, row, &at)?,
            }
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

        transaction.commit().map_err(classify)
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

    fn row(href: &str, name: &str, email: &str) -> Box<ContactRow> {
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
            )
            .unwrap();
        assert_eq!(store.contacts_sync_token(&book.href).unwrap(), None);
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
        assert!(store.apply_contacts(&book, &ops, None).is_err());
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
            store.apply_contacts(&book, &ops, None).unwrap();
        }
        store
            .apply_contacts(
                &book,
                &[],
                Some(&BookProgress {
                    token: Some("t".into()),
                    ctag: None,
                }),
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
}
