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

/// Cómo quedó un lote de [`Store::apply_contacts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Escrito. Cuántos bytes de tarjetas crudas sumó a la cuenta —negativo si
    /// borró o achicó más de lo que agregó—.
    Written { net_bytes: i64 },
    /// No se escribió nada: la cuenta crecería más de lo que había lugar.
    OverCap,
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
        for op in ops {
            match op {
                ContactOp::Delete(href) => {
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
                    net -= freed.unwrap_or(0);
                }
                ContactOp::Upsert(row) => {
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

        transaction.commit().map_err(classify)?;
        Ok(Applied::Written { net_bytes: net })
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
}
