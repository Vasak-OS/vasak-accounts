//! El peerstate OpenPGP: las claves públicas de terceros, por dirección de
//! correo. Sólo estado del almacén cifrado (tabla de la migración V14), **sin
//! red** y **sin decidir confianza**: esta capa guarda y devuelve bytes; la
//! política TOFU (quedarse con la primera clave vista, avisar si cambia) y la
//! ingesta desde Autocrypt o desde los adjuntos `application/pgp-keys` son PR3/PR4,
//! y WKD (resolver por HTTPS) es PR6.
//!
//! Helpers calcados de las colas privadas del correo ([`super::snooze`]):
//! funciones puras sobre `&Connection` para leer, y métodos de [`Store`] para
//! escribir (el único que tiene la conexión de escritura). Los tiempos son
//! segundos epoch (`INTEGER`) que recibe quien llama, como `snoozed_messages` y
//! `alarms`: deterministas, no miran el reloj.
//!
//! **Una fila por dirección** (`UNIQUE (address)`): volver a ver la clave de un
//! contacto **actualiza** su clave, su huella y `updated_at` (upsert por
//! `address`), conservando `first_seen` —lo mínimo para TOFU: cuándo se vio por
//! primera vez y cuándo se actualizó—. La **dirección se guarda tal como la pasa
//! quien llama**: normalizarla (minúsculas, canónica) es decisión de la ingesta
//! (PR3/PR4), no del almacén.
//!
//! No lleva `account_id`: hay una base por cuenta, así que un `ClearStore` o
//! quitar la cuenta se lleva el peerstate con la base (como `snoozed_messages`).
// PR2 es sólo almacenamiento: lo consumen la ingesta de Autocrypt/adjuntos (PR4)
// y la resolución de destinatarios (PR6), que todavía no están. Hasta que lo
// llamen, el chequeo de código muerto lo marcaría entero; se saca al engancharlo.
// Mismo criterio que `pgp.rs` del PR1 y `smime_key`.
#![cfg_attr(not(test), allow(dead_code))]

use rusqlite::Connection;

use super::{classify, Store, StoreError};

/// La clave pública conocida de una dirección (peerstate TOFU). `public_key` son
/// los bytes de la clave OpenPGP tal como se ingirieron (armor o binario),
/// `fingerprint` su huella en texto, y `first_seen`/`updated_at` cuándo se vio por
/// primera vez y cuándo se actualizó por última, en segundos epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgpPeer {
    pub id: i64,
    pub address: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub first_seen: i64,
    pub updated_at: i64,
}

/// Guarda la clave de una dirección, o la actualiza si ya se la conocía: upsert
/// por `address`. Actualizar pisa la clave, la huella y `updated_at`, y conserva
/// `first_seen`; no duplica ni falla. `now` es segundos epoch.
pub fn upsert_peer(
    connection: &Connection,
    address: &str,
    public_key: &[u8],
    fingerprint: &str,
    now: i64,
) -> Result<(), StoreError> {
    connection
        .execute(
            "INSERT INTO pgp_peers (address, public_key, fingerprint, first_seen, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT (address) DO UPDATE SET
                     public_key = excluded.public_key,
                     fingerprint = excluded.fingerprint,
                     updated_at = excluded.updated_at",
            rusqlite::params![address, public_key, fingerprint, now],
        )
        .map_err(classify)?;
    Ok(())
}

/// Refresca sólo `updated_at` de una dirección ya conocida, sin tocar `public_key`
/// ni `fingerprint`. La ingesta TOFU lo usa en la rama de **misma huella**: un blob
/// entrante con la misma primaria pero una subclave de cifrado quitada (o una
/// revocación) no debe **reducir** la clave guardada —escrituras conservadoras,
/// decisión 3—. `now` es segundos epoch. Si la dirección no existe, no hace nada.
pub fn touch_peer(connection: &Connection, address: &str, now: i64) -> Result<(), StoreError> {
    connection
        .execute(
            "UPDATE pgp_peers SET updated_at = ?2 WHERE address = ?1",
            rusqlite::params![address, now],
        )
        .map_err(classify)?;
    Ok(())
}

/// La clave conocida de una dirección, o nada si no se la conoce.
pub fn find_peer(connection: &Connection, address: &str) -> Result<Option<PgpPeer>, StoreError> {
    connection
        .query_row(
            "SELECT id, address, public_key, fingerprint, first_seen, updated_at
               FROM pgp_peers WHERE address = ?1",
            rusqlite::params![address],
            row_to_peer,
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(classify(other)),
        })
}

/// Todas las claves conocidas, ordenadas por dirección.
pub fn list_peers(connection: &Connection) -> Result<Vec<PgpPeer>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, address, public_key, fingerprint, first_seen, updated_at
               FROM pgp_peers ORDER BY address",
        )
        .map_err(classify)?;
    let rows = statement.query_map([], row_to_peer).map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// La escritura del peerstate pasa por el `Store`, que es el único que tiene la
/// conexión de escritura (como el resto de las mutaciones). Las lecturas van por
/// las funciones libres de arriba, así que no necesitan método acá.
impl Store {
    /// Guarda (o actualiza) la clave de una dirección. Delega en [`upsert_peer`].
    pub fn upsert_peer(
        &self,
        address: &str,
        public_key: &[u8],
        fingerprint: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        upsert_peer(&self.connection, address, public_key, fingerprint, now)
    }

    /// Refresca sólo `updated_at` de una dirección conocida, sin reescribir la clave.
    /// Delega en [`touch_peer`]. La ingesta TOFU ([`crate::pgp_import::ingest_peer_key`])
    /// lo usa en la rama de misma huella —por eso hay método, no sólo función libre—.
    pub fn touch_peer(&self, address: &str, now: i64) -> Result<(), StoreError> {
        touch_peer(&self.connection, address, now)
    }

    /// La clave conocida de una dirección, o nada. Delega en [`find_peer`]. La
    /// ingesta TOFU ([`crate::pgp_import::ingest_peer_key`]) la necesita fuera de
    /// `cfg(test)` —por eso hay método, no sólo la función libre—: lee el estado
    /// previo antes de pisar, para detectar el cambio de clave.
    pub fn find_peer(&self, address: &str) -> Result<Option<PgpPeer>, StoreError> {
        find_peer(&self.connection, address)
    }
}

fn row_to_peer(row: &rusqlite::Row) -> rusqlite::Result<PgpPeer> {
    Ok(PgpPeer {
        id: row.get(0)?,
        address: row.get(1)?,
        public_key: row.get(2)?,
        fingerprint: row.get(3)?,
        first_seen: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::super::contacts::tests::open_store;
    use super::super::paths::tests::TempDir;
    use super::*;

    #[test]
    fn upsert_inserta_y_find_devuelve_la_fila() {
        let temp = TempDir::new("pgp-peer-inserta");
        let store = open_store(&temp);
        store
            .upsert_peer("ana@example.com", b"clave-1", "AAAA", 100)
            .unwrap();

        let peer = find_peer(store.connection(), "ana@example.com")
            .unwrap()
            .expect("hay peer");
        assert_eq!(peer.address, "ana@example.com");
        assert_eq!(peer.public_key, b"clave-1");
        assert_eq!(peer.fingerprint, "AAAA");
        assert_eq!(peer.first_seen, 100);
        assert_eq!(peer.updated_at, 100);
    }

    #[test]
    fn volver_a_ver_la_clave_actualiza_y_conserva_first_seen_sin_duplicar() {
        let temp = TempDir::new("pgp-peer-upsert");
        let store = open_store(&temp);
        store
            .upsert_peer("ana@example.com", b"clave-1", "AAAA", 100)
            .unwrap();
        let first = find_peer(store.connection(), "ana@example.com")
            .unwrap()
            .unwrap();
        store
            .upsert_peer("ana@example.com", b"clave-2", "BBBB", 200)
            .unwrap();

        let rows = list_peers(store.connection()).unwrap();
        assert_eq!(rows.len(), 1, "una fila por dirección");
        let peer = &rows[0];
        assert_eq!(peer.id, first.id, "es la misma fila, no una nueva");
        assert_eq!(peer.public_key, b"clave-2");
        assert_eq!(peer.fingerprint, "BBBB");
        assert_eq!(peer.updated_at, 200);
        assert_eq!(peer.first_seen, 100, "TOFU: first_seen no se pisa");
    }

    #[test]
    fn una_direccion_desconocida_no_tiene_peer() {
        let temp = TempDir::new("pgp-peer-nada");
        let store = open_store(&temp);
        store
            .upsert_peer("ana@example.com", b"k", "AAAA", 1)
            .unwrap();
        assert!(find_peer(store.connection(), "beto@example.com")
            .unwrap()
            .is_none());
        // La dirección se guarda tal cual: otra capitalización es otra fila.
        assert!(find_peer(store.connection(), "ANA@example.com")
            .unwrap()
            .is_none());
    }

    #[test]
    fn la_lista_sale_ordenada_por_direccion() {
        let temp = TempDir::new("pgp-peer-orden");
        let store = open_store(&temp);
        assert!(list_peers(store.connection()).unwrap().is_empty());
        for address in ["carla@x.com", "ana@x.com", "beto@x.com"] {
            store.upsert_peer(address, b"k", "F", 1).unwrap();
        }
        let addresses: Vec<String> = list_peers(store.connection())
            .unwrap()
            .into_iter()
            .map(|p| p.address)
            .collect();
        assert_eq!(addresses, ["ana@x.com", "beto@x.com", "carla@x.com"]);
    }
}
