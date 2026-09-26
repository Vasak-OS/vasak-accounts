//! El esquema de la base, versión por versión.
//!
//! Con `rusqlite_migration`, que lleva la cuenta en `PRAGMA user_version` y no
//! en una tabla propia. **Una migración por PR, y nunca se edita una ya
//! mergeada**: una base que ya la aplicó no la vuelve a correr, así que editarla
//! deja dos bases con la misma versión y esquemas distintos.
//!
//! Una base de una versión **más nueva** que este programa —alguien volvió a
//! un paquete anterior— no se abre y no se toca: `to_latest` falla y el ciclo
//! de vida la marca como no disponible, sin borrarla.

use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

use super::StoreError;

/// Cuántas filas guarda la bitácora de la sincronización, como mucho.
///
/// Mil: alcanza para ver qué pasó en las últimas semanas de una cuenta con
/// problemas, y no crece para siempre en una que anda bien. El tope lo aplica
/// un disparador al insertar —ver `V1`—, así que no depende de que alguien se
/// acuerde de podar.
///
/// Una macro y no una constante porque el número tiene que quedar escrito
/// **dentro** del texto de la migración, que es `&'static str`: así la prueba y
/// el disparador leen el mismo número y no pueden separarse.
macro_rules! sync_log_cap {
    () => {
        1000
    };
}

/// v1 (PR 1): la base vacía.
///
/// - `store_meta`: pares clave-valor de la base misma —cuándo se creó—.
/// - `sync_state`: dónde quedó la sincronización de cada colección de cada área
///   (el `sync-token` de DAV, el `HIGHESTMODSEQ` de IMAP), para seguir desde
///   ahí y no traer todo de nuevo.
/// - `sync_log`: la bitácora, con tope de filas.
///
/// El tope va con `AUTOINCREMENT`, que garantiza identificadores que no se
/// reusan: así «las últimas mil» son las de identificador más alto, y el
/// disparador borra con una sola comparación y sin contar filas.
const V1: &str = concat!(
    "
CREATE TABLE store_meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE sync_state (
    area       TEXT NOT NULL CHECK (area IN ('email', 'calendar', 'contacts')),
    collection TEXT NOT NULL,
    token      TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (area, collection)
) STRICT;

CREATE TABLE sync_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT NOT NULL,
    level   TEXT NOT NULL CHECK (level IN ('info', 'warn', 'error')),
    area    TEXT,
    message TEXT NOT NULL
) STRICT;

CREATE TRIGGER sync_log_cap AFTER INSERT ON sync_log
BEGIN
    DELETE FROM sync_log WHERE id <= NEW.id - ",
    sync_log_cap!(),
    ";
END;
"
);

/// Todas las migraciones, en orden.
pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(V1)])
}

/// Lleva la base a la última versión. Aplicarlo sobre una base al día no hace
/// nada.
pub fn apply(connection: &mut Connection) -> Result<(), StoreError> {
    migrations()
        .to_latest(connection)
        .map_err(|e| StoreError::Schema(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNC_LOG_CAP: i64 = sync_log_cap!();

    fn schema_version(connection: &Connection) -> Result<i64, StoreError> {
        connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| StoreError::Sqlite(e.to_string()))
    }

    /// Lo que pide la biblioteca: que todas las migraciones corran sobre una
    /// base vacía. Atrapa un error de sintaxis antes de que llegue a la base de
    /// nadie.
    #[test]
    fn las_migraciones_son_validas() {
        migrations().validate().unwrap();
    }

    #[test]
    fn aplicar_dos_veces_no_cambia_nada() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        let version = schema_version(&connection).unwrap();
        assert_eq!(version, 1);

        let tables = |c: &Connection| -> Vec<String> {
            let mut statement = c
                .prepare("SELECT name FROM sqlite_master ORDER BY name")
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let before = tables(&connection);

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), version);
        assert_eq!(tables(&connection), before);
        for table in ["store_meta", "sync_state", "sync_log", "sync_log_cap"] {
            assert!(before.iter().any(|t| t == table), "falta {table}");
        }
    }

    /// Una base de una versión más nueva que este programa no se toca.
    #[test]
    fn una_base_mas_nueva_no_se_abre() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        assert!(matches!(apply(&mut connection), Err(StoreError::Schema(_))));
        assert_eq!(schema_version(&connection).unwrap(), 99);
    }

    /// La bitácora no pasa de su tope, y lo que queda es lo último.
    #[test]
    fn la_bitacora_tiene_tope_y_guarda_lo_ultimo() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();

        let extra = 500;
        let transaction = connection.transaction().unwrap();
        for i in 0..SYNC_LOG_CAP + extra {
            transaction
                .execute(
                    "INSERT INTO sync_log (at, level, area, message) VALUES ('ahora', 'info', NULL, ?1)",
                    [format!("línea {i}")],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        let (count, min, max): (i64, i64, i64) = connection
            .query_row(
                "SELECT count(*), min(id), max(id) FROM sync_log",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            count, SYNC_LOG_CAP,
            "el disparador y la constante no coinciden"
        );
        assert_eq!(max, SYNC_LOG_CAP + extra);
        assert_eq!(min, extra + 1);
        let oldest: String = connection
            .query_row("SELECT message FROM sync_log WHERE id = ?1", [min], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(oldest, format!("línea {extra}"));
    }

    #[test]
    fn el_estado_de_sincronizacion_es_uno_por_coleccion_y_area() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        let insert = "INSERT INTO sync_state (area, collection, token, updated_at) VALUES (?1, ?2, ?3, 'ahora')";
        connection
            .execute(insert, ["contacts", "/libreta", "t1"])
            .unwrap();
        connection
            .execute(insert, ["calendar", "/libreta", "t2"])
            .unwrap();
        assert!(connection
            .execute(insert, ["contacts", "/libreta", "t3"])
            .is_err());
        assert!(
            connection.execute(insert, ["archivos", "/x", "t"]).is_err(),
            "un área desconocida no entra"
        );
    }
}
