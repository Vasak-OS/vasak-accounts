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

/// v2 (PR 2): los contactos.
///
/// **La tarjeta cruda es la fuente de verdad** (decisión 3 del taller):
/// `contacts.raw_vcard` guarda la vCard tal como vino del servidor, y todo lo
/// demás —el nombre, la clave para ordenar, los correos, los teléfonos, el
/// índice de búsqueda— se deriva de ella y existe sólo para buscar y ordenar.
/// Escribir, cuando llegue, va a ser parchear la cruda y volver a derivar.
///
/// - `address_books`: las libretas de la cuenta. No lleva la cuenta: hay una
///   base por cuenta. El `sync-token` de cada una vive en `sync_state`
///   (`area = 'contacts'`, `collection` = su dirección), y un disparador lo
///   borra junto con la libreta; el `getctag` va acá.
/// - `contacts`: una fila por tarjeta del servidor, identificada por
///   `(libreta, dirección)` y no por el `UID`, que lo escribe quien creó la
///   tarjeta y puede faltar o repetirse. Con cascada desde la libreta.
/// - `contact_emails` y `contact_phones`: derivados, con cascada desde el
///   contacto. Los correos con índice sin mayúsculas, para encontrar a quién
///   pertenece una dirección.
/// - `contacts_fts`: FTS5 sin contenido propio (`content = ''`), con
///   `contentless_delete` para poder borrar por `rowid`, que es el `id` del
///   contacto. Sin acentos (`remove_diacritics 2`): «jose perez» encuentra a
///   «José Pérez».
///
/// **Cómo se mantiene el índice**, que es la mitad a mano y la mitad por
/// disparador, a propósito: una fila del índice lleva los correos y los
/// teléfonos, que se escriben *después* del contacto, así que un disparador
/// sobre `contacts` al insertar los vería vacíos. Por eso la inserción la hace
/// el código, en la misma transacción que el contacto y sus datos. **El borrado
/// sí va por disparador**: una fila de `contacts` se puede ir por la cascada de
/// una libreta borrada, y ahí no hay código que se acuerde del índice.
///
/// Para el PR 3 (listar y buscar): el cursor estable es `(sort_key, id)`, con
/// índice propio y otro por libreta; la búsqueda devuelve `rowid` de
/// `contacts_fts`, que se cruza con `contacts.id`.
const V2: &str = "
CREATE TABLE address_books (
    id           INTEGER PRIMARY KEY,
    href         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    ctag         TEXT,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE TRIGGER address_books_forget_token AFTER DELETE ON address_books
BEGIN
    DELETE FROM sync_state WHERE area = 'contacts' AND collection = OLD.href;
END;

CREATE TABLE contacts (
    id              INTEGER PRIMARY KEY,
    address_book_id INTEGER NOT NULL REFERENCES address_books (id) ON DELETE CASCADE,
    href            TEXT NOT NULL,
    etag            TEXT,
    uid             TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    sort_key        TEXT NOT NULL,
    raw_vcard       TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (address_book_id, href)
) STRICT;

CREATE INDEX contacts_by_sort ON contacts (sort_key, id);
CREATE INDEX contacts_by_book_and_sort ON contacts (address_book_id, sort_key, id);
CREATE INDEX contacts_by_uid ON contacts (uid);

CREATE TABLE contact_emails (
    contact_id INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    label      TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (contact_id, position)
) STRICT, WITHOUT ROWID;

CREATE INDEX contact_emails_by_value ON contact_emails (value COLLATE NOCASE);

CREATE TABLE contact_phones (
    contact_id INTEGER NOT NULL REFERENCES contacts (id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    label      TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (contact_id, position)
) STRICT, WITHOUT ROWID;

CREATE VIRTUAL TABLE contacts_fts USING fts5 (
    name, emails, phones, organization,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER contacts_fts_forget AFTER DELETE ON contacts
BEGIN
    DELETE FROM contacts_fts WHERE rowid = OLD.id;
END;
";

/// v3 (PR 4): el calendario.
///
/// **El iCalendar crudo es la fuente de verdad** (decisión 3 del taller), como
/// la vCard en la v2: `calendar_objects.raw_ical` guarda el recurso tal como
/// vino del servidor —la serie y sus excepciones, que viajan juntas en uno—, y
/// todo lo demás se deriva de él y existe sólo para listar y ordenar.
///
/// - `calendars`: los calendarios de la cuenta, con su color y los
///   componentes que guardan (`VEVENT`, `VTODO`, separados por coma). El
///   `sync-token` vive en `sync_state` (`area = 'calendar'`), y un disparador
///   lo borra junto con el calendario, como el de las libretas.
/// - `calendar_objects`: un objeto por recurso del servidor, identificado por
///   `(calendario, dirección)` y no por el `UID`. Lo derivado: el componente,
///   el título, el comienzo y el fin en segundos UTC (el vencimiento, en una
///   tarea), todo el día, si se repite, cómo quedó la zona (`unknown` es un
///   `TZID` que no se pudo resolver: se tomó como hora flotante), el estado,
///   la prioridad y cuándo se completó una tarea. Y lo de la expansión: el
///   rango que cubren sus ocurrencias guardadas (`expanded_from`,
///   `expanded_to`; nulo en lo que no se repite, que se guarda entero), cómo
///   terminó (`complete`, `truncated` si pasó un tope, `invalid` si la regla
///   no se entendió) y cuánto dura su vez más larga (`span`), que acota la
///   consulta por rango. `sort_key` ordena las tareas por vencimiento, las sin
///   vencimiento al final. `component = ''` es un recurso que no es ni evento
///   ni tarea: se guarda por su ETag y no se lista.
/// - `occurrences`: las veces de cada evento. **En una serie, las que empiezan
///   en la ventana** del almacén; en un evento que no se repite, todas. Una
///   excepción reemplaza su vez (misma clave, `recurrence_id`, el comienzo que
///   tenía en la serie) y lleva su título si cambió. Con el calendario copiado
///   para filtrar sin ir al objeto. Con cascada desde el objeto.
/// - `alarms`: los disparos de los recordatorios de cada ocurrencia guardada,
///   en segundos UTC, para las notificaciones que vengan. Con cascada desde su
///   ocurrencia.
///
/// La lista de un rango pagina por `(starts_at, object_id, recurrence_id)`,
/// con un índice que además lleva el fin y el calendario, así que filtrar por
/// superposición y por calendario no sale del índice (una prueba mira el plan).
const V3: &str = "
CREATE TABLE calendars (
    id           INTEGER PRIMARY KEY,
    href         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    color        TEXT,
    components   TEXT NOT NULL,
    ctag         TEXT,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE TRIGGER calendars_forget_token AFTER DELETE ON calendars
BEGIN
    DELETE FROM sync_state WHERE area = 'calendar' AND collection = OLD.href;
END;

CREATE TABLE calendar_objects (
    id            INTEGER PRIMARY KEY,
    calendar_id   INTEGER NOT NULL REFERENCES calendars (id) ON DELETE CASCADE,
    href          TEXT NOT NULL,
    etag          TEXT,
    uid           TEXT NOT NULL,
    component     TEXT NOT NULL CHECK (component IN ('VEVENT', 'VTODO', '')),
    summary       TEXT NOT NULL,
    starts_at     INTEGER,
    ends_at       INTEGER,
    all_day       INTEGER NOT NULL,
    recurring     INTEGER NOT NULL,
    zone          TEXT NOT NULL CHECK (zone IN ('date', 'utc', 'zoned', 'floating', 'unknown')),
    status        TEXT NOT NULL,
    priority      INTEGER,
    completed_at  INTEGER,
    done          INTEGER NOT NULL,
    sort_key      INTEGER NOT NULL,
    span          INTEGER NOT NULL,
    expansion     TEXT NOT NULL CHECK (expansion IN ('complete', 'truncated', 'invalid')),
    expanded_from INTEGER,
    expanded_to   INTEGER,
    raw_ical      TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (calendar_id, href)
) STRICT;

CREATE INDEX calendar_objects_by_uid ON calendar_objects (uid);
CREATE INDEX calendar_objects_series ON calendar_objects (recurring, starts_at);
CREATE INDEX calendar_objects_by_span ON calendar_objects (span);
CREATE INDEX calendar_objects_by_due ON calendar_objects (component, sort_key, id);

CREATE TABLE occurrences (
    object_id     INTEGER NOT NULL REFERENCES calendar_objects (id) ON DELETE CASCADE,
    recurrence_id INTEGER NOT NULL,
    calendar_id   INTEGER NOT NULL,
    starts_at     INTEGER NOT NULL,
    ends_at       INTEGER NOT NULL,
    all_day       INTEGER NOT NULL,
    summary       TEXT,
    PRIMARY KEY (object_id, recurrence_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX occurrences_by_start
    ON occurrences (starts_at, object_id, recurrence_id, ends_at, calendar_id);

CREATE TABLE alarms (
    object_id     INTEGER NOT NULL,
    recurrence_id INTEGER NOT NULL,
    position      INTEGER NOT NULL,
    fires_at      INTEGER NOT NULL,
    action        TEXT NOT NULL,
    PRIMARY KEY (object_id, recurrence_id, position),
    FOREIGN KEY (object_id, recurrence_id)
        REFERENCES occurrences (object_id, recurrence_id) ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX alarms_by_time ON alarms (fires_at);
";

/// Todas las migraciones, en orden.
pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(V1), M::up(V2), M::up(V3)])
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
        assert_eq!(version, 3);

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
        for table in [
            "store_meta",
            "sync_state",
            "sync_log",
            "sync_log_cap",
            "address_books",
            "address_books_forget_token",
            "contacts",
            "contacts_by_sort",
            "contacts_by_book_and_sort",
            "contact_emails",
            "contact_phones",
            "contacts_fts",
            "contacts_fts_forget",
            "calendars",
            "calendars_forget_token",
            "calendar_objects",
            "calendar_objects_by_uid",
            "calendar_objects_series",
            "calendar_objects_by_span",
            "calendar_objects_by_due",
            "occurrences",
            "occurrences_by_start",
            "alarms",
            "alarms_by_time",
        ] {
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

    /// Las migraciones de antes, tal como quedaron mergeadas: la base que ya
    /// las aplicó es la que hay que llevar a la nueva.
    fn at_version(version: usize) -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        let all = [V1, V2, V3];
        Migrations::new(all[..version].iter().map(|sql| M::up(sql)).collect())
            .to_latest(&mut connection)
            .unwrap();
        connection
    }

    /// **v1 → v2 no pierde nada**: la bitácora y el estado de la
    /// sincronización de una base del PR 1 siguen ahí después de migrar.
    #[test]
    fn de_v1_a_v2_se_conserva_lo_que_habia() {
        let mut connection = at_version(1);
        assert_eq!(schema_version(&connection).unwrap(), 1);
        connection
            .execute(
                "INSERT INTO sync_log (at, level, area, message) VALUES ('ayer', 'warn', NULL, 'rehecha')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sync_state (area, collection, token, updated_at) VALUES ('email', 'INBOX', '42', 'ayer')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 3);
        let message: String = connection
            .query_row("SELECT message FROM sync_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(message, "rehecha");
        let token: String = connection
            .query_row(
                "SELECT token FROM sync_state WHERE area = 'email' AND collection = 'INBOX'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(token, "42");
        // Y la v1 quedó como estaba: el tope de la bitácora sigue andando.
        let triggers: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'sync_log_cap'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(triggers, 1);
    }

    /// Un contacto con sus datos y su entrada en el índice, como los escribe
    /// el sincronizador.
    fn insert_contact(connection: &Connection, book: i64, href: &str, name: &str) -> i64 {
        connection
            .execute(
                "INSERT INTO contacts (address_book_id, href, etag, uid, display_name, sort_key, raw_vcard, updated_at)
                 VALUES (?1, ?2, '\"1\"', ?2, ?3, lower(?3), 'BEGIN:VCARD', 'ahora')",
                rusqlite::params![book, href, name],
            )
            .unwrap();
        let id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO contact_emails (contact_id, position, label, value) VALUES (?1, 0, 'home', 'x@y.com')",
                [id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contact_phones (contact_id, position, label, value) VALUES (?1, 0, 'cell', '555')",
                [id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contacts_fts (rowid, name, emails, phones, organization) VALUES (?1, ?2, 'x@y.com', '555', '')",
                rusqlite::params![id, name],
            )
            .unwrap();
        id
    }

    fn count(connection: &Connection, sql: &str) -> i64 {
        connection.query_row(sql, [], |row| row.get(0)).unwrap()
    }

    fn found(connection: &Connection, terms: &str) -> Vec<i64> {
        let mut statement = connection
            .prepare("SELECT rowid FROM contacts_fts WHERE contacts_fts MATCH ?1 ORDER BY rowid")
            .unwrap();
        statement
            .query_map([terms], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn insert_book(connection: &Connection, href: &str) -> i64 {
        connection
            .execute(
                "INSERT INTO address_books (href, display_name, updated_at) VALUES (?1, 'Libreta', 'ahora')",
                [href],
            )
            .unwrap();
        let id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO sync_state (area, collection, token, updated_at) VALUES ('contacts', ?1, 't1', 'ahora')",
                [href],
            )
            .unwrap();
        id
    }

    /// Borrar una libreta se lleva sus contactos, sus correos y teléfonos, sus
    /// entradas del índice y su token; lo de las otras libretas no se toca.
    #[test]
    fn borrar_una_libreta_se_lleva_todo_lo_suyo() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();

        let gone = insert_book(&connection, "https://x/a/");
        let kept = insert_book(&connection, "https://x/b/");
        insert_contact(&connection, gone, "https://x/a/1.vcf", "Ana");
        insert_contact(&connection, gone, "https://x/a/2.vcf", "Ana Bis");
        let stays = insert_contact(&connection, kept, "https://x/b/1.vcf", "Ana Tres");

        connection
            .execute("DELETE FROM address_books WHERE id = ?1", [gone])
            .unwrap();

        assert_eq!(count(&connection, "SELECT count(*) FROM contacts"), 1);
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_emails"), 1);
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_phones"), 1);
        assert_eq!(found(&connection, "ana"), vec![stays]);
        assert_eq!(
            count(
                &connection,
                "SELECT count(*) FROM sync_state WHERE area = 'contacts'"
            ),
            1,
            "el token de la libreta borrada se va con ella"
        );
    }

    /// Y borrar un contacto suelto se lleva lo suyo, índice incluido.
    #[test]
    fn borrar_un_contacto_se_lleva_sus_datos_y_su_entrada_del_indice() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();
        let book = insert_book(&connection, "https://x/a/");
        let id = insert_contact(&connection, book, "https://x/a/1.vcf", "Ana");
        assert_eq!(found(&connection, "ana"), vec![id]);

        connection
            .execute("DELETE FROM contacts WHERE id = ?1", [id])
            .unwrap();
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_emails"), 0);
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_phones"), 0);
        assert!(found(&connection, "ana").is_empty());
    }

    /// La búsqueda no mira acentos ni mayúsculas: «jose perez» encuentra a
    /// «José Pérez», y también por un pedazo del correo.
    #[test]
    fn la_busqueda_encuentra_sin_acentos() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();
        let book = insert_book(&connection, "https://x/a/");
        let jose = insert_contact(&connection, book, "https://x/a/1.vcf", "José Pérez");
        insert_contact(&connection, book, "https://x/a/2.vcf", "Josefina Gómez");

        assert_eq!(found(&connection, "jose perez"), vec![jose]);
        assert_eq!(found(&connection, "JOSÉ"), vec![jose]);
        assert_eq!(found(&connection, "jose*").len(), 2);
    }

    /// Una tarjeta es una por libreta y dirección; la misma dirección en otra
    /// libreta es otra tarjeta.
    #[test]
    fn un_contacto_es_uno_por_libreta_y_direccion() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();
        let a = insert_book(&connection, "https://x/a/");
        let b = insert_book(&connection, "https://x/b/");
        insert_contact(&connection, a, "https://x/1.vcf", "Ana");
        insert_contact(&connection, b, "https://x/1.vcf", "Ana");
        let again = connection.execute(
            "INSERT INTO contacts (address_book_id, href, uid, display_name, sort_key, raw_vcard, updated_at)
             VALUES (?1, 'https://x/1.vcf', '', '', '', '', 'ahora')",
            [a],
        );
        assert!(again.is_err());
        // Y sin libreta no hay contacto.
        let orphan = connection.execute(
            "INSERT INTO contacts (address_book_id, href, uid, display_name, sort_key, raw_vcard, updated_at)
             VALUES (999, 'https://x/2.vcf', '', '', '', '', 'ahora')",
            [],
        );
        assert!(orphan.is_err());
    }

    /// La lista del PR 3 pagina por `(sort_key, id)`: el plan usa el índice y
    /// no ordena en memoria.
    #[test]
    fn el_orden_de_la_lista_usa_su_indice() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        let plan = |sql: &str| -> String {
            let mut statement = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>()
                .join(" | ")
        };
        let all = plan(
            "SELECT id FROM contacts WHERE (sort_key, id) > ('m', 0) ORDER BY sort_key, id LIMIT 50",
        );
        assert!(all.contains("contacts_by_sort"), "{all}");
        assert!(!all.contains("TEMP B-TREE"), "{all}");
        let by_book = plan(
            "SELECT id FROM contacts WHERE address_book_id = 1 AND (sort_key, id) > ('m', 0) \
             ORDER BY sort_key, id LIMIT 50",
        );
        assert!(by_book.contains("contacts_by_book_and_sort"), "{by_book}");
        assert!(!by_book.contains("TEMP B-TREE"), "{by_book}");
    }

    // ── v3: el calendario ───────────────────────────────────────────────────

    fn insert_calendar(connection: &Connection, href: &str) -> i64 {
        connection
            .execute(
                "INSERT INTO calendars (href, display_name, components, updated_at)
                 VALUES (?1, 'Personal', 'VEVENT,VTODO', 'ahora')",
                [href],
            )
            .unwrap();
        let id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO sync_state (area, collection, token, updated_at) VALUES ('calendar', ?1, 't1', 'ahora')",
                [href],
            )
            .unwrap();
        id
    }

    /// Un objeto con dos ocurrencias y un recordatorio en cada una.
    fn insert_object(connection: &Connection, calendar: i64, href: &str) -> i64 {
        connection
            .execute(
                "INSERT INTO calendar_objects
                   (calendar_id, href, uid, component, summary, starts_at, ends_at, all_day,
                    recurring, zone, status, done, sort_key, span, expansion, raw_ical, updated_at)
                 VALUES (?1, ?2, ?2, 'VEVENT', 'Reunión', 100, 200, 0, 1, 'utc', '', 0, 100, 100,
                         'complete', 'BEGIN:VCALENDAR', 'ahora')",
                rusqlite::params![calendar, href],
            )
            .unwrap();
        let id = connection.last_insert_rowid();
        for rid in [100, 1000] {
            connection
                .execute(
                    "INSERT INTO occurrences (object_id, recurrence_id, calendar_id, starts_at, ends_at, all_day)
                     VALUES (?1, ?2, ?3, ?2, ?2 + 100, 0)",
                    rusqlite::params![id, rid, calendar],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO alarms (object_id, recurrence_id, position, fires_at, action)
                     VALUES (?1, ?2, 0, ?2 - 10, 'DISPLAY')",
                    rusqlite::params![id, rid],
                )
                .unwrap();
        }
        id
    }

    fn with_foreign_keys() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();
        connection
    }

    /// **v2 → v3 no pierde nada**: los contactos, sus datos, su índice y su
    /// token siguen ahí después de migrar, y la bitácora también.
    #[test]
    fn de_v2_a_v3_se_conservan_los_contactos() {
        let mut connection = at_version(2);
        let book = insert_book(&connection, "https://x/a/");
        let id = insert_contact(&connection, book, "https://x/a/1.vcf", "José Pérez");
        connection
            .execute(
                "INSERT INTO sync_log (at, level, area, message) VALUES ('ayer', 'warn', 'contacts', 'algo')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 3);
        assert_eq!(found(&connection, "jose"), vec![id]);
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_emails"), 1);
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_phones"), 1);
        assert_eq!(
            count(
                &connection,
                "SELECT count(*) FROM sync_state WHERE area = 'contacts'"
            ),
            1
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM sync_log"), 1);
        // Y se puede escribir en las tablas nuevas.
        let calendar = insert_calendar(&connection, "https://x/c/");
        insert_object(&connection, calendar, "https://x/c/1.ics");
        assert_eq!(count(&connection, "SELECT count(*) FROM occurrences"), 2);
    }

    /// Borrar un calendario se lleva sus objetos, sus ocurrencias, sus
    /// recordatorios y su token; lo del otro calendario no se toca.
    #[test]
    fn borrar_un_calendario_se_lleva_todo_lo_suyo() {
        let connection = with_foreign_keys();
        let gone = insert_calendar(&connection, "https://x/a/");
        let kept = insert_calendar(&connection, "https://x/b/");
        insert_object(&connection, gone, "https://x/a/1.ics");
        insert_object(&connection, gone, "https://x/a/2.ics");
        insert_object(&connection, kept, "https://x/b/1.ics");

        connection
            .execute("DELETE FROM calendars WHERE id = ?1", [gone])
            .unwrap();

        assert_eq!(
            count(&connection, "SELECT count(*) FROM calendar_objects"),
            1
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM occurrences"), 2);
        assert_eq!(count(&connection, "SELECT count(*) FROM alarms"), 2);
        assert_eq!(
            count(
                &connection,
                "SELECT count(*) FROM sync_state WHERE area = 'calendar'"
            ),
            1,
            "el token del calendario borrado se va con él"
        );
    }

    /// Borrar un objeto se lleva sus ocurrencias y sus recordatorios, y borrar
    /// una ocurrencia se lleva los suyos.
    #[test]
    fn borrar_un_objeto_se_lleva_sus_ocurrencias_y_recordatorios() {
        let connection = with_foreign_keys();
        let calendar = insert_calendar(&connection, "https://x/a/");
        let object = insert_object(&connection, calendar, "https://x/a/1.ics");
        connection
            .execute(
                "DELETE FROM occurrences WHERE object_id = ?1 AND recurrence_id = 100",
                [object],
            )
            .unwrap();
        assert_eq!(count(&connection, "SELECT count(*) FROM alarms"), 1);

        connection
            .execute("DELETE FROM calendar_objects WHERE id = ?1", [object])
            .unwrap();
        assert_eq!(count(&connection, "SELECT count(*) FROM occurrences"), 0);
        assert_eq!(count(&connection, "SELECT count(*) FROM alarms"), 0);
    }

    /// Un objeto es uno por calendario y dirección, y no hay objeto sin
    /// calendario, ni ocurrencia sin objeto, ni recordatorio sin ocurrencia.
    #[test]
    fn un_objeto_es_uno_por_calendario_y_direccion() {
        let connection = with_foreign_keys();
        let calendar = insert_calendar(&connection, "https://x/a/");
        insert_object(&connection, calendar, "https://x/a/1.ics");
        let again = connection.execute(
            "INSERT INTO calendar_objects
               (calendar_id, href, uid, component, summary, all_day, recurring, zone, status,
                done, sort_key, span, expansion, raw_ical, updated_at)
             VALUES (?1, 'https://x/a/1.ics', '', 'VEVENT', '', 0, 0, 'utc', '', 0, 0, 0,
                     'complete', '', 'ahora')",
            [calendar],
        );
        assert!(again.is_err());
        let orphan = connection.execute(
            "INSERT INTO calendar_objects
               (calendar_id, href, uid, component, summary, all_day, recurring, zone, status,
                done, sort_key, span, expansion, raw_ical, updated_at)
             VALUES (999, 'https://x/a/2.ics', '', 'VEVENT', '', 0, 0, 'utc', '', 0, 0, 0,
                     'complete', '', 'ahora')",
            [],
        );
        assert!(orphan.is_err(), "sin calendario no hay objeto");
        let orphan = connection.execute(
            "INSERT INTO occurrences (object_id, recurrence_id, calendar_id, starts_at, ends_at, all_day)
             VALUES (999, 1, 1, 1, 2, 0)",
            [],
        );
        assert!(orphan.is_err());
        let orphan = connection.execute(
            "INSERT INTO alarms (object_id, recurrence_id, position, fires_at, action)
             VALUES (1, 55, 0, 1, 'DISPLAY')",
            [],
        );
        assert!(
            orphan.is_err(),
            "un recordatorio sin su ocurrencia no entra"
        );
        let bad = connection.execute("UPDATE calendar_objects SET component = 'VJOURNAL'", []);
        assert!(bad.is_err());
    }

    /// La consulta por rango del calendario usa su índice —la superposición y
    /// el calendario se filtran dentro de él— y pagina sin ordenar en memoria.
    /// Y las tareas, por vencimiento, igual.
    #[test]
    fn la_consulta_por_rango_usa_su_indice() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        let plan = |sql: &str| -> String {
            let mut statement = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            statement
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>()
                .join(" | ")
        };
        let range = plan(
            "SELECT o.object_id FROM occurrences o
              WHERE o.starts_at >= 0 AND o.starts_at < 1000 AND o.ends_at > 10
                AND o.calendar_id IN (1, 2)
                AND (o.starts_at, o.object_id, o.recurrence_id) > (5, 1, 1)
              ORDER BY o.starts_at, o.object_id, o.recurrence_id LIMIT 101",
        );
        assert!(range.contains("occurrences_by_start"), "{range}");
        assert!(range.contains("COVERING INDEX"), "{range}");
        assert!(!range.contains("TEMP B-TREE"), "{range}");

        let tasks = plan(
            "SELECT id FROM calendar_objects WHERE component = 'VTODO'
                AND (sort_key, id) > (5, 1) ORDER BY sort_key, id LIMIT 101",
        );
        assert!(tasks.contains("calendar_objects_by_due"), "{tasks}");
        assert!(!tasks.contains("TEMP B-TREE"), "{tasks}");
    }
}
