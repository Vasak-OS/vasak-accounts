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
///   tenía en la serie). Si su título no es el del objeto, `title` dice cuál
///   de `object_titles` es —el número, no el texto: una `THISANDFUTURE` con
///   otro título se lo pasa a todas las que le siguen, y copiarlo a cada una
///   multiplicaba el título por las ocurrencias—. Con el calendario copiado
///   para filtrar sin ir al objeto. Con cascada desde el objeto.
/// - `object_titles`: los títulos de las excepciones de un objeto que no son
///   el suyo, por su lugar entre ellas. Uno por excepción como mucho, y cada
///   uno salió del recurso: juntos no pesan más que `raw_ical`.
/// - `alarms`: los disparos de los recordatorios de cada ocurrencia guardada,
///   en segundos UTC, para las notificaciones que vengan. Con cascada desde su
///   ocurrencia.
///
/// La lista de un rango pagina por `(starts_at, object_id, recurrence_id)`,
/// con un índice que además lleva el fin y el calendario, así que filtrar por
/// superposición y por calendario no sale del índice (una prueba mira el plan).
/// `occurrences_long` es el mismo índice con sólo las veces que duran más de
/// 400 días (`calendar_read::LONG_OCCURRENCE_SECONDS`): la consulta por rango
/// mira hacia atrás como mucho eso, y las que duran más las busca ahí.
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
    title         INTEGER,
    PRIMARY KEY (object_id, recurrence_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX occurrences_by_start
    ON occurrences (starts_at, object_id, recurrence_id, ends_at, calendar_id);

CREATE INDEX occurrences_long
    ON occurrences (starts_at, object_id, recurrence_id, ends_at, calendar_id)
    WHERE ends_at - starts_at > 34560000;

CREATE TABLE object_titles (
    object_id INTEGER NOT NULL REFERENCES calendar_objects (id) ON DELETE CASCADE,
    position  INTEGER NOT NULL,
    summary   TEXT NOT NULL,
    PRIMARY KEY (object_id, position)
) STRICT, WITHOUT ROWID;

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

/// v4 (PR para vasak-accounts#23): el correo.
///
/// El almacén local guarda:
/// - **mailboxes**: las casillas (carpetas/etiquetas) de la cuenta —INBOX,
///   Enviados, Papelera, Archivo, las que haya creado la persona—. El
///   `HIGHESTMODSEQ` de IMAP vive en `sync_state` (`area = 'email'`,
///   `collection` = su nombre), y un disparador lo borra junto con la casilla.
/// - **messages**: un resumen por mensaje que hay en el servidor, identificado
///   por `(mailbox_id, uid)` y no por el `UID` solo, porque los UID son por
///   casilla. Lo derivado: remitente, destinatarios, asunto, fecha, banderas
///   (leído, respondido, reenviado, borrado, marcado), si tiene adjuntos,
///   tamaño y el `Message-ID` para enhebrar. La fecha está en segundos UTC
///   (`date_ts`), y `sort_key` ordena por fecha descendente (lo más nuevo
///   primero) para que la lista de la bandeja de entrada sea instantánea.
/// - **message_bodies**: el cuerpo del mensaje, en texto plano y en HTML
///   saneado. Una fila por mensaje, vinculada a `messages.id`. Se guarda
///   cuando alguien abre el mensaje, no en la sincronización de la lista.
/// - **message_attachments**: los adjuntos de un mensaje, con su número de
///   parte, nombre, tipo MIME y tamaño. El contenido no se guarda aquí —se
///   trae del servidor al pedirlo—; esta tabla dice qué hay.
/// - **message_flags**: las banderas IMAP por mensaje, separadas para poder
///   consultar «¿qué mensajes tienen la bandera X en esta casilla?» sin
///   leer el JSON. Una fila por bandera distinta de `\Seen` (leído), que es
///   la más común y vive como columna booleana en `messages` para la lista.
///   El resto (`\Answered`, `\Flagged`, `\Draft`, `\Deleted`, `$MDNSent`,
///   palabras clave del servidor) van aquí.
///
/// **Cómo se mantiene el índice**, como en contactos y calendario: la
/// inserción la hace el código en la misma transacción, y el borrado va por
/// disparador (una casilla borrada se lleva sus mensajes, sus cuerpos, sus
/// adjuntos y sus banderas).
///
/// La lista de una casilla pagina por `(sort_key, id)` descendente, con
/// índice propio y otro por casilla; la búsqueda (cuando llegue) usará FTS5
/// sobre `messages.subject`, `messages.from_addr`, `messages.to_addrs`,
/// `messages.cc_addrs` y `message_bodies.text_body`.
const V4: &str = "
CREATE TABLE mailboxes (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('inbox', 'sent', 'drafts', 'trash', 'archive', 'junk', 'outbox', 'other')),
    modseq       TEXT,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE TRIGGER mailboxes_forget_token AFTER DELETE ON mailboxes
BEGIN
    DELETE FROM sync_state WHERE area = 'email' AND collection = OLD.name;
END;

CREATE TABLE messages (
    id              INTEGER PRIMARY KEY,
    mailbox_id      INTEGER NOT NULL REFERENCES mailboxes (id) ON DELETE CASCADE,
    uid             INTEGER NOT NULL,
    message_id      TEXT,
    from_addr       TEXT NOT NULL,
    to_addrs        TEXT NOT NULL,
    cc_addrs        TEXT NOT NULL,
    bcc_addrs       TEXT NOT NULL,
    reply_to        TEXT,
    subject         TEXT NOT NULL,
    date_ts         INTEGER NOT NULL,
    sort_key        INTEGER NOT NULL,
    flags_seen      INTEGER NOT NULL DEFAULT 0,
    flags_answered  INTEGER NOT NULL DEFAULT 0,
    flags_flagged   INTEGER NOT NULL DEFAULT 0,
    flags_draft     INTEGER NOT NULL DEFAULT 0,
    flags_deleted   INTEGER NOT NULL DEFAULT 0,
    has_attachments INTEGER NOT NULL DEFAULT 0,
    size            INTEGER NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (mailbox_id, uid)
) STRICT;

CREATE INDEX messages_by_sort ON messages (sort_key DESC, id DESC);
CREATE INDEX messages_by_mailbox_and_sort ON messages (mailbox_id, sort_key DESC, id DESC);
CREATE INDEX messages_by_message_id ON messages (message_id);
CREATE INDEX messages_by_uid ON messages (uid);

CREATE TABLE message_bodies (
    message_id   INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    text_body    TEXT,
    html_body    TEXT,
    truncated    INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (message_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE message_attachments (
    message_id   INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    part_number  TEXT NOT NULL,
    name         TEXT,
    content_type TEXT NOT NULL,
    size         INTEGER NOT NULL,
    inline       INTEGER NOT NULL DEFAULT 0,
    content_id   TEXT,
    PRIMARY KEY (message_id, part_number)
) STRICT, WITHOUT ROWID;

CREATE TABLE message_flags (
    message_id  INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    flag        TEXT NOT NULL,
    PRIMARY KEY (message_id, flag)
) STRICT, WITHOUT ROWID;

CREATE VIRTUAL TABLE messages_fts USING fts5 (
    subject, from_addr, to_addrs, cc_addrs, text_body,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER messages_fts_forget AFTER DELETE ON messages
BEGIN
    DELETE FROM messages_fts WHERE rowid = OLD.id;
END;
";

/// v5 (PR 3 de M2, `vasak-accounts#23`): la cola de escrituras hacia el
/// servidor, y la marca de lo que cambió local y todavía no se confirmó.
///
/// Hasta la v4 el almacén era de sólo lectura hacia el servidor: la
/// sincronización traía y nunca mandaba. La escritura conservadora (decisión 3
/// del taller) necesita dos cosas, y las dos viven **dentro de la base
/// cifrada** —nunca en un archivo aparte en disco— porque guardan cuerpos
/// privados (un evento, una tarjeta):
///
/// - **`pending_dav_ops`**: una fila por escritura pendiente —un `PUT` o un
///   `DELETE`— hacia el servidor, con su cuerpo (`payload`), el ETag con el que
///   se vio por última vez el recurso (`base_etag`, nulo al crear algo nuevo) y
///   su estado. `op = 'put'` crea o reemplaza; `op = 'delete'` borra. `state`
///   es `ready` mientras se puede reintentar y `conflict` cuando el servidor la
///   rechazó con un `412` (el recurso cambió desde `base_etag`): ahí no se pisa
///   nada, se conserva el crudo local y lo resuelve M3 de cara a la persona.
///   `attempts` y `last_error` llevan la cuenta de los reintentos reintentables
///   (red, `423`, `507`). **Una sola op pendiente por objeto** (`UNIQUE`): una
///   edición nueva reemplaza la que hubiera.
///
///   No lleva `account_id`: hay **una base por cuenta** (como `address_books` y
///   `calendars`), así que la cuenta es implícita. `AUTOINCREMENT` para que el
///   orden de drenaje sea el de encolado y no se reuse un id.
///
/// - **`pending_op`** en `calendar_objects` y `contacts`: la marca de que la
///   fila guardada es un cambio local sin confirmar. `NULL` es lo normal —al
///   día con el servidor—; `'put'` es una creación o edición local que todavía
///   no subió; `'delete'` es un borrado local que todavía no subió. **La
///   bajada no pisa ni borra una fila marcada** (ver
///   `apply_calendar_objects` y `apply_contacts`): sin esto, una vuelta de
///   sincronización entre el encolado y el empuje borraría el cambio local, o
///   lo volvería a dejar como estaba en el servidor. Si el `PUT` falla, la
///   caché no queda como `local == servidor`: la marca sigue puesta y la op
///   viva hasta confirmar.
///
/// Que la cola y la marca vivan en la base cifrada da gratis la limpieza de
/// seguridad: un `ClearStore` o un `SetStoreEnabled(false)` borran el archivo
/// entero (ver `lifecycle::StoreManager::remove_store`), y con él la cola; una
/// op con un cuerpo privado no sobrevive a vaciar o apagar la cuenta.
const V5: &str = "
CREATE TABLE pending_dav_ops (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    area            TEXT NOT NULL CHECK (area IN ('calendar', 'contacts')),
    collection_href TEXT NOT NULL,
    object_href     TEXT NOT NULL,
    op              TEXT NOT NULL CHECK (op IN ('put', 'delete')),
    base_etag       TEXT,
    payload         BLOB,
    state           TEXT NOT NULL DEFAULT 'ready' CHECK (state IN ('ready', 'conflict')),
    created_at      TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    -- Testigo de versión de la op: sube cada vez que una edición nueva la
    -- reemplaza (mismo objeto, misma fila por `UNIQUE`, mismo `id`). El empuje
    -- saca una foto de la op, suelta el almacén para hablar con la red, y recién
    -- con la respuesta cierra la op **condicionado a este número**: si una
    -- edición nueva corrió en el medio, la revisión no coincide y no se cierra la
    -- edición de la persona por error (lost-update).
    revision        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (area, object_href)
) STRICT;

CREATE INDEX pending_dav_ops_by_area ON pending_dav_ops (area, id);

ALTER TABLE calendar_objects ADD COLUMN pending_op TEXT
    CHECK (pending_op IN ('put', 'delete'));

ALTER TABLE contacts ADD COLUMN pending_op TEXT
    CHECK (pending_op IN ('put', 'delete'));
";

/// v6 (PR A3 de M3, `vasak-accounts#23`): la copia del servidor de un recurso en
/// conflicto.
///
/// Hasta la v5, un `412` dejaba la op en `conflict` y conservaba el crudo local,
/// pero **no traía la versión del servidor**: M3 no tenía con qué mostrar «local
/// vs. servidor». Esta migración le suma a `pending_dav_ops` dos columnas,
/// nulas mientras no se haya traído la copia:
///
/// - **`server_etag`**: el ETag del recurso tal como está hoy en el servidor.
/// - **`server_raw`**: el crudo del recurso del servidor —el iCal o la vCard—,
///   como lo trae el camino de lectura de un recurso (`calendar-multiget` /
///   `addressbook-multiget` por href). Un `BLOB`, como `payload`.
///
/// Las dos viven **dentro de la base cifrada**, en la misma fila de la op: la
/// copia del servidor es dato privado de la persona (un evento, una tarjeta), así
/// que hereda el cifrado del almacén y se borra con la op cuando un `ClearStore`
/// o un `SetStoreEnabled(false)` rehace la base vacía
/// (ver `lifecycle::StoreManager::remove_store`). No hace falta ninguna limpieza
/// aparte: al colgar de `pending_dav_ops`, se va con ella.
///
/// Nulas al migrar: una op en conflicto de una base de la v5 queda sin copia, y
/// la próxima vuelta del empuje la trae (ver `replay::capture_server_copy`).
const V6: &str = "
ALTER TABLE pending_dav_ops ADD COLUMN server_etag TEXT;
ALTER TABLE pending_dav_ops ADD COLUMN server_raw BLOB;
";

/// v7 (PR 1 de P5, `vasak-accounts#111`): el enlace de un contacto con su
/// persona de la People API de Google.
///
/// Google sincroniza los contactos por CardDAV; la People API los **enriquece**
/// (la foto, sobre todo, que el CardDAV de Google no suele traer embebida), no
/// los reemplaza. El enriquecimiento vive **fuera del `raw_vcard`** —en esta
/// tabla aparte y no dentro del crudo— por la decisión de diseño de la issue:
/// el crudo es la fuente de la escritura conservadora (decisión 3 del taller) y
/// lo pisa el replay de una edición local sin confirmar; meter la foto ahí la
/// borraría en la próxima bajada. Al colgar del contacto por clave foránea con
/// `ON DELETE CASCADE`, el enlace se va cuando se va el contacto, y toda la
/// tabla desaparece con la base cuando un `ClearStore` o un
/// `SetStoreEnabled(false)` la rehace vacía (ver `lifecycle::StoreManager`).
///
/// - **`contact_id`**: a qué contacto local enriquece. Es la clave primaria:
///   un enlace por contacto. El contacto se identifica por su `id` entero, como
///   en `contact_emails` y `contact_phones`, no por el `href` ni el `uid`.
/// - **`resource_name`**: el `people/c<id>` con el que la People API vuelve a
///   pedir esa persona. Una corrida incremental lo reusa en vez de re-casar por
///   email. `UNIQUE` en toda la base (una base por cuenta): dos contactos no
///   apuntan a la misma persona.
/// - **`etag`** y **`photo_etag`**: los testigos con los que la corrida
///   siguiente decide si la persona —y su foto, que versiona aparte— cambiaron
///   desde la última, y se saltea traerlas si no. Nulos mientras no se hayan
///   traído por primera vez.
///
/// Sin red todavía: PR1 es sólo la tabla y sus accesores; la pasada de People
/// API es el PR2 (ver `vasak-accounts#111`).
const V7: &str = "
CREATE TABLE contact_enrichment (
    contact_id    INTEGER PRIMARY KEY REFERENCES contacts (id) ON DELETE CASCADE,
    resource_name TEXT NOT NULL,
    etag          TEXT,
    photo_etag    TEXT
) STRICT;

CREATE UNIQUE INDEX contact_enrichment_by_resource ON contact_enrichment (resource_name);
";

/// v8 (PR 2 de P5, `vasak-accounts#111`): el payload de la foto que la People API
/// de Google trae y el CardDAV de Google no suele traer embebida.
///
/// V7 guardó el *enlace* (resourceName/etag/photo_etag), no los *bytes*: no había
/// dónde ponerlos. La foto NO puede ir en el `raw_vcard` —la pisaría el replay de
/// una edición local sin confirmar (decisión 3 del taller)— ni en un archivo en
/// disco —el almacén es completo y cifrado (decisión 1), y una foto de contacto
/// es dato privado—. Por eso vive acá, en dos columnas nuevas de la misma fila
/// del enlace, dentro de la base cifrada:
///
/// - **`photo`**: los bytes crudos de la imagen, un `BLOB`. La lectura
///   (`contacts_read::cards_page`) los inyecta como una propiedad `PHOTO` al
///   vCard de salida, fuera del crudo guardado.
/// - **`photo_media_type`**: el `Content-Type` real con el que se descargó
///   (`image/jpeg`, `image/png`, …), para armar la línea `PHOTO`. No se adivina.
///
/// Las dos nulas mientras no se bajó ninguna foto; se llenan por separado de los
/// testigos (`Store::set_contact_photo`) para que la pasada de matching e
/// incrementalidad no cargue el `BLOB` en cada `contact_enrichment()`.
const V8: &str = "
ALTER TABLE contact_enrichment ADD COLUMN photo BLOB;
ALTER TABLE contact_enrichment ADD COLUMN photo_media_type TEXT;
";

/// v9 (`vasak-calendar#6`, punto 2): las categorías y el color propios de un
/// evento, para agrupar y colorear por categoría en la ventana.
///
/// Las dos viven en `calendar_objects`, por objeto (no por ocurrencia): una
/// serie las comparte entre todas sus veces, igual que el `summary`.
///
/// - **`categories`**: las etiquetas del evento (`CATEGORIES` de iCalendar),
///   como un arreglo JSON de textos. JSON y no una lista separada por comas
///   porque una categoría puede traer una coma adentro (`\,` en el crudo), que
///   la separación por comas perdería. `[]` por omisión: una base de la v8 queda
///   sin categorías, y la próxima bajada las llena al reescribir el objeto.
/// - **`color`**: el color propio del evento (`COLOR`, RFC 7986 §5.9), distinto
///   del color del calendario. Nulo cuando el evento no trae ninguno.
///
/// Las dos se derivan del `raw_ical`, que es la fuente de verdad: no hace falta
/// volver a la red para llenarlas, las completa el re-sync normal.
const V9: &str = "
ALTER TABLE calendar_objects ADD COLUMN categories TEXT NOT NULL DEFAULT '[]';
ALTER TABLE calendar_objects ADD COLUMN color TEXT;
";

/// v10 (PR de vasak-mail#78, firmar/verificar S/MIME): el estado de la firma de
/// un mensaje, calculado al bajarlo (cuando está el crudo) y guardado acá para
/// responder desde la caché sin re-verificar ni guardar el RFC822 entero.
/// `smime_status` es NULL si no venía firmado, 0 «firmado, no verificado», 1
/// «firmado, firma válida»; `smime_signer` el correo del firmante cuando vale.
const V10: &str = "
ALTER TABLE message_bodies ADD COLUMN smime_status INTEGER;
ALTER TABLE message_bodies ADD COLUMN smime_signer TEXT;
";

/// v11 (PR de vasak-mail#78, descifrar S/MIME): el estado de cifrado de un
/// mensaje, calculado al bajarlo (con nuestra clave en mano; al leer no está).
/// `smime_encrypted` es NULL si no venía cifrado, 1 «cifrado y abierto» (el cuerpo
/// guardado es el descifrado), 2 «cifrado, no se pudo abrir» (destinatario ECC,
/// sin nuestra clave, cifrado no soportado; el cuerpo queda vacío). El cuerpo
/// descifrado se guarda descifrado, protegido en reposo por SQLCipher como el
/// resto del correo (decisión #1): no se re-descifra en cada lectura.
const V11: &str = "
ALTER TABLE message_bodies ADD COLUMN smime_encrypted INTEGER;
";

/// v12 (PR 3 de P5, `vasak-accounts#111`): los grupos/etiquetas y el «destacado»
/// que la People API de Google trae y el CardDAV de Google no suele traer.
///
/// Como la foto de la V8, viven **fuera del `raw_vcard`** —el crudo es la fuente
/// de la escritura conservadora (decisión 3 del taller) y lo pisa el replay de una
/// edición local sin confirmar— y dentro de la base cifrada, en dos columnas
/// nuevas de la misma fila del enlace de enriquecimiento. La lectura
/// (`contacts_read::cards_page`) las inyecta al vCard de salida —los grupos como
/// `CATEGORIES`, el destacado como `X-VASAK-STARRED`— sólo si el contacto no tiene
/// op pendiente, igual que la foto.
///
/// - **`groups`**: los nombres de los grupos a los que pertenece el contacto, como
///   un arreglo JSON de textos (el mismo formato que `calendar_objects.categories`
///   de la V9). JSON y no una lista separada por comas porque un nombre de grupo
///   puede traer una coma adentro, que la separación perdería. `[]` por omisión:
///   una base de la V11 queda sin grupos, y la próxima pasada de enriquecimiento
///   los llena. El grupo de sistema `contactGroups/starred` **no** entra acá: marca
///   el destacado.
/// - **`starred`**: `1` si el contacto está en el grupo de sistema
///   `contactGroups/starred`, `0` si no. `0` por omisión.
///
/// Las dos se llenan por `Store::set_contact_groups`, aparte de los testigos del
/// enlace, igual que la foto: la pasada de matching e incrementalidad no las carga.
const V12: &str = "
ALTER TABLE contact_enrichment ADD COLUMN groups TEXT NOT NULL DEFAULT '[]';
ALTER TABLE contact_enrichment ADD COLUMN starred INTEGER NOT NULL DEFAULT 0;
";

/// Todas las migraciones, en orden.
pub fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(V1),
        M::up(V2),
        M::up(V3),
        M::up(V4),
        M::up(V5),
        M::up(V6),
        M::up(V7),
        M::up(V8),
        M::up(V9),
        M::up(V10),
        M::up(V11),
        M::up(V12),
    ])
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
        assert_eq!(version, 12);

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
            "occurrences_long",
            "object_titles",
            "alarms",
            "alarms_by_time",
            "mailboxes",
            "mailboxes_forget_token",
            "messages",
            "messages_by_sort",
            "messages_by_mailbox_and_sort",
            "messages_by_message_id",
            "messages_by_uid",
            "message_bodies",
            "message_attachments",
            "message_flags",
            "messages_fts",
            "messages_fts_forget",
            "pending_dav_ops",
            "pending_dav_ops_by_area",
            "contact_enrichment",
            "contact_enrichment_by_resource",
        ] {
            assert!(before.iter().any(|t| t == table), "falta {table}");
        }
    }

    /// El índice de las veces largas tiene en su condición el mismo tope que
    /// la consulta por rango: si no, SQLite no lo puede usar.
    #[test]
    fn el_indice_de_las_veces_largas_usa_el_tope_de_la_lectura() {
        let seconds = crate::store::calendar_read::LONG_OCCURRENCE_SECONDS;
        assert!(V3.contains(&format!("WHERE ends_at - starts_at > {seconds};")));
    }

    /// Una base de una versión más nueva que este programa no se toca.
    #[test]
    fn una_base_mas_nueva_no_se_abre() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection.pragma_update(None, "user_version", 99).unwrap();
        assert!(matches!(apply(&mut connection), Err(StoreError::Schema(_))));
        assert_eq!(schema_version(&connection).unwrap(), 99);
    }

    /// **v4 → v5 no pierde nada**: un calendario, un objeto y un contacto de una
    /// base del PR del correo siguen ahí después de migrar, y la columna
    /// `pending_op` nueva les queda en `NULL` —al día con el servidor—.
    #[test]
    fn de_v4_a_v5_se_conserva_lo_que_habia_y_la_marca_arranca_limpia() {
        let mut connection = at_version(4);
        assert_eq!(schema_version(&connection).unwrap(), 4);
        connection
            .execute(
                "INSERT INTO calendars (id, href, display_name, components, updated_at)
                 VALUES (1, 'https://x/c/', 'C', 'VEVENT', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO calendar_objects
                   (id, calendar_id, href, etag, uid, component, summary, all_day, recurring,
                    zone, status, done, sort_key, span, expansion, raw_ical, updated_at)
                 VALUES (1, 1, 'https://x/c/a.ics', '\"v1\"', 'u1', 'VEVENT', 'A', 0, 0,
                    'utc', '', 0, 0, 0, 'complete', 'BEGIN:VCALENDAR', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO address_books (id, href, display_name, updated_at)
                 VALUES (1, 'https://x/a/', 'A', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contacts
                   (id, address_book_id, href, etag, uid, display_name, sort_key, raw_vcard,
                    updated_at)
                 VALUES (1, 1, 'https://x/a/ana.vcf', '\"v1\"', 'u1', 'Ana', 'ana',
                    'BEGIN:VCARD', 'ayer')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // Lo que había sigue, y la marca nueva es NULL.
        let object_mark: Option<String> = connection
            .query_row(
                "SELECT pending_op FROM calendar_objects WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(object_mark, None);
        let contact_mark: Option<String> = connection
            .query_row("SELECT pending_op FROM contacts WHERE id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(contact_mark, None);
        // La cola arranca vacía.
        let pending: i64 = connection
            .query_row("SELECT count(*) FROM pending_dav_ops", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pending, 0);
    }

    /// **v5 → v6 no pierde nada**: una op en conflicto de una base del PR 3 de M2
    /// sigue ahí después de migrar, y las columnas nuevas de la copia del
    /// servidor le quedan en `NULL` —todavía no se trajo—.
    #[test]
    fn de_v5_a_v6_conserva_la_op_y_la_copia_del_servidor_arranca_nula() {
        let mut connection = at_version(5);
        assert_eq!(schema_version(&connection).unwrap(), 5);
        connection
            .execute(
                "INSERT INTO pending_dav_ops
                   (id, area, collection_href, object_href, op, base_etag, payload, state,
                    created_at, attempts, last_error)
                 VALUES (1, 'calendar', 'https://x/c/', 'https://x/c/a.ics', 'put', '\"v1\"',
                    x'0102', 'conflict', 'ayer', 1, 'chocó')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // La op sigue, en conflicto, y las columnas nuevas son NULL.
        let (state, server_etag, server_raw): (String, Option<String>, Option<Vec<u8>>) =
            connection
                .query_row(
                    "SELECT state, server_etag, server_raw FROM pending_dav_ops WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
        assert_eq!(state, "conflict");
        assert_eq!(server_etag, None);
        assert_eq!(server_raw, None);
        // Y se puede escribir la copia del servidor en las columnas nuevas.
        connection
            .execute(
                "UPDATE pending_dav_ops SET server_etag = '\"v9\"', server_raw = x'0304'
                  WHERE id = 1",
                [],
            )
            .unwrap();
        let server_raw: Option<Vec<u8>> = connection
            .query_row(
                "SELECT server_raw FROM pending_dav_ops WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(server_raw.as_deref(), Some(&[3u8, 4u8][..]));
    }

    /// **v6 → v7 no pierde nada**: un contacto de una base del PR del correo
    /// sigue ahí después de migrar, la tabla de enriquecimiento nueva existe y
    /// arranca vacía, y se puede enlazar ese contacto con una persona de People
    /// API.
    #[test]
    fn de_v6_a_v7_suma_la_tabla_de_enriquecimiento_vacia() {
        let mut connection = at_version(6);
        assert_eq!(schema_version(&connection).unwrap(), 6);
        connection
            .execute(
                "INSERT INTO address_books (id, href, display_name, updated_at)
                 VALUES (1, 'https://x/a/', 'A', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contacts
                   (id, address_book_id, href, etag, uid, display_name, sort_key, raw_vcard,
                    updated_at)
                 VALUES (1, 1, 'https://x/a/ana.vcf', '\"v1\"', 'u1', 'Ana', 'ana',
                    'BEGIN:VCARD', 'ayer')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // El contacto sigue, y la tabla nueva arranca vacía.
        let contacts: i64 = connection
            .query_row("SELECT count(*) FROM contacts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(contacts, 1);
        let links: i64 = connection
            .query_row("SELECT count(*) FROM contact_enrichment", [], |r| r.get(0))
            .unwrap();
        assert_eq!(links, 0);

        // Se puede enlazar el contacto con una persona, y leerlo de vuelta.
        connection
            .execute(
                "INSERT INTO contact_enrichment (contact_id, resource_name, etag, photo_etag)
                 VALUES (1, 'people/c1', '\"e1\"', '\"p1\"')",
                [],
            )
            .unwrap();
        let (resource, etag, photo): (String, Option<String>, Option<String>) = connection
            .query_row(
                "SELECT resource_name, etag, photo_etag FROM contact_enrichment WHERE contact_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(resource, "people/c1");
        assert_eq!(etag.as_deref(), Some("\"e1\""));
        assert_eq!(photo.as_deref(), Some("\"p1\""));
    }

    /// El enlace cuelga del contacto: al borrar el contacto se va con él
    /// (`ON DELETE CASCADE`), y dos contactos no pueden apuntar a la misma
    /// persona (`resource_name` `UNIQUE`).
    #[test]
    fn el_enlace_de_enriquecimiento_cuelga_del_contacto_y_la_persona_es_unica() {
        let connection = at_version(7);
        connection
            .execute(
                "INSERT INTO address_books (id, href, display_name, updated_at)
                 VALUES (1, 'https://x/a/', 'A', 'ayer')",
                [],
            )
            .unwrap();
        let insert_contact = "INSERT INTO contacts
               (id, address_book_id, href, etag, uid, display_name, sort_key, raw_vcard, updated_at)
             VALUES (?1, 1, ?2, '\"v1\"', ?3, 'N', 'n', 'BEGIN:VCARD', 'ayer')";
        connection
            .execute(insert_contact, ["1", "https://x/a/1.vcf", "u1"])
            .unwrap();
        connection
            .execute(insert_contact, ["2", "https://x/a/2.vcf", "u2"])
            .unwrap();
        connection
            .execute(
                "INSERT INTO contact_enrichment (contact_id, resource_name) VALUES (1, 'people/c1')",
                [],
            )
            .unwrap();
        // Un segundo contacto no puede reclamar la misma persona.
        assert!(
            connection
                .execute(
                    "INSERT INTO contact_enrichment (contact_id, resource_name) VALUES (2, 'people/c1')",
                    [],
                )
                .is_err(),
            "dos contactos no apuntan a la misma persona"
        );
        // Al borrar el contacto, su enlace se va en cascada.
        connection
            .execute("DELETE FROM contacts WHERE id = 1", [])
            .unwrap();
        let links: i64 = connection
            .query_row("SELECT count(*) FROM contact_enrichment", [], |r| r.get(0))
            .unwrap();
        assert_eq!(links, 0);
    }

    /// **v7 → v8 no pierde nada**: un enlace de enriquecimiento de una base del
    /// PR1 sigue ahí después de migrar, las dos columnas nuevas de la foto
    /// arrancan nulas, y se les pueden guardar los bytes y el tipo.
    #[test]
    fn de_v7_a_v8_suma_las_columnas_de_la_foto_nulas() {
        let mut connection = at_version(7);
        connection
            .execute(
                "INSERT INTO address_books (id, href, display_name, updated_at)
                 VALUES (1, 'https://x/a/', 'A', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contacts
                   (id, address_book_id, href, etag, uid, display_name, sort_key, raw_vcard,
                    updated_at)
                 VALUES (1, 1, 'https://x/a/ana.vcf', '\"v1\"', 'u1', 'Ana', 'ana',
                    'BEGIN:VCARD', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contact_enrichment (contact_id, resource_name, etag, photo_etag)
                 VALUES (1, 'people/c1', '\"e1\"', '\"p1\"')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // El enlace sigue, y las columnas nuevas arrancan nulas.
        let (resource, photo, media): (String, Option<Vec<u8>>, Option<String>) = connection
            .query_row(
                "SELECT resource_name, photo, photo_media_type
                   FROM contact_enrichment WHERE contact_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(resource, "people/c1");
        assert_eq!(photo, None);
        assert_eq!(media, None);

        // Se les pueden guardar los bytes y el tipo.
        connection
            .execute(
                "UPDATE contact_enrichment SET photo = ?1, photo_media_type = ?2 WHERE contact_id = 1",
                rusqlite::params![&[1u8, 2u8, 3u8][..], "image/jpeg"],
            )
            .unwrap();
        let (photo, media): (Option<Vec<u8>>, Option<String>) = connection
            .query_row(
                "SELECT photo, photo_media_type FROM contact_enrichment WHERE contact_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(photo.as_deref(), Some(&[1u8, 2u8, 3u8][..]));
        assert_eq!(media.as_deref(), Some("image/jpeg"));
    }

    /// Las columnas de la foto existen tras migrar de cero y **aplicar dos veces
    /// no las toca**: `aplicar_dos_veces_no_cambia_nada` compara sólo los nombres
    /// de `sqlite_master`, que no ven las columnas.
    #[test]
    fn aplicar_dos_veces_conserva_las_columnas_de_la_foto() {
        let columns = |c: &Connection| -> Vec<(String, String)> {
            let mut statement = c
                .prepare(
                    "SELECT name, type FROM pragma_table_info('contact_enrichment') ORDER BY cid",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        let before = columns(&connection);
        assert!(
            before.contains(&("photo".into(), "BLOB".into())),
            "{before:?}"
        );
        assert!(
            before.contains(&("photo_media_type".into(), "TEXT".into())),
            "{before:?}"
        );

        apply(&mut connection).unwrap();
        assert_eq!(columns(&connection), before);
        assert_eq!(schema_version(&connection).unwrap(), 12);
    }

    /// **v11 → v12 no pierde nada**: un enlace con su foto de una base de la v11
    /// sigue intacto; los grupos arrancan en `[]` y el destacado en `0` (los
    /// defaults, no `NULL`), y la pasada de enriquecimiento los puede llenar.
    #[test]
    fn de_v11_a_v12_suma_grupos_y_destacado_con_sus_defaults() {
        let mut connection = at_version(11);
        connection
            .execute(
                "INSERT INTO address_books (id, href, display_name, updated_at)
                 VALUES (1, 'https://x/a/', 'A', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contacts
                   (id, address_book_id, href, etag, uid, display_name, sort_key, raw_vcard,
                    updated_at)
                 VALUES (1, 1, 'https://x/a/ana.vcf', '\"v1\"', 'u1', 'Ana', 'ana',
                    'BEGIN:VCARD', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contact_enrichment
                   (contact_id, resource_name, etag, photo_etag, photo, photo_media_type)
                 VALUES (1, 'people/c1', '\"e1\"', '\"p1\"', x'010203', 'image/jpeg')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // Lo que había sigue, y las columnas nuevas traen sus defaults.
        let row: (String, Option<Vec<u8>>, String, i64) = connection
            .query_row(
                "SELECT resource_name, photo, groups, starred
                   FROM contact_enrichment WHERE contact_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, "people/c1");
        assert_eq!(row.1.as_deref(), Some(&[1u8, 2u8, 3u8][..]));
        assert_eq!(row.2, "[]");
        assert_eq!(row.3, 0);

        // Un enlace nuevo (sin nombrar las columnas) también arranca con defaults.
        connection
            .execute(
                "INSERT INTO contacts
                   (id, address_book_id, href, etag, uid, display_name, sort_key, raw_vcard,
                    updated_at)
                 VALUES (2, 1, 'https://x/a/b.vcf', NULL, 'u2', 'Beto', 'beto',
                    'BEGIN:VCARD', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO contact_enrichment (contact_id, resource_name) VALUES (2, 'people/c2')",
                [],
            )
            .unwrap();
        let (groups, starred): (String, i64) = connection
            .query_row(
                "SELECT groups, starred FROM contact_enrichment WHERE contact_id = 2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((groups.as_str(), starred), ("[]", 0));
    }

    /// **v8 → v9 no pierde nada**: un evento de una base de la v8 sigue con sus
    /// ocurrencias, recordatorios y títulos; `categories` arranca en `[]` (el
    /// `NOT NULL DEFAULT` llena las filas viejas) y `color` en `NULL`; y las
    /// columnas aceptan lo que `upsert_object` les va a guardar.
    ///
    /// Rojo-sin-cambio: sin la v9 la versión se queda en 8 y las columnas no
    /// existen.
    #[test]
    fn de_v8_a_v9_suma_categorias_y_color_con_sus_valores_por_omision() {
        let mut connection = at_version(8);
        assert_eq!(schema_version(&connection).unwrap(), 8);
        let calendar = insert_calendar(&connection, "https://x/c/");
        let object = insert_object(&connection, calendar, "https://x/c/1.ics");

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // Lo que había sigue.
        assert_eq!(
            count(&connection, "SELECT count(*) FROM calendar_objects"),
            1
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM occurrences"), 2);
        assert_eq!(count(&connection, "SELECT count(*) FROM alarms"), 2);
        assert_eq!(count(&connection, "SELECT count(*) FROM object_titles"), 1);

        // Las filas viejas: sin categorías y sin color, y no `NULL` en la lista.
        let (categories, color): (String, Option<String>) = connection
            .query_row(
                "SELECT categories, color FROM calendar_objects WHERE id = ?1",
                [object],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(categories, "[]");
        assert_eq!(color, None);

        // La forma de las columnas: `categories` obligatoria, `color` nula.
        let column = |name: &str| -> (String, i64, Option<String>) {
            connection
                .query_row(
                    "SELECT type, \"notnull\", dflt_value
                       FROM pragma_table_info('calendar_objects') WHERE name = ?1",
                    [name],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap()
        };
        assert_eq!(
            column("categories"),
            ("TEXT".into(), 1, Some("'[]'".into()))
        );
        assert_eq!(column("color"), ("TEXT".into(), 0, None));

        // Una fila nueva sin las columnas sigue entrando (las inserciones de
        // antes de v9 no se rompen), y se les puede guardar lo derivado.
        let again = insert_object(&connection, calendar, "https://x/c/2.ics");
        let default: String = connection
            .query_row(
                "SELECT categories FROM calendar_objects WHERE id = ?1",
                [again],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(default, "[]");
        connection
            .execute(
                "UPDATE calendar_objects SET categories = ?1, color = 'turquoise' WHERE id = ?2",
                rusqlite::params![r#"["a","b,c"]"#, object],
            )
            .unwrap();
        let stored: String = connection
            .query_row(
                "SELECT categories FROM calendar_objects WHERE id = ?1",
                [object],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            super::super::calendar::categories_from_json(&stored),
            vec!["a".to_string(), "b,c".to_string()]
        );
        // `NULL` en `categories` no entra: la columna es `NOT NULL`.
        assert!(connection
            .execute("UPDATE calendar_objects SET categories = NULL", [])
            .is_err());
    }

    /// Aplicar la v9 dos veces no cambia las columnas ni la versión, y desde
    /// cero queda igual que migrando desde la v8.
    #[test]
    fn la_v9_es_la_misma_desde_cero_que_desde_la_v8_y_no_cambia_al_repetir() {
        let columns = |c: &Connection| -> Vec<(String, String, i64, Option<String>)> {
            let mut statement = c
                .prepare(
                    "SELECT name, type, \"notnull\", dflt_value
                       FROM pragma_table_info('calendar_objects') ORDER BY cid",
                )
                .unwrap();
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let mut fresh = Connection::open_in_memory().unwrap();
        apply(&mut fresh).unwrap();
        let before = columns(&fresh);
        assert!(before.iter().any(|c| c.0 == "categories"), "{before:?}");
        assert!(before.iter().any(|c| c.0 == "color"), "{before:?}");

        apply(&mut fresh).unwrap();
        assert_eq!(columns(&fresh), before);
        assert_eq!(schema_version(&fresh).unwrap(), 12);

        let mut from_v8 = at_version(8);
        apply(&mut from_v8).unwrap();
        assert_eq!(columns(&from_v8), before);
    }

    /// **v9 → v10 no pierde nada**: el cuerpo guardado de un mensaje de una base
    /// de la v9 sigue entero, y las dos columnas S/MIME arrancan en `NULL`, que
    /// quiere decir «no venía firmado». Y la base migrada es igual a la creada
    /// de cero, y migrar otra vez no cambia nada.
    #[test]
    fn de_v9_a_v10_se_conserva_el_cuerpo_y_las_columnas_smime_arrancan_nulas() {
        let columns = |c: &Connection| -> Vec<(String, String, i64, Option<String>)> {
            let mut statement = c
                .prepare(
                    "SELECT name, type, \"notnull\", dflt_value
                       FROM pragma_table_info('message_bodies') ORDER BY cid",
                )
                .unwrap();
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };

        let mut connection = at_version(9);
        assert_eq!(schema_version(&connection).unwrap(), 9);
        assert!(!columns(&connection)
            .iter()
            .any(|c| c.0.starts_with("smime")));
        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at)
                 VALUES ('INBOX', 'Bandeja', 'inbox', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs,
                                       subject, date_ts, sort_key, size, updated_at)
                 VALUES (1, 7, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 10, 'ayer')",
                [],
            )
            .unwrap();
        let message = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO message_bodies (message_id, text_body, html_body, truncated, updated_at)
                 VALUES (?1, 'cuerpo de antes', '<p>de antes</p>', 1, 'ayer')",
                [message],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        // Lo que había sigue, y las columnas nuevas son NULL.
        let row: (String, Option<String>, i64, Option<i64>, Option<String>) = connection
            .query_row(
                "SELECT text_body, html_body, truncated, smime_status, smime_signer
                   FROM message_bodies WHERE message_id = ?1",
                [message],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "cuerpo de antes".to_string(),
                Some("<p>de antes</p>".to_string()),
                1,
                None,
                None
            )
        );

        // Igual que creada de cero, y repetir no cambia nada.
        let mut fresh = Connection::open_in_memory().unwrap();
        apply(&mut fresh).unwrap();
        assert_eq!(columns(&connection), columns(&fresh));
        assert!(columns(&fresh).iter().any(|c| c.0 == "smime_status"));
        assert!(columns(&fresh).iter().any(|c| c.0 == "smime_signer"));
        let before = columns(&connection);
        apply(&mut connection).unwrap();
        assert_eq!(columns(&connection), before);
        assert_eq!(schema_version(&connection).unwrap(), 12);
    }

    /// **v10 → v11 no pierde nada**: el cuerpo, la firma y el firmante de una base de
    /// la v10 siguen, `smime_encrypted` arranca en `NULL` (no cifrado), la base queda
    /// igual que creada de cero, y migrar otra vez no cambia nada.
    #[test]
    fn de_v10_a_v11_se_conserva_el_cuerpo_y_el_estado_de_cifrado_arranca_nulo() {
        let columns = |c: &Connection| -> Vec<(String, String, i64, Option<String>)> {
            let mut statement = c
                .prepare(
                    "SELECT name, type, \"notnull\", dflt_value
                       FROM pragma_table_info('message_bodies') ORDER BY cid",
                )
                .unwrap();
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };

        let mut connection = at_version(10);
        assert_eq!(schema_version(&connection).unwrap(), 10);
        assert!(!columns(&connection)
            .iter()
            .any(|c| c.0 == "smime_encrypted"));
        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at)
                 VALUES ('INBOX', 'Bandeja', 'inbox', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs,
                                       subject, date_ts, sort_key, size, updated_at)
                 VALUES (1, 7, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 10, 'ayer')",
                [],
            )
            .unwrap();
        let message = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO message_bodies
                     (message_id, text_body, html_body, truncated, smime_status, smime_signer, updated_at)
                 VALUES (?1, 'cuerpo de antes', '<p>de antes</p>', 1, 0, 'ana@x.com', 'ayer')",
                [message],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);

        let row: (String, Option<String>, i64, Option<i64>, Option<String>, Option<i64>) =
            connection
                .query_row(
                    "SELECT text_body, html_body, truncated, smime_status, smime_signer, smime_encrypted
                       FROM message_bodies WHERE message_id = ?1",
                    [message],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .unwrap();
        assert_eq!(
            row,
            (
                "cuerpo de antes".to_string(),
                Some("<p>de antes</p>".to_string()),
                1,
                Some(0),
                Some("ana@x.com".to_string()),
                None
            )
        );

        // Igual que creada de cero (mismo tipo, sin NOT NULL ni valor por omisión), y
        // repetir no cambia nada.
        let mut fresh = Connection::open_in_memory().unwrap();
        apply(&mut fresh).unwrap();
        assert_eq!(columns(&connection), columns(&fresh));
        let added = columns(&fresh)
            .into_iter()
            .find(|c| c.0 == "smime_encrypted")
            .expect("la columna nueva");
        assert_eq!(added, ("smime_encrypted".into(), "INTEGER".into(), 0, None));
        let before = columns(&connection);
        apply(&mut connection).unwrap();
        assert_eq!(columns(&connection), before);
        assert_eq!(schema_version(&connection).unwrap(), 12);
    }

    /// La marca `pending_op` sólo acepta los dos valores conocidos, o `NULL`.
    #[test]
    fn la_marca_pending_op_esta_acotada() {
        let connection = at_version(5);
        for good in ["put", "delete"] {
            connection
                .execute(
                    "UPDATE calendar_objects SET pending_op = ?1 WHERE 1 = 0",
                    [good],
                )
                .unwrap_or(0);
        }
        // Un calendario y un objeto para poder escribir la columna de verdad.
        connection
            .execute(
                "INSERT INTO calendars (id, href, display_name, components, updated_at)
                 VALUES (1, 'https://x/c/', 'C', 'VEVENT', 'ayer')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO calendar_objects
                   (id, calendar_id, href, etag, uid, component, summary, all_day, recurring,
                    zone, status, done, sort_key, span, expansion, raw_ical, updated_at, pending_op)
                 VALUES (1, 1, 'https://x/c/a.ics', '\"v1\"', 'u1', 'VEVENT', 'A', 0, 0,
                    'utc', '', 0, 0, 0, 'complete', 'BEGIN:VCALENDAR', 'ayer', 'put')",
                [],
            )
            .unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE calendar_objects SET pending_op = 'raro' WHERE id = 1",
                    [],
                )
                .is_err(),
            "un valor desconocido no entra"
        );
    }

    /// La columna `op` y el `state` de la cola están acotados a sus valores.
    #[test]
    fn la_cola_acota_op_y_estado() {
        let connection = at_version(5);
        let insert = "INSERT INTO pending_dav_ops
            (area, collection_href, object_href, op, created_at)
            VALUES (?1, 'https://x/c/', ?2, ?3, 'ahora')";
        connection
            .execute(insert, ["calendar", "https://x/c/a.ics", "put"])
            .unwrap();
        connection
            .execute(insert, ["contacts", "https://x/a/ana.vcf", "delete"])
            .unwrap();
        assert!(
            connection
                .execute(insert, ["calendar", "https://x/c/b.ics", "patch"])
                .is_err(),
            "una operación desconocida no entra"
        );
        assert!(
            connection
                .execute(insert, ["archivos", "https://x/c/c.ics", "put"])
                .is_err(),
            "un área desconocida no entra"
        );
        // Una sola op pendiente por objeto.
        assert!(
            connection
                .execute(insert, ["calendar", "https://x/c/a.ics", "delete"])
                .is_err(),
            "no entran dos ops del mismo objeto"
        );
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
        let all = [V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11];
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
        assert_eq!(schema_version(&connection).unwrap(), 12);
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

    /// Un objeto con dos ocurrencias y un recordatorio en cada una, y el
    /// título de una excepción.
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
        connection
            .execute(
                "INSERT INTO object_titles (object_id, position, summary) VALUES (?1, 0, 'Otra')",
                [id],
            )
            .unwrap();
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
        assert_eq!(schema_version(&connection).unwrap(), 12);
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
        assert_eq!(count(&connection, "SELECT count(*) FROM object_titles"), 1);
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
        assert_eq!(count(&connection, "SELECT count(*) FROM object_titles"), 0);
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

    /// **v3 → v4 no pierde nada**: el calendario, los contactos, sus datos, sus
    /// índices y sus tokens siguen ahí después de migrar, y la bitácora también.
    #[test]
    fn de_v3_a_v4_se_conserva_todo() {
        let mut connection = at_version(3);
        let calendar = insert_calendar(&connection, "https://x/c/");
        insert_object(&connection, calendar, "https://x/c/1.ics");
        let book = insert_book(&connection, "https://x/a/");
        let id = insert_contact(&connection, book, "https://x/a/1.vcf", "José Pérez");
        connection
            .execute(
                "INSERT INTO sync_log (at, level, area, message) VALUES ('ayer', 'warn', 'calendar', 'algo')",
                [],
            )
            .unwrap();

        apply(&mut connection).unwrap();
        assert_eq!(schema_version(&connection).unwrap(), 12);
        assert_eq!(found(&connection, "jose"), vec![id]);
        assert_eq!(count(&connection, "SELECT count(*) FROM occurrences"), 2);
        assert_eq!(count(&connection, "SELECT count(*) FROM contact_emails"), 1);
        assert_eq!(
            count(
                &connection,
                "SELECT count(*) FROM sync_state WHERE area = 'calendar'"
            ),
            1
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM sync_log"), 1);
        // Y se puede escribir en las tablas nuevas.
        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES ('INBOX', 'Bandeja de entrada', 'inbox', 'ahora')",
                [],
            )
            .unwrap();
        let mb_id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
                 VALUES (?1, 1, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
                [mb_id],
            )
            .unwrap();
        assert_eq!(count(&connection, "SELECT count(*) FROM messages"), 1);
    }

    /// Borrar una casilla se lleva sus mensajes, sus cuerpos, sus adjuntos,
    /// sus banderas y su token; lo de las otras casillas no se toca.
    #[test]
    fn borrar_una_casilla_se_lleva_todo_lo_suyo() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();

        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES ('INBOX', 'Bandeja de entrada', 'inbox', 'ahora')",
                [],
            )
            .unwrap();
        let inbox = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES ('Sent', 'Enviados', 'sent', 'ahora')",
                [],
            )
            .unwrap();
        let sent = connection.last_insert_rowid();

        for (mb, n) in [(inbox, 1), (inbox, 2), (sent, 1)] {
            connection
                .execute(
                    "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
                     VALUES (?1, ?2, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
                    rusqlite::params![mb, n],
                )
                .unwrap();
            let mid = connection.last_insert_rowid();
            connection
                .execute(
                    "INSERT INTO message_bodies (message_id, text_body, html_body, truncated, updated_at)
                     VALUES (?1, 'texto', '<p>texto</p>', 0, 'ahora')",
                    [mid],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO message_attachments (message_id, part_number, name, content_type, size, inline, content_id)
                     VALUES (?1, '2', 'x.pdf', 'application/pdf', 1024, 0, '')",
                    [mid],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO message_flags (message_id, flag) VALUES (?1, '\\\\Flagged')",
                    [mid],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO sync_state (area, collection, token, updated_at) VALUES ('email', 'INBOX', 't1', 'ahora')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sync_state (area, collection, token, updated_at) VALUES ('email', 'Sent', 't2', 'ahora')",
                [],
            )
            .unwrap();

        connection
            .execute("DELETE FROM mailboxes WHERE id = ?1", [inbox])
            .unwrap();

        assert_eq!(count(&connection, "SELECT count(*) FROM messages"), 1);
        assert_eq!(count(&connection, "SELECT count(*) FROM message_bodies"), 1);
        assert_eq!(
            count(&connection, "SELECT count(*) FROM message_attachments"),
            1
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM message_flags"), 1);
        assert_eq!(
            count(
                &connection,
                "SELECT count(*) FROM sync_state WHERE area = 'email'"
            ),
            1,
            "el token de la casilla borrada se va con ella"
        );
    }

    /// Y borrar un mensaje suelto se lleva su cuerpo, sus adjuntos y sus
    /// banderas.
    #[test]
    fn borrar_un_mensaje_se_lleva_sus_datos() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply(&mut connection).unwrap();

        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES ('INBOX', 'Bandeja de entrada', 'inbox', 'ahora')",
                [],
            )
            .unwrap();
        let inbox = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
                 VALUES (?1, 1, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
                [inbox],
            )
            .unwrap();
        let mid = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO message_bodies (message_id, text_body, html_body, truncated, updated_at)
                 VALUES (?1, 'texto', '<p>texto</p>', 0, 'ahora')",
                [mid],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO message_attachments (message_id, part_number, name, content_type, size, inline, content_id)
                 VALUES (?1, '2', 'x.pdf', 'application/pdf', 1024, 0, '')",
                [mid],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO message_flags (message_id, flag) VALUES (?1, '\\\\Flagged')",
                [mid],
            )
            .unwrap();

        assert_eq!(count(&connection, "SELECT count(*) FROM message_bodies"), 1);
        assert_eq!(
            count(&connection, "SELECT count(*) FROM message_attachments"),
            1
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM message_flags"), 1);

        connection
            .execute("DELETE FROM messages WHERE id = ?1", [mid])
            .unwrap();

        assert_eq!(count(&connection, "SELECT count(*) FROM message_bodies"), 0);
        assert_eq!(
            count(&connection, "SELECT count(*) FROM message_attachments"),
            0
        );
        assert_eq!(count(&connection, "SELECT count(*) FROM message_flags"), 0);
    }

    /// La lista de una casilla pagina por `(sort_key DESC, id)`: el plan usa
    /// el índice y no ordena en memoria.
    #[test]
    fn el_orden_de_la_lista_de_correo_usa_su_indice() {
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
            "SELECT id FROM messages WHERE (sort_key, id) < (100, 0) ORDER BY sort_key DESC, id DESC LIMIT 50",
        );
        assert!(all.contains("messages_by_sort"), "{all}");
        assert!(!all.contains("TEMP B-TREE"), "{all}");
        let by_mailbox = plan(
            "SELECT id FROM messages WHERE mailbox_id = 1 AND (sort_key, id) < (100, 0) \
             ORDER BY sort_key DESC, id DESC LIMIT 50",
        );
        assert!(
            by_mailbox.contains("messages_by_mailbox_and_sort"),
            "{by_mailbox}"
        );
        assert!(!by_mailbox.contains("TEMP B-TREE"), "{by_mailbox}");
    }

    /// Un mensaje es uno por casilla y UID; el mismo UID en otra casilla es
    /// otro mensaje.
    #[test]
    fn un_mensaje_es_uno_por_casilla_y_uid() {
        let mut connection = Connection::open_in_memory().unwrap();
        apply(&mut connection).unwrap();
        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES ('INBOX', 'Bandeja de entrada', 'inbox', 'ahora')",
                [],
            )
            .unwrap();
        let a = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO mailboxes (name, display_name, role, updated_at) VALUES ('Sent', 'Enviados', 'sent', 'ahora')",
                [],
            )
            .unwrap();
        let b = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
                 VALUES (?1, 1, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
                [a],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
                 VALUES (?1, 1, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
                [b],
            )
            .unwrap();
        let again = connection.execute(
            "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
             VALUES (?1, 1, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
            [a],
        );
        assert!(again.is_err());
        // Y sin casilla no hay mensaje.
        let orphan = connection.execute(
            "INSERT INTO messages (mailbox_id, uid, from_addr, to_addrs, cc_addrs, bcc_addrs, subject, date_ts, sort_key, size, updated_at)
             VALUES (999, 1, 'ana@x.com', 'yo@x.com', '', '', 'Hola', 100, 100, 1024, 'ahora')",
            [],
        );
        assert!(orphan.is_err());
    }
}
