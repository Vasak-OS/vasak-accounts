//! Posponer mensajes (`vasak-accounts#22`) por D-Bus, **lo que se puede probar
//! sin un servidor IMAP real**: los rechazos de antes de tocar el servidor, el
//! almacén ausente, y el productor del bucle de vuelta ante un servidor que no
//! contesta. Un bus privado de la prueba y un servicio de cuentas falso (ver
//! `test_bus.rs`).
//!
//! No hay almacén en estas pruebas (`LIVE_STORE` lo fija sólo el arranque del
//! servicio): es el estado de «el almacén no está disponible», que es justo el
//! que `SnoozeMessage` tiene que reconocer **antes** de mover nada.

use crate::snooze_return::SnoozeReturner;
use crate::store::snooze::SnoozedMessage;
use crate::test_bus::{captured_logs, error_of, Fixture};
use crate::{store_api, Service, ServiceSnoozeReturner};

const ACCOUNT: &str = "cta";
const ADDRESS: &str = "ana@vasak.test";

fn row(message_id: &str) -> SnoozedMessage {
    SnoozedMessage {
        id: 1,
        message_id: message_id.into(),
        origin_mailbox: "INBOX".into(),
        new_uid: Some(7),
        uidvalidity: Some(3),
        return_at: 1_000,
        created_at: 1,
    }
}

/// Sin almacén escribible, `SnoozeMessage` **no mueve**: rechaza antes de tocar
/// el servidor. Si no, el mensaje quedaría en Pospuestos sin fila que lo traiga
/// de vuelta. La cuenta existe y es alcanzable por el servicio de cuentas, así
/// que el rechazo tiene que ser por el almacén y no por la cuenta ni por el
/// servidor de correo (que acá no existe: otro orden daría otro error).
#[tokio::test]
async fn posponer_sin_almacen_rechaza_antes_de_mover() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, text) = error_of(
        f.call("SnoozeMessage", &(ACCOUNT, "INBOX", 7u32, 9_999i64))
            .await,
    );

    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert!(
        text.contains("el almacén de la cuenta no está disponible"),
        "el rechazo no fue por el almacén: {text}"
    );
}

/// Lo mismo con la casilla vacía (la de entrada) y con otra: el chequeo del
/// almacén no depende de dónde estaba el mensaje.
#[tokio::test]
async fn posponer_sin_almacen_rechaza_desde_cualquier_casilla() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    for mailbox in ["", "Trabajo"] {
        let (_, text) = error_of(
            f.call("SnoozeMessage", &(ACCOUNT, mailbox, 7u32, 9_999i64))
                .await,
        );
        assert!(text.contains("almacén"), "casilla «{mailbox}»: {text}");
    }
}

/// `ListSnoozed` sin almacén dice que no está disponible; no devuelve una lista
/// vacía, que la ventana leería como «no hay pospuestos».
#[tokio::test]
async fn listar_pospuestos_sin_almacen_no_es_una_lista_vacia() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, text) = error_of(f.call("ListSnoozed", &(ACCOUNT,)).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert!(text.contains("el almacén no está disponible"), "{text}");
}

/// `CancelSnooze` sin almacén es un error y **no** `no_estaba`: no poder mirar
/// la cola no es lo mismo que no haber pospuesto nunca el mensaje.
#[tokio::test]
async fn cancelar_sin_almacen_es_un_error_y_no_un_no_estaba() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, text) = error_of(f.call("CancelSnooze", &(ACCOUNT, "<a@x>")).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert!(text.contains("el almacén no está disponible"), "{text}");
}

/// Un servidor que no contesta no borra el pospuesto: el productor del bucle
/// registra que no pudo devolverlo —y deja la fila para la próxima vuelta— en
/// vez de darlo por atendido. Acá el servidor es inalcanzable (el servicio de
/// cuentas falso no da ni token).
#[tokio::test]
async fn el_productor_no_da_por_atendido_un_pospuesto_si_el_servidor_no_contesta() {
    let _f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;
    let returner = ServiceSnoozeReturner {
        service: Service::default(),
    };

    returner.return_due(ACCOUNT, &row("<a@x>")).await;

    let logs = captured_logs();
    assert!(
        logs.contains("no se devolvió el pospuesto «<a@x>»"),
        "no quedó registrado el reintento: {logs}"
    );
}

/// Devolver un pospuesto de una cuenta que ya no existe es un error con motivo,
/// que el bucle registra y `CancelSnooze` le pasa a la ventana.
#[tokio::test]
async fn devolver_de_una_cuenta_que_ya_no_existe_da_error() {
    let _f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let error = Service::default()
        .return_to_inbox("borrada", &row("<a@x>"))
        .await
        .unwrap_err();

    assert!(error.contains("ya no existe"), "{error}");
}

/// Las funciones de almacén de los pospuestos, antes de que el servicio de
/// almacén arranque (o sin cuenta con correo): nada se anota, nada vence y
/// nadie explota.
#[tokio::test]
async fn los_pospuestos_sin_almacen_no_hacen_nada_ni_fallan() {
    assert!(!store_api::snooze_store_ready(ACCOUNT).await);
    assert!(
        store_api::snooze_upsert(ACCOUNT, "<a@x>", "INBOX", Some(7), Some(3), 1_000)
            .await
            .is_err()
    );
    assert!(store_api::snooze_delete(ACCOUNT, "<a@x>").await.is_err());
    assert!(store_api::snooze_list(ACCOUNT).await.is_err());
    assert!(store_api::snooze_due_all(1_000, 50).await.is_empty());
    assert_eq!(store_api::snooze_next_after(1_000).await, None);
}

// ── Contra un servidor IMAP de mentira, por TLS ───────────────────────────
//
// `Reader` habla con un `Session` de TLS de verdad (no es genérico), así que la
// única forma de ejercer lo que hacen `snooze_to` y `return_from_snooze` con el
// servidor —qué comando manda, en qué orden, si busca o mueve directo— es un
// servidor que hable TLS: uno de `localhost`, con un certificado autofirmado de
// la prueba (`tests/fixtures/imap-tls`) que `test_bus` deja como único de
// confianza (`SSL_CERT_FILE`). El guion es el de `imap::tests::with_server`: pares
// de «lo que se espera recibir» y «lo que se contesta», y la prueba **falla** si
// llega otro comando o si el cliente deja de mandar.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::imap::MoveOutcome;
use crate::SNOOZE_MAILBOX;

type Script = Vec<(&'static str, Vec<&'static str>)>;

/// Un guion; `caps` son las capacidades que anuncia el servidor (`MOVE`, `UIDPLUS`).
/// El saludo, el `LOGIN`, el `CAPABILITY` y el `SELECT "INBOX"` con que `Reader`
/// abre su sesión van solos; `script` es lo que viene después.
fn prelude(caps: &'static str) -> Script {
    vec![
        ("LOGIN", vec!["{tag} OK LOGIN completado"]),
        (
            "CAPABILITY",
            vec![
                Box::leak(format!("* CAPABILITY IMAP4rev1 {caps}").into_boxed_str()),
                "{tag} OK CAPABILITY completado",
            ],
        ),
        (
            "SELECT \"INBOX\"",
            vec![
                "* 3 EXISTS",
                "* OK [UIDVALIDITY 1] ok",
                "{tag} OK [READ-WRITE] SELECT completado",
            ],
        ),
    ]
}

/// Levanta el servidor y devuelve su puerto y la tarea con lo recibido.
async fn imap_server(
    caps: &'static str,
    script: Script,
) -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        include_bytes!("../tests/fixtures/imap-tls/key.der").as_slice(),
    ));
    let cert =
        CertificateDer::from_pem_slice(include_bytes!("../tests/fixtures/imap-tls/cert.pem"))
            .unwrap();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut full = prelude(caps);
    full.extend(script);
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(tcp).await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();
        let mut received = Vec::new();
        let mut tag = String::from("a1");
        let mut awaiting_literal = false;

        writer.write_all(b"* OK listo\r\n").await.unwrap();
        for (expected, reply) in full {
            let Ok(Some(line)) = lines.next_line().await else {
                panic!("el cliente dejó de mandar; se esperaba «{expected}»");
            };
            assert!(
                line.contains(expected),
                "se esperaba un comando con «{expected}» y llegó «{line}»"
            );
            received.push(line.clone());
            if !awaiting_literal {
                tag = line.split_whitespace().next().unwrap_or("a1").to_string();
            }
            awaiting_literal = reply.iter().any(|l| l.starts_with('+'));
            for l in reply {
                writer
                    .write_all(l.replace("{tag}", &tag).as_bytes())
                    .await
                    .unwrap();
                writer.write_all(b"\r\n").await.unwrap();
            }
        }
        // Se terminó el guion: si el cliente manda algo más, no estaba previsto.
        if let Ok(Ok(Some(extra))) =
            tokio::time::timeout(Duration::from_millis(300), lines.next_line()).await
        {
            panic!("el cliente mandó un comando que no estaba en el guion: «{extra}»");
        }
        received
    });
    (port, task)
}

/// Lo que mandó el cliente tras la apertura de sesión (`LOGIN`, `CAPABILITY`,
/// `SELECT "INBOX"`), sin las etiquetas.
fn after_open(received: &[String]) -> Vec<String> {
    received
        .iter()
        .skip(3)
        .map(|l| l.split_once(' ').map(|(_, c)| c).unwrap_or(l).to_string())
        .collect()
}

/// Espera al servidor de mentira con un tope: si el guion pedía más de lo que el
/// cliente mandó, se dice en vez de colgar la prueba.
async fn finish(task: tokio::task::JoinHandle<Vec<String>>) -> Vec<String> {
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("el servidor esperaba más comandos de los que mandó el cliente")
        .expect("el servidor de mentira falló (ver el mensaje de arriba)")
}

const HEADERS_WITH_ID: &str = "Subject: Hola\r\nMessage-ID: <abc@x>";

fn fetch_with_id() -> Vec<&'static str> {
    vec![
        // 34 bytes de encabezado + el CRLF que agrega el servidor.
        "* 1 FETCH (UID 7 FLAGS () BODY[HEADER.FIELDS (MESSAGE-ID)] {36}",
        HEADERS_WITH_ID,
        ")",
        "{tag} OK FETCH completado",
    ]
}

/// Una cuenta contra el servidor de mentira, con el `Service` y lo que hace falta
/// para llamar a `Reader`.
struct Client {
    service: Service,
    broker: crate::broker::Broker,
    account: crate::broker::Account,
    _fixture: Fixture,
}

async fn client(port: u16) -> Client {
    let fixture = Fixture::start_with_imap(&[(ACCOUNT, ADDRESS)], port).await;
    let service = Service::default();
    let (broker, account) = service.account(ACCOUNT).await.unwrap();
    Client {
        service,
        broker,
        account,
        _fixture: fixture,
    }
}

impl Client {
    async fn snooze_to(&self, uid: u32) -> Result<(String, MoveOutcome), String> {
        let reader = self.service.reader(ACCOUNT).await;
        let result = reader
            .lock()
            .await
            .snooze_to(&self.broker, &self.account, "INBOX", uid, SNOOZE_MAILBOX)
            .await;
        result
    }

    async fn return_from_snooze(&self, row: &SnoozedMessage) -> Result<bool, String> {
        let reader = self.service.reader(ACCOUNT).await;
        let result = reader
            .lock()
            .await
            .return_from_snooze(&self.broker, &self.account, SNOOZE_MAILBOX, row)
            .await;
        result
    }
}

fn select_snooze(validity: &'static str) -> (&'static str, Vec<&'static str>) {
    (
        "SELECT \"VasakOS/Pospuestos\"",
        vec![
            "* 1 EXISTS",
            validity,
            "{tag} OK [READ-WRITE] SELECT completado",
        ],
    )
}

/// Posponer: el `Message-ID` se lee **antes** de mover (con `PEEK`, sin marcar
/// como leído), la casilla de pospuestos se crea y recién entonces se mueve, y
/// lo que vuelve es ese `Message-ID` y el `COPYUID` del movimiento.
#[tokio::test]
async fn posponer_lee_el_message_id_antes_de_mover_y_devuelve_el_copyuid() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            (
                "SELECT \"INBOX\"",
                vec![
                    "* 3 EXISTS",
                    "* OK [UIDVALIDITY 1] ok",
                    "{tag} OK [READ-WRITE] ok",
                ],
            ),
            ("UID FETCH 7 (", fetch_with_id()),
            (
                "CREATE \"VasakOS/Pospuestos\"",
                vec!["{tag} OK CREATE completado"],
            ),
            (
                "UID MOVE 7 \"VasakOS/Pospuestos\"",
                vec!["* OK [COPYUID 5 7 42] movido", "{tag} OK MOVE completado"],
            ),
        ],
    )
    .await;
    let c = client(port).await;

    let (message_id, outcome) = c.snooze_to(7).await.unwrap();

    assert_eq!(message_id, "<abc@x>");
    assert_eq!(
        outcome,
        MoveOutcome::Complete {
            new_uid: Some(42),
            uidvalidity: Some(5)
        }
    );
    let received = finish(task).await;
    assert!(
        after_open(&received)[1].contains("BODY.PEEK["),
        "{received:?}"
    );
}

/// Un mensaje sin `Message-ID` **no se mueve**: no se podría volver a encontrar
/// para devolverlo. El error sale antes de crear la casilla y antes de mover, y
/// el servidor no recibe nada más que la lectura del encabezado.
#[tokio::test]
async fn posponer_un_mensaje_sin_message_id_no_lo_mueve() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            (
                "SELECT \"INBOX\"",
                vec![
                    "* 3 EXISTS",
                    "* OK [UIDVALIDITY 1] ok",
                    "{tag} OK [READ-WRITE] ok",
                ],
            ),
            (
                "UID FETCH 7 (",
                vec![
                    "* 1 FETCH (UID 7 FLAGS () BODY[HEADER.FIELDS (MESSAGE-ID)] {15}",
                    "Subject: Hola",
                    ")",
                    "{tag} OK FETCH completado",
                ],
            ),
        ],
    )
    .await;
    let c = client(port).await;

    let error = c.snooze_to(7).await.unwrap_err();

    assert!(error.contains("no tiene Message-ID"), "{error}");
    let received = finish(task).await; // y de ahí no pasó: no hubo CREATE ni MOVE
    assert_eq!(after_open(&received).len(), 2, "{received:?}");
}

/// Un `Message-ID` en blanco tampoco sirve para seguir al mensaje.
#[tokio::test]
async fn posponer_un_mensaje_con_message_id_en_blanco_no_lo_mueve() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            (
                "SELECT \"INBOX\"",
                vec![
                    "* 3 EXISTS",
                    "* OK [UIDVALIDITY 1] ok",
                    "{tag} OK [READ-WRITE] ok",
                ],
            ),
            (
                "UID FETCH 7 (",
                vec![
                    "* 1 FETCH (UID 7 FLAGS () BODY[HEADER.FIELDS (MESSAGE-ID)] {17}",
                    "Message-ID:    ",
                    ")",
                    "{tag} OK FETCH completado",
                ],
            ),
        ],
    )
    .await;
    let c = client(port).await;

    let error = c.snooze_to(7).await.unwrap_err();

    assert!(error.contains("no tiene Message-ID"), "{error}");
    finish(task).await;
}

/// Sin `MOVE` ni `UIDPLUS` el servidor deja una copia en la casilla de origen:
/// `snooze_to` lo dice con `OldCopyKept` (y `SnoozeMessage` rechaza), sin
/// inventar un `COPYUID`.
#[tokio::test]
async fn posponer_sin_move_ni_uidplus_avisa_que_quedo_la_copia_vieja() {
    let (port, task) = imap_server(
        "",
        vec![
            (
                "SELECT \"INBOX\"",
                vec![
                    "* 3 EXISTS",
                    "* OK [UIDVALIDITY 1] ok",
                    "{tag} OK [READ-WRITE] ok",
                ],
            ),
            ("UID FETCH 7 (", fetch_with_id()),
            (
                "CREATE \"VasakOS/Pospuestos\"",
                vec!["{tag} OK CREATE completado"],
            ),
            (
                "UID COPY 7 \"VasakOS/Pospuestos\"",
                vec!["{tag} OK copiado"],
            ),
            ("UID STORE 7 +FLAGS (\\Deleted)", vec!["{tag} OK marcado"]),
        ],
    )
    .await;
    let c = client(port).await;

    let (message_id, outcome) = c.snooze_to(7).await.unwrap();

    assert_eq!(message_id, "<abc@x>");
    assert_eq!(outcome, MoveOutcome::OldCopyKept);
    finish(task).await;
}

/// Una casilla de pospuestos que ya existía no es un error al posponer.
#[tokio::test]
async fn posponer_con_la_casilla_ya_creada_sigue_adelante() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            (
                "SELECT \"INBOX\"",
                vec![
                    "* 3 EXISTS",
                    "* OK [UIDVALIDITY 1] ok",
                    "{tag} OK [READ-WRITE] ok",
                ],
            ),
            ("UID FETCH 7 (", fetch_with_id()),
            (
                "CREATE \"VasakOS/Pospuestos\"",
                vec!["{tag} NO [ALREADYEXISTS] Mailbox already exists"],
            ),
            (
                "UID MOVE 7",
                vec!["* OK [COPYUID 5 7 42] movido", "{tag} OK MOVE completado"],
            ),
        ],
    )
    .await;
    let c = client(port).await;

    assert!(c.snooze_to(7).await.is_ok());
    finish(task).await;
}

fn snoozed(new_uid: Option<i64>, uidvalidity: Option<i64>) -> SnoozedMessage {
    SnoozedMessage {
        id: 1,
        message_id: "<abc@x>".into(),
        origin_mailbox: "INBOX".into(),
        new_uid,
        uidvalidity,
        return_at: 1_000,
        created_at: 1,
    }
}

/// Volver con el `COPYUID` vigente: el `UIDVALIDITY` de la casilla es el mismo de
/// cuando se pospuso, así que se mueve **ese UID directo**, sin buscar.
#[tokio::test]
async fn volver_con_el_uidvalidity_vigente_mueve_el_uid_directo() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 5] ok"),
            ("UID MOVE 42 \"INBOX\"", vec!["{tag} OK MOVE completado"]),
        ],
    )
    .await;
    let c = client(port).await;

    assert_eq!(
        c.return_from_snooze(&snoozed(Some(42), Some(5))).await,
        Ok(true)
    );

    let received = finish(task).await;
    assert!(
        !after_open(&received).iter().any(|c| c.contains("SEARCH")),
        "buscó teniendo el UID vigente: {received:?}"
    );
}

/// Si el servidor recreó la casilla (otro `UIDVALIDITY`), el UID guardado no
/// apunta a nada: se busca por `Message-ID` y se mueve el que aparece, **no** el
/// UID viejo.
#[tokio::test]
async fn volver_con_otro_uidvalidity_busca_por_message_id() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 9] ok"),
            (
                "HEADER Message-ID \"<abc@x>\"",
                vec!["* SEARCH 77", "{tag} OK SEARCH completado"],
            ),
            ("UID MOVE 77 \"INBOX\"", vec!["{tag} OK MOVE completado"]),
        ],
    )
    .await;
    let c = client(port).await;

    assert_eq!(
        c.return_from_snooze(&snoozed(Some(42), Some(5))).await,
        Ok(true)
    );
    finish(task).await;
}

/// Sin `COPYUID` anotado (servidor sin `UIDPLUS`) se busca por `Message-ID`
/// directamente.
#[tokio::test]
async fn volver_sin_copyuid_anotado_busca_por_message_id() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 5] ok"),
            (
                "HEADER Message-ID \"<abc@x>\"",
                vec!["* SEARCH 8", "{tag} OK SEARCH completado"],
            ),
            ("UID MOVE 8 \"INBOX\"", vec!["{tag} OK MOVE completado"]),
        ],
    )
    .await;
    let c = client(port).await;

    assert_eq!(c.return_from_snooze(&snoozed(None, None)).await, Ok(true));
    finish(task).await;
}

/// Un UID guardado que no entra en `u32` (la base lo guarda como `i64`) se trata
/// como ausente: se busca por `Message-ID` en vez de truncar o fallar.
#[tokio::test]
async fn volver_con_un_uid_fuera_de_rango_busca_por_message_id() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 5] ok"),
            (
                "HEADER Message-ID",
                vec!["* SEARCH 8", "{tag} OK SEARCH completado"],
            ),
            ("UID MOVE 8 \"INBOX\"", vec!["{tag} OK MOVE completado"]),
        ],
    )
    .await;
    let c = client(port).await;

    let row = snoozed(Some(i64::from(u32::MAX) + 1), Some(5));
    assert_eq!(c.return_from_snooze(&row).await, Ok(true));
    finish(task).await;
}

/// Si el mensaje ya no está en Pospuestos (otro dispositivo lo movió) no es un
/// error: se contesta que no se movió nada, y no se manda ningún `MOVE`.
#[tokio::test]
async fn volver_de_algo_que_ya_no_esta_no_es_un_error_ni_mueve_nada() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 9] ok"),
            (
                "HEADER Message-ID",
                vec!["* SEARCH", "{tag} OK SEARCH completado"],
            ),
        ],
    )
    .await;
    let c = client(port).await;

    assert_eq!(
        c.return_from_snooze(&snoozed(Some(42), Some(5))).await,
        Ok(false)
    );
    finish(task).await; // y de ahí no pasó: el guion no tiene MOVE
}

/// Vuelve a la casilla **de origen** que quedó anotada, no siempre a la de
/// entrada.
#[tokio::test]
async fn volver_va_a_la_casilla_de_origen_anotada() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 5] ok"),
            ("UID MOVE 42 \"Trabajo\"", vec!["{tag} OK MOVE completado"]),
        ],
    )
    .await;
    let c = client(port).await;

    let mut row = snoozed(Some(42), Some(5));
    row.origin_mailbox = "Trabajo".into();
    assert_eq!(c.return_from_snooze(&row).await, Ok(true));
    finish(task).await;
}

/// `Service::return_to_inbox` (lo que comparten `CancelSnooze` y el bucle) llega
/// al mismo camino: cuenta → sesión → mover por UID directo.
#[tokio::test]
async fn el_servicio_devuelve_un_pospuesto_por_imap() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 5] ok"),
            ("UID MOVE 42 \"INBOX\"", vec!["{tag} OK MOVE completado"]),
        ],
    )
    .await;
    let c = client(port).await;

    assert_eq!(
        c.service
            .return_to_inbox(ACCOUNT, &snoozed(Some(42), Some(5)))
            .await,
        Ok(true)
    );
    finish(task).await;
}

/// El productor del bucle da por atendido un pospuesto que ya no estaba: no
/// registra ningún reintento (la fila se va, no se vuelve a intentar para
/// siempre).
#[tokio::test]
async fn el_productor_atiende_un_pospuesto_que_ya_no_estaba() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 9] ok"),
            (
                "HEADER Message-ID",
                vec!["* SEARCH", "{tag} OK SEARCH completado"],
            ),
        ],
    )
    .await;
    let c = client(port).await;
    let returner = ServiceSnoozeReturner {
        service: c.service.clone(),
    };

    returner
        .return_due(ACCOUNT, &snoozed(Some(42), Some(5)))
        .await;

    finish(task).await;
    let logs = captured_logs();
    assert!(!logs.contains("no se devolvió el pospuesto"), "{logs}");
}

/// Y el que el servidor no pudo mover (`NO` a mitad de la vuelta) **no** se da
/// por atendido: queda registrado para el reintento.
#[tokio::test]
async fn el_productor_reintenta_si_el_servidor_rechaza_la_vuelta() {
    let (port, task) = imap_server(
        "MOVE UIDPLUS",
        vec![
            select_snooze("* OK [UIDVALIDITY 5] ok"),
            ("UID MOVE 42 \"INBOX\"", vec!["{tag} NO servidor ocupado"]),
        ],
    )
    .await;
    let c = client(port).await;
    let returner = ServiceSnoozeReturner {
        service: c.service.clone(),
    };

    returner
        .return_due(ACCOUNT, &snoozed(Some(42), Some(5)))
        .await;

    finish(task).await;
    let logs = captured_logs();
    assert!(
        logs.contains("no se devolvió el pospuesto «<abc@x>»"),
        "{logs}"
    );
}
