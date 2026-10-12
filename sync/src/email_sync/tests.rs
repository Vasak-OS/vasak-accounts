//! La sincronización del correo al almacén: lo que se decide sin red, y vueltas
//! enteras contra el servidor IMAP de mentira de `imap.rs` y una base de
//! verdad, con el llavero falso.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use super::*;
use crate::imap::tests::with_server_caps;
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{AccountListing, Consent, ListedAccount, Locations};
use crate::store::paths::tests::TempDir;

use mailboxes::MailboxRole as ServerRole;

const ACCOUNT: &str = "cuenta";

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn server_box(path: &str, role: ServerRole, selectable: bool) -> Mailbox {
    Mailbox {
        path: path.into(),
        name: path.into(),
        delimiter: Some('/'),
        role,
        selectable,
    }
}

fn token(
    uidvalidity: u32,
    modseq: Option<u64>,
    uid_next: Option<u32>,
    exists: u32,
) -> MailboxToken {
    MailboxToken {
        uidvalidity,
        highest_modseq: modseq,
        uid_next,
        exists,
    }
}

fn uid_flags(uid: u32, flags: &[&str]) -> UidFlags {
    UidFlags {
        uid,
        flags: flags.iter().map(|f| f.to_string()).collect(),
    }
}

fn record(uid: u32, headers: &str) -> HeaderRecord {
    HeaderRecord {
        uid,
        flags: vec!["\\Seen".into()],
        size: 1234,
        headers: headers.into(),
    }
}

// ---------------------------------------------------------------------------
// Casillas: cuáles, en qué orden, con qué ventana
// ---------------------------------------------------------------------------

#[test]
fn cada_rol_del_servidor_tiene_su_rol_en_el_almacen() {
    assert_eq!(store_role(ServerRole::Inbox), MailboxRole::Inbox);
    assert_eq!(store_role(ServerRole::Sent), MailboxRole::Sent);
    assert_eq!(store_role(ServerRole::Drafts), MailboxRole::Drafts);
    assert_eq!(store_role(ServerRole::Trash), MailboxRole::Trash);
    assert_eq!(store_role(ServerRole::Spam), MailboxRole::Junk);
    assert_eq!(store_role(ServerRole::Archive), MailboxRole::Archive);
    // «Todo el correo» es una copia de las demás: no es una casilla especial.
    assert_eq!(store_role(ServerRole::All), MailboxRole::Other);
    assert_eq!(store_role(ServerRole::Other), MailboxRole::Other);
}

#[test]
fn la_bandeja_de_entrada_va_primero_y_todo_el_correo_al_final() {
    let order = [
        ServerRole::Inbox,
        ServerRole::Sent,
        ServerRole::Drafts,
        ServerRole::Archive,
        ServerRole::Trash,
        ServerRole::Spam,
        ServerRole::Other,
        ServerRole::All,
    ];
    for pair in order.windows(2) {
        assert!(
            priority(pair[0]) < priority(pair[1]),
            "{:?} tenía que ir antes que {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[test]
fn solo_se_sincronizan_las_casillas_que_se_pueden_abrir_en_orden_y_sin_repetir() {
    let listed = vec![
        server_box("Zeta", ServerRole::Other, true),
        server_box("[Gmail]", ServerRole::Other, false),
        server_box("[Gmail]/Todos", ServerRole::All, true),
        server_box("Alfa", ServerRole::Other, true),
        server_box("Enviados", ServerRole::Sent, true),
        server_box("INBOX", ServerRole::Inbox, true),
        server_box("Alfa", ServerRole::Other, true),
    ];
    let paths: Vec<String> = selectable(listed).into_iter().map(|m| m.path).collect();
    assert_eq!(
        paths,
        vec!["INBOX", "Enviados", "Alfa", "Zeta", "[Gmail]/Todos"]
    );
}

/// Una cuenta corporativa con cientos de carpetas: el tope deja afuera las
/// últimas, nunca la de entrada ni las especiales.
#[test]
fn el_tope_de_casillas_deja_afuera_las_comunes_y_no_la_de_entrada() {
    let mut listed: Vec<Mailbox> = (0..MAX_MAILBOXES + 50)
        .map(|i| server_box(&format!("carpeta{i:03}"), ServerRole::Other, true))
        .collect();
    listed.push(server_box("Papelera", ServerRole::Trash, true));
    listed.push(server_box("INBOX", ServerRole::Inbox, true));

    let chosen = selectable(listed);
    assert_eq!(chosen.len(), MAX_MAILBOXES);
    assert_eq!(chosen[0].path, "INBOX");
    assert_eq!(chosen[1].path, "Papelera");
    assert!(chosen.iter().all(|m| m.path != "carpeta149"));
}

#[test]
fn la_bandeja_de_entrada_guarda_mas_mensajes_que_las_demas() {
    assert_eq!(window_for(MailboxRole::Inbox), INBOX_WINDOW);
    for role in [
        MailboxRole::Sent,
        MailboxRole::Drafts,
        MailboxRole::Trash,
        MailboxRole::Junk,
        MailboxRole::Archive,
        MailboxRole::Other,
    ] {
        assert_eq!(window_for(role), OTHER_WINDOW);
    }
    const { assert!(INBOX_WINDOW > OTHER_WINDOW) };
}

// ---------------------------------------------------------------------------
// El token de una casilla
// ---------------------------------------------------------------------------

#[test]
fn el_token_de_una_casilla_vuelve_igual_de_ida_y_vuelta() {
    for t in [
        token(7, Some(715_194_045_007), Some(4392), 120),
        token(1, None, Some(3), 0),
        token(u32::MAX, Some(u64::MAX), None, u32::MAX),
        token(9, None, None, 5),
    ] {
        assert_eq!(MailboxToken::decode(&t.encode()), Some(t));
    }
    assert_eq!(token(7, Some(100), Some(3), 2).encode(), "v1 7 100 3 2");
    // Lo que no se sabe va como `-`.
    assert_eq!(token(7, None, None, 2).encode(), "v1 7 - - 2");
}

/// Lo que no se entiende se trata como «sin token»: la casilla se compara
/// entera, que es lo seguro.
#[test]
fn un_token_que_no_se_entiende_no_se_toma() {
    for bad in [
        "",
        "v1",
        "v2 7 100 3 2",
        "V1 7 100 3 2",
        "v1 7 100 3",
        "v1 7 100 3 2 9",
        "v1 x 100 3 2",
        "v1 7 cien 3 2",
        "v1 7 100 - x",
        "v1 -1 100 3 2",
        "v1 7 100 4294967296 2",
        "v1  7 100 3 2",
        "basura",
    ] {
        assert_eq!(MailboxToken::decode(bad), None, "se tomó: {bad:?}");
    }
}

// ---------------------------------------------------------------------------
// Qué hacer con una casilla
// ---------------------------------------------------------------------------

#[test]
fn sin_token_anterior_se_compara() {
    let now = token(7, Some(100), Some(3), 2);
    assert_eq!(decide(None, now, false), MailboxAction::Diff);
    assert_eq!(decide(None, now, true), MailboxAction::Diff);
}

/// Con otro `UIDVALIDITY`, los UID guardados apuntan a otros mensajes:
/// compararlos sería mezclar el correo de uno con las banderas de otro.
#[test]
fn otro_uidvalidity_vacia_la_casilla() {
    let before = token(7, Some(100), Some(3), 2);
    for now in [token(8, Some(100), Some(3), 2), token(8, None, None, 0)] {
        assert_eq!(decide(Some(before), now, false), MailboxAction::Reset);
        assert_eq!(decide(Some(before), now, true), MailboxAction::Reset);
    }
}

#[test]
fn con_condstore_el_mismo_modseq_saltea_y_otro_compara() {
    let before = token(7, Some(100), Some(3), 2);
    // Mismo HIGHESTMODSEQ: nada cambió, aunque sea la de entrada.
    assert_eq!(decide(Some(before), before, true), MailboxAction::Skip);
    assert_eq!(decide(Some(before), before, false), MailboxAction::Skip);
    // Otro: algo cambió, aunque UIDNEXT y la cantidad sean iguales (banderas).
    let flags_changed = token(7, Some(101), Some(3), 2);
    assert_eq!(
        decide(Some(before), flags_changed, false),
        MailboxAction::Diff
    );
}

/// Sin CONDSTORE, `UIDNEXT` y la cantidad dicen si llegó o se fue algo, pero
/// no si cambió una bandera. La de entrada es la que se mira: se compara
/// siempre. Las demás se saltean.
#[test]
fn sin_condstore_la_de_entrada_se_compara_igual() {
    let before = token(7, None, Some(3), 2);
    assert_eq!(decide(Some(before), before, false), MailboxAction::Skip);
    assert_eq!(decide(Some(before), before, true), MailboxAction::Diff);

    // Llegó algo, o se fue algo.
    assert_eq!(
        decide(Some(before), token(7, None, Some(4), 3), false),
        MailboxAction::Diff
    );
    assert_eq!(
        decide(Some(before), token(7, None, Some(3), 1), false),
        MailboxAction::Diff
    );

    // Antes con CONDSTORE y ahora sin (o al revés): se mira por UIDNEXT.
    let with = token(7, Some(100), Some(3), 2);
    assert_eq!(decide(Some(with), before, false), MailboxAction::Skip);
    assert_eq!(decide(Some(before), with, false), MailboxAction::Skip);
}

/// Un servidor que no dijo `UIDNEXT` no dice si llegó algo: sin eso no se
/// puede afirmar que nada cambió.
#[test]
fn sin_uidnext_anterior_no_se_saltea() {
    let before = token(7, None, None, 2);
    assert_eq!(decide(Some(before), before, false), MailboxAction::Diff);
    assert_eq!(
        decide(Some(before), token(7, None, Some(3), 2), false),
        MailboxAction::Diff
    );
}

// ---------------------------------------------------------------------------
// Banderas y diferencias
// ---------------------------------------------------------------------------

#[test]
fn las_banderas_del_servidor_se_leen_sin_distinguir_mayusculas() {
    let flags: Vec<String> = [
        "\\SEEN",
        "\\answered",
        "\\Flagged",
        "\\DrAfT",
        "\\Deleted",
        "$Forwarded",
    ]
    .iter()
    .map(|f| f.to_string())
    .collect();
    assert_eq!(
        stored_flags(&flags),
        StoredFlags {
            seen: true,
            answered: true,
            flagged: true,
            draft: true,
            deleted: true,
        }
    );
    assert_eq!(stored_flags(&[]), StoredFlags::default());
    // `Seen` sin la barra es una palabra clave cualquiera, no `\Seen`.
    assert_eq!(stored_flags(&["Seen".into()]), StoredFlags::default());
}

#[test]
fn la_diferencia_dice_que_traer_que_cambiar_y_que_borrar() {
    let read = StoredFlags {
        seen: true,
        ..Default::default()
    };
    let stored: HashMap<u64, StoredFlags> = HashMap::from([
        (1, StoredFlags::default()), // ya no está en el servidor
        (2, read),                   // igual
        (3, StoredFlags::default()), // ahora leído
        (4, read),                   // fuera de la ventana
    ]);
    let server = vec![
        uid_flags(2, &["\\Seen"]),
        uid_flags(3, &["\\Seen", "\\Flagged"]),
        uid_flags(5, &[]),
        uid_flags(9, &["\\Seen"]),
        uid_flags(7, &[]),
    ];

    let plan = plan_mailbox(&stored, &server);
    // Lo nuevo, del más nuevo al más viejo: lo de hoy llega primero.
    assert_eq!(plan.new, vec![9, 7, 5]);
    assert_eq!(
        plan.flags,
        vec![(
            3,
            StoredFlags {
                seen: true,
                flagged: true,
                ..Default::default()
            }
        )]
    );
    assert_eq!(plan.gone, vec![1, 4]);
}

/// Un servidor que repite un UID en la misma respuesta no hace traer dos
/// veces el mismo mensaje, y la segunda copia no pisa a la primera.
#[test]
fn un_uid_repetido_en_el_servidor_cuenta_una_vez() {
    let stored: HashMap<u64, StoredFlags> = HashMap::from([(2, StoredFlags::default())]);
    let server = vec![
        uid_flags(5, &[]),
        uid_flags(5, &["\\Seen"]),
        uid_flags(2, &[]),
        uid_flags(2, &["\\Seen"]),
    ];
    let plan = plan_mailbox(&stored, &server);
    assert_eq!(plan.new, vec![5]);
    assert!(plan.flags.is_empty());
    assert!(plan.gone.is_empty());
}

#[test]
fn sin_nada_guardado_y_sin_nada_en_el_servidor_no_hay_nada_que_hacer() {
    assert_eq!(plan_mailbox(&HashMap::new(), &[]), MailboxPlan::default());
}

// ---------------------------------------------------------------------------
// Las filas que se guardan
// ---------------------------------------------------------------------------

#[test]
fn la_fila_de_un_mensaje_sale_de_sus_encabezados() {
    let headers = "From: =?UTF-8?Q?Ana_P=C3=A9rez?= <ana@x.com>\r\n\
                   To: yo@x.com, otro@x.com\r\n\
                   Cc: copia@x.com\r\n\
                   Reply-To: listas@x.com\r\n\
                   Subject: =?UTF-8?Q?Reuni=C3=B3n?=\r\n\
                   Date: Mon, 5 Oct 2026 10:00:00 +0000\r\n\
                   Message-ID:   <m1@x.com>  \r\n\
                   Content-Type: Multipart/Mixed; boundary=a\r\n\r\n";
    let row = message_row(4, &record(77, headers));

    assert_eq!(row.mailbox_id, 4);
    assert_eq!(row.uid, 77);
    assert_eq!(row.from_addr, "Ana Pérez <ana@x.com>");
    assert_eq!(row.to_addrs, "yo@x.com, otro@x.com");
    assert_eq!(row.cc_addrs, "copia@x.com");
    assert_eq!(row.bcc_addrs, "");
    assert_eq!(row.reply_to.as_deref(), Some("listas@x.com"));
    assert_eq!(row.subject, "Reunión");
    assert_eq!(row.message_id.as_deref(), Some("<m1@x.com>"));
    assert_eq!(row.date_ts, 1_791_194_400);
    assert_eq!(row.sort_key, row.date_ts);
    assert!(row.flags_seen);
    assert!(!row.flags_flagged);
    assert!(row.has_attachments);
    assert_eq!(row.size, 1234);
}

/// Una fecha que no se entiende no pone el mensaje arriba de todo: ordena por
/// UID, que crece con la llegada.
#[test]
fn sin_fecha_el_mensaje_ordena_por_su_uid() {
    for headers in [
        "From: ana@x.com\r\nDate: ayer a la tarde\r\n",
        "From: ana@x.com\r\n",
    ] {
        let row = message_row(1, &record(42, headers));
        assert_eq!(row.date_ts, 0);
        assert_eq!(row.sort_key, 42);
    }
}

#[test]
fn lo_que_falta_o_viene_vacio_no_se_guarda_como_texto_vacio() {
    let headers = "From: ana@x.com\r\nReply-To:   \r\nMessage-ID:  \r\n\
                   Content-Type: multipart/alternative; boundary=b\r\n";
    let row = message_row(1, &record(1, headers));
    // Una dirección pelada no se repite como nombre.
    assert_eq!(row.from_addr, "ana@x.com");
    assert_eq!(row.reply_to, None);
    assert_eq!(row.message_id, None);
    // `alternative` es texto y HTML del mismo mensaje, no un adjunto.
    assert!(!row.has_attachments);

    let row = message_row(1, &record(1, "Subject: sin remitente\r\n"));
    assert_eq!(row.from_addr, "");
    assert_eq!(row.reply_to, None);
    assert_eq!(row.message_id, None);
    assert!(!row.has_attachments);
}

/// El nombre se muestra separado de la dirección, y uno que se hace pasar por
/// otra dirección no se convierte en la dirección.
#[test]
fn el_remitente_se_guarda_como_nombre_y_direccion() {
    let row = message_row(1, &record(1, "From: \"Banco\" <fraude@x.com>\r\n"));
    assert_eq!(row.from_addr, "Banco <fraude@x.com>");
    let row = message_row(1, &record(1, "From: <solo@x.com>\r\n"));
    assert_eq!(row.from_addr, "solo@x.com");
}

const OPENED: &str = "From: ana@x.com\r\n\
Subject: Con todo\r\n\
Content-Type: multipart/mixed; boundary=a\r\n\
\r\n\
--a\r\n\
Content-Type: multipart/alternative; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hola, va el informe.\r\n\
--b\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Hola</p><script>robar()</script><img src=x onerror=alert(1)>\r\n\
--b--\r\n\
--a\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"informe.pdf\"\r\n\
\r\n\
datos\r\n\
--a--\r\n";

/// El HTML lo escribió un desconocido: se guarda **saneado**, para que
/// ninguna aplicación que lea del almacén tenga que acordarse de hacerlo.
#[test]
fn un_mensaje_abierto_se_guarda_con_el_html_saneado_y_sus_adjuntos() {
    let (body, attachments) = opened_rows(31, OPENED.as_bytes(), true);

    assert_eq!(body.message_id, 31);
    assert!(body.truncated);
    assert!(body.text_body.as_deref().unwrap().contains("va el informe"));
    let html = body.html_body.as_deref().unwrap();
    assert!(html.contains("Hola"));
    assert!(!html.to_ascii_lowercase().contains("<script"), "{html}");
    assert!(!html.contains("robar()"), "{html}");
    assert!(!html.to_ascii_lowercase().contains("onerror"), "{html}");

    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].message_id, 31);
    assert_eq!(attachments[0].part_number, "2");
    assert_eq!(attachments[0].name.as_deref(), Some("informe.pdf"));
    assert_eq!(attachments[0].content_type, "application/pdf");
}

#[test]
fn un_mensaje_de_texto_solo_no_tiene_html_ni_adjuntos() {
    let raw = b"From: ana@x.com\r\nContent-Type: text/plain\r\n\r\nSolo texto\r\n";
    let (body, attachments) = opened_rows(1, raw, false);
    assert!(!body.truncated);
    assert!(body.text_body.as_deref().unwrap().contains("Solo texto"));
    assert_eq!(body.html_body, None);
    assert!(attachments.is_empty());
}

// ---------------------------------------------------------------------------
// Vueltas enteras: servidor de mentira y base de verdad
// ---------------------------------------------------------------------------

struct Fixture {
    _temp: TempDir,
    keys: FakeKeys,
    manager: Arc<StoreManager<FakeKeys>>,
}

impl Fixture {
    async fn new(label: &str) -> Self {
        let temp = TempDir::new(label);
        let keys = FakeKeys::default();
        let manager = Arc::new(StoreManager::new(
            keys.clone(),
            Ok(Locations {
                stores: temp.0.join("data/stores"),
                settings: temp.0.join("config/stores.json"),
            }),
        ));
        manager
            .accounts_listed(
                AccountListing::Listed(vec![ListedAccount {
                    id: ACCOUNT.into(),
                    display_name: "Trabajo".into(),
                    capabilities: vec!["email".into()],
                    needs_reauth: false,
                }]),
                Instant::now(),
            )
            .await;
        assert!(manager
            .activate_area(EMAIL_AREA, ACCOUNT, Consent::Granted)
            .await
            .unwrap());
        Self {
            _temp: temp,
            keys,
            manager,
        }
    }

    /// Una vuelta contra un guion. Devuelve lo que informó y los comandos que
    /// recibió el servidor.
    async fn round(
        &self,
        script: Vec<(&'static str, Vec<&'static str>)>,
    ) -> (EmailReport, Vec<String>) {
        let (mut session, task) =
            with_server_caps("* OK listo", &["IMAP4REV1", "CONDSTORE"], script);
        let report = sync_session(&self.manager, ACCOUNT, &mut session)
            .await
            .unwrap_or_else(|e| panic!("la vuelta no terminó: {e:?}"));
        drop(session);
        (report, task.await.unwrap())
    }

    /// `(uid, asunto, leído, destacado, tiene cuerpo)` de una casilla, por UID.
    async fn messages(&self, mailbox: &str) -> Vec<(u64, String, bool, bool, bool)> {
        let mailbox = mailbox.to_string();
        self.manager
            .with_store(ACCOUNT, move |store| {
                let mut statement = store
                    .connection()
                    .prepare(
                        "SELECT m.uid, m.subject, m.flags_seen, m.flags_flagged,
                                b.message_id IS NOT NULL
                         FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
                         LEFT JOIN message_bodies b ON b.message_id = m.id
                         WHERE mb.name = ?1 ORDER BY m.uid",
                    )
                    .unwrap();
                let rows = statement
                    .query_map([mailbox], |row| {
                        Ok((
                            row.get::<_, i64>(0)? as u64,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                Ok(rows)
            })
            .await
            .unwrap()
    }

    async fn token_of(&self, mailbox: &str) -> Option<String> {
        let mailbox = mailbox.to_string();
        self.manager
            .with_store(ACCOUNT, move |store| {
                Ok(store
                    .mailboxes()?
                    .into_iter()
                    .find(|m| m.name == mailbox)
                    .and_then(|m| m.modseq))
            })
            .await
            .unwrap()
    }
}

const LIST: (&str, &[&str]) = (
    "LIST \"\" \"*\"",
    &[
        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"",
        "{tag} OK LIST completado",
    ],
);

fn list() -> (&'static str, Vec<&'static str>) {
    (LIST.0, LIST.1.to_vec())
}

fn examine(
    exists: u32,
    uidvalidity: u32,
    uid_next: u32,
    modseq: u64,
) -> (&'static str, Vec<&'static str>) {
    (
        "EXAMINE \"INBOX\" (CONDSTORE)",
        vec![
            leak(format!("* {exists} EXISTS")),
            leak(format!("* OK [UIDVALIDITY {uidvalidity}] válido")),
            leak(format!("* OK [UIDNEXT {uid_next}] el que sigue")),
            leak(format!("* OK [HIGHESTMODSEQ {modseq}] lo más alto")),
            "{tag} OK [READ-ONLY] EXAMINE completado",
        ],
    )
}

/// `FETCH a:b (UID FLAGS)` con `(seq, uid, banderas)`.
fn flags_window(range: &str, items: &[(u32, u32, &str)]) -> (&'static str, Vec<&'static str>) {
    let mut reply: Vec<&'static str> = items
        .iter()
        .map(|(seq, uid, flags)| leak(format!("* {seq} FETCH (UID {uid} FLAGS ({flags}))")))
        .collect();
    reply.push("{tag} OK FETCH completado");
    (leak(format!("FETCH {range} (UID FLAGS)")), reply)
}

/// `UID FETCH <uids> (... BODY.PEEK[HEADER.FIELDS ...])` con
/// `(uid, banderas, asunto, fecha)`.
fn headers_of(uids: &str, items: &[(u32, &str, &str, &str)]) -> (&'static str, Vec<&'static str>) {
    let mut reply = Vec::new();
    for (i, (uid, flags, subject, date)) in items.iter().enumerate() {
        let headers = format!(
            "From: Ana <ana@x.com>\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <m{uid}@x>"
        );
        // El servidor de mentira agrega el CRLF de cada línea: va en el literal.
        reply.push(leak(format!(
            "* {} FETCH (UID {uid} FLAGS ({flags}) RFC822.SIZE 500 BODY[HEADER.FIELDS (FROM SUBJECT)] {{{}}}",
            i + 1,
            headers.len() + 2
        )));
        reply.push(leak(headers));
        reply.push(")");
    }
    reply.push("{tag} OK FETCH completado");
    (
        leak(format!(
            "UID FETCH {uids} (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS"
        )),
        reply,
    )
}

fn body_of(uid: u32, text: &str) -> (&'static str, Vec<&'static str>) {
    let raw = format!("From: ana@x.com\r\nContent-Type: text/plain\r\n\r\n{text}");
    (
        leak(format!("UID FETCH {uid} (BODY.PEEK[]")),
        vec![
            leak(format!(
                "* 1 FETCH (UID {uid} BODY[]<0> {{{}}}",
                raw.len() + 2
            )),
            leak(raw),
            ")",
            "{tag} OK FETCH completado",
        ],
    )
}

const MONDAY: &str = "Mon, 5 Oct 2026 10:00:00 +0000";
const TUESDAY: &str = "Tue, 6 Oct 2026 10:00:00 +0000";

/// La primera vuelta: dos mensajes, uno leído, y sus cuerpos —el más nuevo
/// primero—.
async fn first_round(fixture: &Fixture) {
    let (report, received) = fixture
        .round(vec![
            list(),
            examine(2, 7, 3, 100),
            flags_window("1:2", &[(1, 1, "\\Seen"), (2, 2, "")]),
            headers_of(
                "2,1",
                &[(2, "", "Martes", TUESDAY), (1, "\\Seen", "Lunes", MONDAY)],
            ),
            body_of(2, "cuerpo del martes"),
            body_of(1, "cuerpo del lunes"),
        ])
        .await;
    assert_eq!(received.len(), 6, "{received:#?}");
    assert_eq!(
        report,
        EmailReport {
            mailboxes: 1,
            fetched: 2,
            bodies: 2,
            ..Default::default()
        }
    );
    assert_eq!(
        fixture.messages("INBOX").await,
        vec![
            (1, "Lunes".into(), true, false, true),
            (2, "Martes".into(), false, false, true),
        ]
    );
    assert_eq!(
        fixture.token_of("INBOX").await.as_deref(),
        Some("v1 7 100 3 2")
    );
}

#[tokio::test]
async fn la_primera_vuelta_trae_encabezados_y_cuerpos_de_la_bandeja_de_entrada() {
    let fixture = Fixture::new("correo-primera").await;
    first_round(&fixture).await;
}

/// **Lo que hace barata la sincronización**: con el mismo `HIGHESTMODSEQ`,
/// después de abrir la casilla no se pide nada más.
#[tokio::test]
async fn con_el_mismo_highestmodseq_la_segunda_vuelta_no_pide_nada() {
    let fixture = Fixture::new("correo-igual").await;
    first_round(&fixture).await;

    let (report, received) = fixture.round(vec![list(), examine(2, 7, 3, 100)]).await;

    assert_eq!(received.len(), 2, "pidió algo más: {received:#?}");
    assert_eq!(
        report,
        EmailReport {
            mailboxes: 1,
            unchanged: 1,
            ..Default::default()
        }
    );
    assert_eq!(fixture.messages("INBOX").await.len(), 2);
}

/// Un mensaje que se borró en el servidor se borra de la base, y uno que se
/// marcó en otro cliente cambia sus banderas sin volver a pedir encabezados.
#[tokio::test]
async fn un_uid_que_ya_no_esta_se_borra_y_las_banderas_se_actualizan() {
    let fixture = Fixture::new("correo-borrado").await;
    first_round(&fixture).await;

    let (report, received) = fixture
        .round(vec![
            list(),
            examine(1, 7, 3, 101),
            flags_window("1:1", &[(1, 2, "\\Seen \\Flagged")]),
        ])
        .await;

    assert_eq!(received.len(), 3, "{received:#?}");
    assert_eq!(
        report,
        EmailReport {
            mailboxes: 1,
            flag_updates: 1,
            removed: 1,
            ..Default::default()
        }
    );
    assert_eq!(
        fixture.messages("INBOX").await,
        vec![(2, "Martes".into(), true, true, true)]
    );
    assert_eq!(
        fixture.token_of("INBOX").await.as_deref(),
        Some("v1 7 101 3 1")
    );
}

/// Otro `UIDVALIDITY`: lo guardado se tira entero —los UID ya no apuntan a
/// esos mensajes— y la casilla se rehace en la misma vuelta.
#[tokio::test]
async fn otro_uidvalidity_vacia_la_casilla_y_la_rehace() {
    let fixture = Fixture::new("correo-uidvalidity").await;
    first_round(&fixture).await;

    let (report, received) = fixture
        .round(vec![
            list(),
            examine(1, 8, 2, 5),
            flags_window("1:1", &[(1, 1, "")]),
            headers_of("1", &[(1, "", "Otro mensaje", TUESDAY)]),
            body_of(1, "otro cuerpo"),
        ])
        .await;

    assert_eq!(received.len(), 5, "{received:#?}");
    assert_eq!(report.resets, 1);
    assert_eq!(report.fetched, 1);
    assert_eq!(report.bodies, 1);
    assert_eq!(
        fixture.messages("INBOX").await,
        vec![(1, "Otro mensaje".into(), false, false, true)],
        "quedó algo de antes del cambio"
    );
    assert_eq!(
        fixture.token_of("INBOX").await.as_deref(),
        Some("v1 8 5 2 1")
    );
}

/// Una casilla que se borró en el servidor se va de la base con sus
/// mensajes.
#[tokio::test]
async fn una_casilla_que_ya_no_esta_en_el_servidor_se_borra() {
    let fixture = Fixture::new("correo-casilla").await;
    first_round(&fixture).await;

    let (report, received) = fixture
        .round(vec![
            (
                "LIST \"\" \"*\"",
                vec![
                    "* LIST (\\HasNoChildren) \"/\" \"Otra\"",
                    "{tag} OK LIST completado",
                ],
            ),
            (
                "EXAMINE \"Otra\" (CONDSTORE)",
                vec!["* 0 EXISTS", "* OK [UIDVALIDITY 1]", "{tag} OK completado"],
            ),
        ])
        .await;

    assert_eq!(received.len(), 2, "{received:#?}");
    assert_eq!(report.removed, 2);
    assert!(fixture.messages("INBOX").await.is_empty());
    assert_eq!(fixture.token_of("INBOX").await, None);
    assert_eq!(
        fixture.token_of("Otra").await.as_deref(),
        Some("v1 1 - - 0")
    );
}

/// Una casilla que no abre —se borró recién, permisos del servidor— no corta
/// la vuelta de las demás.
#[tokio::test]
async fn una_casilla_que_no_abre_no_corta_la_vuelta() {
    let fixture = Fixture::new("correo-no-abre").await;
    let (report, received) = fixture
        .round(vec![
            (
                "LIST \"\" \"*\"",
                vec![
                    "* LIST (\\HasNoChildren) \"/\" \"INBOX\"",
                    "* LIST (\\HasNoChildren \\Sent) \"/\" \"Enviados\"",
                    "{tag} OK LIST completado",
                ],
            ),
            ("EXAMINE \"INBOX\" (CONDSTORE)", vec!["{tag} NO no existe"]),
            (
                "EXAMINE \"Enviados\" (CONDSTORE)",
                vec![
                    "* 0 EXISTS",
                    "* OK [UIDVALIDITY 3]",
                    "* OK [UIDNEXT 1]",
                    "{tag} OK completado",
                ],
            ),
        ])
        .await;
    assert_eq!(received.len(), 3, "{received:#?}");
    assert_eq!(report.mailboxes, 2);
    assert_eq!(
        fixture.token_of("INBOX").await,
        None,
        "se dio por al día sin abrirla"
    );
    assert_eq!(
        fixture.token_of("Enviados").await.as_deref(),
        Some("v1 3 - 1 0")
    );
}

/// Si la conexión se corta a mitad de la vuelta, la vuelta se corta: no se
/// siguen mandando comandos a una sesión que ya no sirve, ni se termina como
/// «al día» sin haber traído nada.
#[tokio::test]
async fn un_corte_a_mitad_de_la_vuelta_la_corta() {
    let fixture = Fixture::new("correo-corte").await;
    let (mut session, task) = with_server_caps(
        "* OK listo",
        &["IMAP4REV1", "CONDSTORE"],
        vec![
            (
                "LIST \"\" \"*\"",
                vec![
                    "* LIST (\\HasNoChildren) \"/\" \"INBOX\"",
                    "* LIST (\\HasNoChildren \\Sent) \"/\" \"Enviados\"",
                    "{tag} OK LIST completado",
                ],
            ),
            // El servidor recibe el EXAMINE y se va sin contestar.
            ("EXAMINE \"INBOX\" (CONDSTORE)", vec![]),
        ],
    );
    let result = sync_session(&fixture.manager, ACCOUNT, &mut session).await;
    drop(session);
    let received = task.await.unwrap();
    assert!(
        matches!(result, Err(RoundError::Imap(ImapError::Failed(_)))),
        "la vuelta siguió como si nada: {result:?}"
    );
    assert_eq!(received.len(), 2, "siguió mandando comandos: {received:#?}");
}

/// Con el llavero bloqueado la base no se abre: no se le pide nada al
/// servicio de cuentas ni al servidor, y el intento no cuenta como hecho.
#[tokio::test]
async fn con_el_llavero_bloqueado_no_se_conecta_a_nada() {
    let fixture = Fixture::new("correo-bloqueado").await;
    fixture.keys.state().locked = true;
    let notified = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&notified);
    let sync = EmailSync::new(
        Arc::clone(&fixture.manager),
        Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
    );

    assert_eq!(sync.sync_account(ACCOUNT).await, EmailOutcome::StoreClosed);
    assert!(!sync.attempt(ACCOUNT).await);
    assert_eq!(sync.interval(), EMAIL_INTERVAL);
}
