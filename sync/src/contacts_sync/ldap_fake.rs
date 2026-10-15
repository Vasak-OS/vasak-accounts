//! Un servidor LDAP de mentira en `127.0.0.1`, para las pruebas.
//!
//! Habla LDAPv3 de verdad sobre TCP —el cliente es `ldap3`, sin atajos— y
//! contesta lo mínimo que usa el backend: `bindRequest`, `searchRequest` y, para
//! el caso de StartTLS, el `extendedRequest` del arranque de TLS. No es un
//! directorio: no interpreta el filtro ni la base de búsqueda, sólo devuelve las
//! entradas que se le dieron. Es el espejo de [`crate::dav::fake`], pero para
//! LDAP en vez de HTTP.
//!
//! Las respuestas se arman con `lber` —la misma biblioteca de BER que usa
//! `ldap3` por dentro—, así que son bytes LDAP legítimos y el cliente los parsea
//! como los de un servidor real. Anota el **código de operación** de cada
//! mensaje que le llega **en claro**, para que una prueba pueda afirmar «nunca
//! llegó un bind sin cifrar» (es lo que sostiene la garantía de StartTLS).
//!
//! Sólo texto plano: se usa con `ldap://` y `allow_insecure`, o para comprobar
//! que un `ldap://` sin `allow_insecure` **no** manda el bind en claro porque
//! StartTLS falla antes. No implementa el handshake de TLS: un cliente que
//! insista con TLS se topa con bytes que no son TLS y la conexión se cae, que es
//! justo lo que la prueba quiere ver.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use lber::common::TagClass;
use lber::structure::{StructureTag, PL};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Códigos de operación del protocolo LDAP (RFC 4511), los que usa el fake.
pub const OP_BIND_REQUEST: u64 = 0;
pub const OP_UNBIND_REQUEST: u64 = 2;
pub const OP_SEARCH_REQUEST: u64 = 3;
pub const OP_EXTENDED_REQUEST: u64 = 23;

/// Una entrada de directorio tal como la va a devolver la búsqueda.
#[derive(Clone)]
pub struct FakeEntry {
    pub dn: String,
    /// Atributos, cada uno con su nombre y sus valores.
    pub attrs: Vec<(String, Vec<String>)>,
}

impl FakeEntry {
    /// Una persona con nombre, apellido y correo, lo mínimo de una entrada real.
    pub fn person(dn: &str, cn: &str, sn: &str, given: &str, mail: &str) -> Self {
        FakeEntry {
            dn: dn.into(),
            attrs: vec![
                ("cn".into(), vec![cn.into()]),
                ("sn".into(), vec![sn.into()]),
                ("givenName".into(), vec![given.into()]),
                ("mail".into(), vec![mail.into()]),
            ],
        }
    }
}

/// Cómo se porta el servidor falso en esta prueba.
///
/// El `Default` —bind que acepta (`0`), sin StartTLS y sin entradas— es el punto
/// de partida que cada prueba ajusta con `..Default::default()`.
#[derive(Clone, Default)]
pub struct FakeLdapConfig {
    /// El `resultCode` con que contesta el bind. `0` acepta; `49`
    /// (`invalidCredentials`) lo rechaza.
    pub bind_result: u8,
    /// Si `false`, el `extendedRequest` de StartTLS se contesta con un fallo
    /// (`unwillingToPerform`), como un servidor que no sabe StartTLS.
    pub starttls_supported: bool,
    /// Las entradas que devuelve cualquier búsqueda.
    pub entries: Vec<FakeEntry>,
}

/// El servidor falso, ya escuchando.
pub struct FakeLdap {
    addr: SocketAddr,
    ops: Arc<Mutex<Vec<u64>>>,
}

impl FakeLdap {
    /// Arranca el servidor y devuelve el handle. Escucha en un puerto al azar de
    /// `127.0.0.1` y atiende cada conexión en su propia tarea.
    pub async fn start(config: FakeLdapConfig) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ops = Arc::new(Mutex::new(Vec::new()));
        let ops_task = Arc::clone(&ops);

        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let config = config.clone();
                let ops = Arc::clone(&ops_task);
                tokio::spawn(serve(socket, config, ops));
            }
        });

        FakeLdap { addr, ops }
    }

    /// La URL `ldap://` con la que conectarse a este servidor.
    pub fn url(&self) -> String {
        format!("ldap://{}", self.addr)
    }

    /// Los códigos de operación que llegaron en claro, en orden.
    pub fn ops(&self) -> Vec<u64> {
        self.ops.lock().unwrap().clone()
    }

    /// Si en algún momento llegó un `bindRequest` sin cifrar.
    pub fn saw_cleartext_bind(&self) -> bool {
        self.ops().contains(&OP_BIND_REQUEST)
    }
}

async fn serve(
    mut socket: tokio::net::TcpStream,
    config: FakeLdapConfig,
    ops: Arc<Mutex<Vec<u64>>>,
) {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        // Un mensaje LDAP entero: un `SEQUENCE` BER. Si todavía no llegó
        // completo, `parse_tag` falla y se lee más.
        let (consumed, tag) = match lber::parse::parse_tag(&buffer) {
            Ok((rest, tag)) => (buffer.len() - rest.len(), tag),
            Err(_) => {
                if !read_more(&mut socket, &mut buffer).await {
                    return;
                }
                continue;
            }
        };
        buffer.drain(..consumed);

        // El `LDAPMessage` es `SEQUENCE { messageID, protocolOp }`.
        let inner = match tag.payload {
            PL::C(inner) => inner,
            PL::P(_) => return,
        };
        let message_id = match inner.first().map(|t| &t.payload) {
            Some(PL::P(bytes)) => bytes.clone(),
            _ => return,
        };
        let op = match inner.get(1) {
            Some(op) => op,
            None => return,
        };
        let op_id = op.id;
        ops.lock().unwrap().push(op_id);

        let reply = match op_id {
            OP_BIND_REQUEST => Some(message(message_id, app(1, ldap_result(config.bind_result)))),
            OP_EXTENDED_REQUEST => {
                let code = if config.starttls_supported { 0 } else { 53 };
                Some(message(message_id, app(24, ldap_result(code))))
            }
            OP_SEARCH_REQUEST => {
                let mut out = Vec::new();
                for entry in &config.entries {
                    out.extend(message(message_id.clone(), search_result_entry(entry)));
                }
                // `searchResultDone` con éxito cierra la búsqueda.
                out.extend(message(message_id, app(5, ldap_result(0))));
                Some(out)
            }
            // `unbindRequest` no lleva respuesta: el cliente se va.
            OP_UNBIND_REQUEST => return,
            _ => None,
        };

        if let Some(bytes) = reply {
            if socket.write_all(&bytes).await.is_err() {
                return;
            }
        }
    }
}

async fn read_more(socket: &mut tokio::net::TcpStream, buffer: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 4096];
    match socket.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buffer.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

// --- Armado de respuestas BER ------------------------------------------------

/// Un `LDAPMessage`: `SEQUENCE { messageID, protocolOp }`, ya en bytes.
fn message(message_id: Vec<u8>, op: StructureTag) -> Vec<u8> {
    let id = StructureTag {
        class: TagClass::Universal,
        id: 2, // INTEGER
        payload: PL::P(message_id),
    };
    let msg = seq(vec![id, op]);
    let mut buf = BytesMut::new();
    lber::write::encode_into(&mut buf, msg).unwrap();
    buf.to_vec()
}

/// Un `[APPLICATION n]` constructido: el envoltorio de cada operación.
fn app(id: u64, children: Vec<StructureTag>) -> StructureTag {
    StructureTag {
        class: TagClass::Application,
        id,
        payload: PL::C(children),
    }
}

fn seq(children: Vec<StructureTag>) -> StructureTag {
    StructureTag {
        class: TagClass::Universal,
        id: 16, // SEQUENCE
        payload: PL::C(children),
    }
}

fn set(children: Vec<StructureTag>) -> StructureTag {
    StructureTag {
        class: TagClass::Universal,
        id: 17, // SET
        payload: PL::C(children),
    }
}

fn octet(bytes: &[u8]) -> StructureTag {
    StructureTag {
        class: TagClass::Universal,
        id: 4, // OCTET STRING
        payload: PL::P(bytes.to_vec()),
    }
}

fn enumerated(code: u8) -> StructureTag {
    StructureTag {
        class: TagClass::Universal,
        id: 10, // ENUMERATED
        payload: PL::P(vec![code]),
    }
}

/// `LDAPResult`: el `resultCode` y los dos textos vacíos que lo acompañan.
fn ldap_result(code: u8) -> Vec<StructureTag> {
    vec![enumerated(code), octet(b""), octet(b"")]
}

/// `SearchResultEntry [APPLICATION 4]`: el DN y sus atributos.
fn search_result_entry(entry: &FakeEntry) -> StructureTag {
    let attrs: Vec<StructureTag> = entry
        .attrs
        .iter()
        .map(|(name, values)| {
            let vals: Vec<StructureTag> = values.iter().map(|v| octet(v.as_bytes())).collect();
            seq(vec![octet(name.as_bytes()), set(vals)])
        })
        .collect();
    app(4, vec![octet(entry.dn.as_bytes()), seq(attrs)])
}
