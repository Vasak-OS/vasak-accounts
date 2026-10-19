//! Las claves S/MIME en el llavero, por identidad (dirección de correo).
//!
//! La clave privada X.509 de una identidad vive en `vasak-keyring` bajo el
//! esquema protegido [`SCHEMA`] (`ar.net.vasak.os.SmimeKey`, de
//! Vasak-OS/vasak-keyring#54): sólo la toca este servicio, cifrada en reposo
//! como el resto, y a cualquier otro proceso el llavero le contesta
//! `SearchItems` vacío. Es el mismo trato que la clave del almacén —el esquema
//! es el único que cambia—, así que esto reusa el cliente de Secret Service de
//! [`super::key`] (sesión `plain`, `CreateItem replace=true`,
//! `SearchItems`/`GetSecret`).
//!
//! Por identidad se guardan dos ítems: la **clave privada** (DER PKCS#8, el
//! secreto) y la **cadena de certificados propia** que vino en el `.p12`
//! (pública, pero viaja con la clave y la necesita PR3 para embeber el cert
//! firmante). Los certificados de los **destinatarios** —para cifrar— son de
//! PR4 y van con el contacto, no acá.
//!
//! El `.p12` lo escribió otro programa: el parseo ([`parse_pkcs12`]) trata cada
//! byte como ajeno y nunca entra en pánico. Sólo PBES2 (el cifrado por omisión
//! de openssl 3 y de los exportadores modernos); un `.p12` con el PBE heredado
//! (RC2/3DES, `-legacy`) se rechaza con [`SmimeError::UnsupportedPkcs12`], que
//! no es un error roto sino «no disponible» (decisión #2) —ampliable a RC2/3DES
//! más adelante con los crates `rc2`/`des` y el KDF de PKCS#12—.
//!
//! Esta capa es la fundación (vasak-mail#78): firmar y verificar (PR3), cifrar
//! y descifrar (PR4) y la interfaz hacia la ventana (PR5) la consumen después.
#![allow(dead_code)]

use std::collections::HashMap;

use cms::content_info::ContentInfo;
use cms::encrypted_data::EncryptedData;
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Any, Decode, Encode, Reader, SliceReader};
use pkcs12::bag_type::BagType;
use pkcs12::cert_type::CertBag;
use pkcs12::pfx::Pfx;
use pkcs12::safe_bag::{SafeBag, SafeContents};
use pkcs8::EncryptedPrivateKeyInfo;
use zbus::zvariant::{OwnedObjectPath, Value};
use zeroize::Zeroizing;

use super::key::{KeyError, Secret, SecretServiceKeys};

/// El esquema protegido de las claves S/MIME. Tiene que coincidir con el que
/// `vasak-keyring` restringe a este ejecutable (Vasak-OS/vasak-keyring#54).
pub const SCHEMA: &str = "ar.net.vasak.os.SmimeKey";

const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
const IDENTITY_ATTRIBUTE: &str = "identity";
const TYPE_ATTRIBUTE: &str = "type";
const TYPE_PRIVATE_KEY: &str = "private-key";
const TYPE_CERTS: &str = "certs";

const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";

const ID_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_DATA;
const ID_ENCRYPTED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_ENCRYPTED_DATA;
/// `id-PBES2`, el único esquema de cifrado que soportamos en el `.p12`.
const ID_PBES2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13");
/// `x509Certificate` dentro de un `CertBag`.
const X509_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.22.1");

/// Lo que puede salir mal con una identidad S/MIME.
#[derive(Debug)]
pub enum SmimeError {
    /// El `.p12` no se pudo parsear: no es un PFX, le falta la clave o un cert,
    /// o una estructura interna está rota.
    MalformedPkcs12(String),
    /// El `.p12` usa un cifrado que no soportamos (RC2/3DES heredado). No está
    /// roto: es «no disponible» hasta que se reexporte sin `-legacy`.
    UnsupportedPkcs12,
    /// La contraseña no abre el `.p12` (o el archivo está corrupto).
    WrongPassword,
    /// El llavero falló al guardar o leer.
    Keyring(KeyError),
}

impl std::fmt::Display for SmimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmimeError::MalformedPkcs12(d) => write!(f, "el .p12 no se pudo leer: {d}"),
            SmimeError::UnsupportedPkcs12 => f.write_str(
                "formato de .p12 no soportado (cifrado heredado): reexportá el archivo sin -legacy",
            ),
            SmimeError::WrongPassword => f.write_str("la contraseña no abre el .p12"),
            SmimeError::Keyring(e) => write!(f, "el llavero falló: {e}"),
        }
    }
}

impl std::error::Error for SmimeError {}

impl From<KeyError> for SmimeError {
    fn from(e: KeyError) -> Self {
        SmimeError::Keyring(e)
    }
}

/// Lo que trae un `.p12`: la clave privada en PKCS#8 DER (se borra sola) y la
/// cadena de certificados en DER, en el orden en que venían.
pub struct ImportedIdentity {
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    pub certs: Vec<Vec<u8>>,
}

impl std::fmt::Debug for ImportedIdentity {
    /// Nunca imprime la clave privada.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedIdentity")
            .field("private_key_pkcs8", &"<oculto>")
            .field("certs", &self.certs.len())
            .finish()
    }
}

// ── Parseo del .p12 ───────────────────────────────────────────────────

/// Parsea un `.p12`/PFX cifrado con PBES2 y devuelve la clave privada (PKCS#8
/// DER) y su cadena de certificados.
///
/// Sólo PBES2: un `.p12` con el PBE heredado da [`SmimeError::UnsupportedPkcs12`]
/// y una contraseña equivocada [`SmimeError::WrongPassword`]. Todo lo demás que
/// no cuadre es [`SmimeError::MalformedPkcs12`]; nunca entra en pánico.
pub fn parse_pkcs12(der: &[u8], password: &[u8]) -> Result<ImportedIdentity, SmimeError> {
    let pfx = Pfx::from_der(der).map_err(|e| SmimeError::MalformedPkcs12(format!("PFX: {e}")))?;

    if pfx.auth_safe.content_type != ID_DATA {
        return Err(SmimeError::MalformedPkcs12("authSafe no es id-data".into()));
    }
    let authsafe_der = content_octets(&pfx.auth_safe)?;
    let safes = Vec::<ContentInfo>::from_der(&authsafe_der)
        .map_err(|e| SmimeError::MalformedPkcs12(format!("AuthenticatedSafe: {e}")))?;

    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut private_key: Option<Zeroizing<Vec<u8>>> = None;

    for safe in &safes {
        let safe_contents_der: Vec<u8> = if safe.content_type == ID_DATA {
            content_octets(safe)?
        } else if safe.content_type == ID_ENCRYPTED_DATA {
            decrypt_encrypted_data(safe, password)?
        } else {
            continue;
        };

        let bags = SafeContents::from_der(&safe_contents_der)
            .map_err(|e| SmimeError::MalformedPkcs12(format!("SafeContents: {e}")))?;
        for bag in &bags {
            collect_bag(bag, password, &mut private_key, &mut certs)?;
        }
    }

    let private_key_pkcs8 =
        private_key.ok_or_else(|| SmimeError::MalformedPkcs12("el .p12 no trae clave".into()))?;
    if certs.is_empty() {
        return Err(SmimeError::MalformedPkcs12(
            "el .p12 no trae certificados".into(),
        ));
    }
    Ok(ImportedIdentity {
        private_key_pkcs8,
        certs,
    })
}

/// El valor del OCTET STRING que envuelve el contenido de un `ContentInfo`
/// `id-data`.
fn content_octets(ci: &ContentInfo) -> Result<Vec<u8>, SmimeError> {
    let der = ci
        .content
        .to_der()
        .map_err(|e| SmimeError::MalformedPkcs12(e.to_string()))?;
    let os = OctetString::from_der(&der)
        .map_err(|e| SmimeError::MalformedPkcs12(format!("id-data no es OCTET STRING: {e}")))?;
    Ok(os.as_bytes().to_vec())
}

/// Descifra un `ContentInfo` `id-encryptedData` (los SafeContents cifrados).
fn decrypt_encrypted_data(safe: &ContentInfo, password: &[u8]) -> Result<Vec<u8>, SmimeError> {
    let der = safe
        .content
        .to_der()
        .map_err(|e| SmimeError::MalformedPkcs12(e.to_string()))?;
    let ed = EncryptedData::from_der(&der)
        .map_err(|e| SmimeError::MalformedPkcs12(format!("EncryptedData: {e}")))?;
    let eci = ed.enc_content_info;
    let ciphertext = eci
        .encrypted_content
        .ok_or_else(|| SmimeError::MalformedPkcs12("EncryptedData sin contenido".into()))?;
    decrypt_pbes2(&eci.content_enc_alg, ciphertext.as_bytes(), password)
}

fn collect_bag(
    bag: &SafeBag,
    password: &[u8],
    private_key: &mut Option<Zeroizing<Vec<u8>>>,
    certs: &mut Vec<Vec<u8>>,
) -> Result<(), SmimeError> {
    // `bag_value` guarda el `[0] EXPLICIT` entero; adentro está el valor real.
    let wrapper = Any::from_der(&bag.bag_value)
        .map_err(|e| SmimeError::MalformedPkcs12(format!("bag: {e}")))?;
    let inner = wrapper.value();
    match BagType::try_from(bag.bag_id) {
        Ok(BagType::Pkcs8) => {
            // Shrouded key bag: EncryptedPrivateKeyInfo → descifrar a PKCS#8.
            // `encryption_algorithm` ya viene parseado como `EncryptionScheme`
            // (PBES1/PBES2); el PBE heredado de PKCS#12 ni siquiera parsea acá y
            // cae en `MalformedPkcs12`, pero en la práctica el `.p12` legacy se
            // detecta antes, en el certbag (`decrypt_pbes2`). Igual exigimos
            // PBES2 explícito para no intentar PBES1.
            let epki = EncryptedPrivateKeyInfo::from_der(inner)
                .map_err(|e| SmimeError::MalformedPkcs12(format!("keybag: {e}")))?;
            if epki.encryption_algorithm.oid() != ID_PBES2 {
                return Err(SmimeError::UnsupportedPkcs12);
            }
            let doc = epki
                .decrypt(password)
                .map_err(|_| SmimeError::WrongPassword)?;
            *private_key = Some(Zeroizing::new(doc.as_bytes().to_vec()));
        }
        Ok(BagType::Key) => {
            // Key bag en claro: ya es PKCS#8.
            *private_key = Some(Zeroizing::new(inner.to_vec()));
        }
        Ok(BagType::Cert) => {
            let cert_bag = CertBag::from_der(inner)
                .map_err(|e| SmimeError::MalformedPkcs12(format!("certbag: {e}")))?;
            if cert_bag.cert_id == X509_CERTIFICATE {
                certs.push(cert_bag.cert_value.as_bytes().to_vec());
            }
        }
        _ => {}
    }
    Ok(())
}

/// Descifra con PBES2. Un esquema que `pkcs5` no reconoce (el PBE heredado de
/// PKCS#12) es [`SmimeError::UnsupportedPkcs12`]; que lo reconozca y falle el
/// descifrado es [`SmimeError::WrongPassword`].
fn decrypt_pbes2(
    alg: &spki::AlgorithmIdentifierOwned,
    ciphertext: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, SmimeError> {
    if alg.oid != ID_PBES2 {
        return Err(SmimeError::UnsupportedPkcs12);
    }
    let alg_der = alg
        .to_der()
        .map_err(|e| SmimeError::MalformedPkcs12(e.to_string()))?;
    let alg_ref = spki::AlgorithmIdentifierRef::from_der(&alg_der)
        .map_err(|e| SmimeError::MalformedPkcs12(e.to_string()))?;
    let scheme =
        pkcs5::EncryptionScheme::try_from(alg_ref).map_err(|_| SmimeError::UnsupportedPkcs12)?;
    scheme
        .decrypt(password, ciphertext)
        .map(|v| v.to_vec())
        .map_err(|_| SmimeError::WrongPassword)
}

// ── Guardado y lectura en el llavero ──────────────────────────────────

/// Importa un `.p12` a la identidad `identity`: lo parsea y guarda la clave
/// privada y la cadena de certificados en el llavero.
pub async fn import_pkcs12(
    keys: &SecretServiceKeys,
    identity: &str,
    p12_der: &[u8],
    password: &[u8],
) -> Result<(), SmimeError> {
    let imported = parse_pkcs12(p12_der, password)?;
    keys.store_smime_identity(identity, &imported).await?;
    Ok(())
}

/// La cadena de certificados en DER, concatenada. Cada cert es una SEQUENCE
/// autodelimitada, así que la concatenación se vuelve a separar leyendo TLV a
/// TLV ([`split_certs`]) sin inventar ningún formato propio.
fn join_certs(certs: &[Vec<u8>]) -> Vec<u8> {
    certs.concat()
}

/// Separa la cadena concatenada por [`join_certs`] en los certs individuales.
fn split_certs(blob: &[u8]) -> Result<Vec<Vec<u8>>, KeyError> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    let mut reader = SliceReader::new(blob)
        .map_err(|e| KeyError::Failed(format!("cadena de certs ilegible: {e}")))?;
    let mut out = Vec::new();
    while !reader.is_finished() {
        let tlv = reader
            .tlv_bytes()
            .map_err(|e| KeyError::Failed(format!("cert de la cadena ilegible: {e}")))?;
        out.push(tlv.to_vec());
    }
    Ok(out)
}

fn smime_attributes<'a>(identity: &'a str, type_: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        (SCHEMA_ATTRIBUTE, SCHEMA),
        (IDENTITY_ATTRIBUTE, identity),
        (TYPE_ATTRIBUTE, type_),
    ])
}

impl SecretServiceKeys {
    /// Guarda la clave privada y la cadena de certificados de una identidad,
    /// reemplazando lo que hubiera.
    pub(crate) async fn store_smime_identity(
        &self,
        identity: &str,
        imported: &ImportedIdentity,
    ) -> Result<(), KeyError> {
        self.store_smime_item(
            identity,
            TYPE_PRIVATE_KEY,
            &imported.private_key_pkcs8,
            "application/pkcs8",
        )
        .await?;
        let certs_blob = join_certs(&imported.certs);
        self.store_smime_item(identity, TYPE_CERTS, &certs_blob, "application/pkix-cert")
            .await
    }

    /// La clave privada (PKCS#8 DER) de una identidad, si hay una.
    pub(crate) async fn find_smime_private_key(
        &self,
        identity: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self
            .find_smime_item(identity, TYPE_PRIVATE_KEY)
            .await?
            .map(Zeroizing::new))
    }

    /// La cadena de certificados propia de una identidad, si hay una.
    pub(crate) async fn find_smime_certs(
        &self,
        identity: &str,
    ) -> Result<Option<Vec<Vec<u8>>>, KeyError> {
        match self.find_smime_item(identity, TYPE_CERTS).await? {
            Some(blob) => Ok(Some(split_certs(&blob)?)),
            None => Ok(None),
        }
    }

    /// Borra la clave y los certificados de una identidad. Que no hubiera no es
    /// un error; la colección bloqueada sí ([`KeyError::Locked`]).
    pub(crate) async fn delete_smime_identity(&self, identity: &str) -> Result<(), KeyError> {
        for type_ in [TYPE_PRIVATE_KEY, TYPE_CERTS] {
            let attributes = smime_attributes(identity, type_);
            for item in self.search(&attributes).await? {
                let prompt: OwnedObjectPath =
                    self.call(item.as_str(), ITEM_IFACE, "Delete", &()).await?;
                if prompt.as_str() != "/" {
                    return Err(KeyError::PromptRequired);
                }
            }
        }
        Ok(())
    }

    async fn store_smime_item(
        &self,
        identity: &str,
        type_: &str,
        value: &[u8],
        content_type: &str,
    ) -> Result<(), KeyError> {
        let collection = self.default_collection().await?;
        let label = format!("Clave S/MIME de VasakOS ({identity})");
        let attributes = smime_attributes(identity, type_);
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes),
        );

        let session = self.open_session().await?;
        let secret = Secret {
            session: session.clone(),
            parameters: Vec::new(),
            value: value.to_vec(),
            content_type: content_type.into(),
        };
        // `replace = true`: reimportar una identidad reemplaza su clave en vez
        // de dejar dos que después no se sabe cuál es.
        let reply: Result<(OwnedObjectPath, OwnedObjectPath), KeyError> = self
            .call(
                collection.as_str(),
                COLLECTION_IFACE,
                "CreateItem",
                &(properties, &secret, true),
            )
            .await;
        drop(secret);
        self.close_session(&session).await;

        let (_item, prompt) = reply?;
        if prompt.as_str() != "/" {
            return Err(KeyError::PromptRequired);
        }
        Ok(())
    }

    async fn find_smime_item(
        &self,
        identity: &str,
        type_: &str,
    ) -> Result<Option<Vec<u8>>, KeyError> {
        let attributes = smime_attributes(identity, type_);
        let items = self.search(&attributes).await?;
        let Some(item) = items.first() else {
            return Ok(None);
        };
        let session = self.open_session().await?;
        let reply: Result<(Secret,), KeyError> = self
            .call(item.as_str(), ITEM_IFACE, "GetSecret", &(&session,))
            .await;
        self.close_session(&session).await;
        let (mut secret,) = reply?;
        Ok(Some(std::mem::take(&mut secret.value)))
    }
}
