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
use hmac::{Hmac, Mac};
use pkcs12::bag_type::BagType;
use pkcs12::cert_type::CertBag;
use pkcs12::kdf::{derive_key_utf8, Pkcs12KeyType};
use pkcs12::mac_data::MacData;
use pkcs12::pfx::Pfx;
use pkcs12::safe_bag::{SafeBag, SafeContents};
use pkcs8::EncryptedPrivateKeyInfo;
use sha2::{Digest, Sha256, Sha384, Sha512};
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

const ID_SHA_256: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_256;
const ID_SHA_384: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_384;
const ID_SHA_512: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_512;

/// Cotas de entrada contra un `.p12` hostil (DoS). Un `.p12` real pesa unos
/// pocos KB y usa 2048 rondas; estos topes son holgados para lo legítimo y
/// cierran el OOM/CPU de un archivo armado a propósito. Fuera de rango:
/// [`SmimeError::UnsupportedPkcs12`].
const MAX_PKCS12_BYTES: usize = 8 * 1024 * 1024;
const MAX_PBKDF2_ITERS: u32 = 10_000_000;
const MAX_MAC_ITERS: i32 = 10_000_000;
/// `N` de scrypt (memoria ≈ 128 · r · N): 2^20 con r=8 son ~1 GiB, el techo.
const MAX_SCRYPT_COST: u64 = 1 << 20;
const MAX_SCRYPT_BLOCK: u16 = 64;
const MAX_SCRYPT_PARALLEL: u16 = 16;

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
    // Cota dura antes de parsear: un `.p12` legítimo pesa unos pocos KB.
    if der.len() > MAX_PKCS12_BYTES {
        return Err(SmimeError::UnsupportedPkcs12);
    }

    let pfx = Pfx::from_der(der).map_err(|e| SmimeError::MalformedPkcs12(format!("PFX: {e}")))?;

    if pfx.auth_safe.content_type != ID_DATA {
        return Err(SmimeError::MalformedPkcs12("authSafe no es id-data".into()));
    }
    let authsafe_der = content_octets(&pfx.auth_safe)?;

    // El MAC se verifica ANTES de confiar en el contenido: autentica el archivo
    // con la contraseña, así una contraseña equivocada da `WrongPassword`
    // determinista y un `.p12` corrompido o manipulado falla en vez de importar
    // una identidad distinta en silencio (medido: sin esto, un byte cambiado
    // daba otra clave o cert en ~1960 de 2670 posiciones). Un `.p12` sin MAC se
    // rechaza: no se puede verificar su integridad.
    let mac = pfx.mac_data.as_ref().ok_or_else(|| {
        SmimeError::MalformedPkcs12(
            "el .p12 no trae MAC; no se puede verificar su integridad".into(),
        )
    })?;
    verify_mac(mac, &authsafe_der, password)?;

    let safes = Vec::<ContentInfo>::from_der(&authsafe_der)
        .map_err(|e| SmimeError::MalformedPkcs12(format!("AuthenticatedSafe: {e}")))?;

    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut private_key: Option<Zeroizing<Vec<u8>>> = None;

    for safe in &safes {
        // El contenido descifrado —que puede traer la clave en claro— se borra
        // al soltarlo.
        let safe_contents_der: Zeroizing<Vec<u8>> = if safe.content_type == ID_DATA {
            Zeroizing::new(content_octets(safe)?)
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
fn decrypt_encrypted_data(
    safe: &ContentInfo,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SmimeError> {
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

/// El OID del esquema de cifrado de un keybag (`EncryptedPrivateKeyInfo`), leído
/// del `AlgorithmIdentifier` crudo sin exigir que `pkcs5` lo entienda. Así un PBE
/// heredado se clasifica como no soportado en vez de ilegible.
fn keybag_pbe_oid(epki_der: &[u8]) -> Result<ObjectIdentifier, SmimeError> {
    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, ... }
    let seq =
        Any::from_der(epki_der).map_err(|e| SmimeError::MalformedPkcs12(format!("keybag: {e}")))?;
    let mut reader = SliceReader::new(seq.value())
        .map_err(|e| SmimeError::MalformedPkcs12(format!("keybag: {e}")))?;
    let alg: spki::AlgorithmIdentifierRef = reader
        .decode()
        .map_err(|e| SmimeError::MalformedPkcs12(format!("keybag alg: {e}")))?;
    Ok(alg.oid)
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
            // El OID del PBE se mira **antes** de `from_der`: ése parsea
            // `encryption_algorithm` como `EncryptionScheme`, que no entiende el
            // PBE heredado de PKCS#12 (3DES/RC2) y daría `MalformedPkcs12`
            // («no se pudo leer») en vez del hint «reexportá sin -legacy». Pasa
            // con los `.p12` que ponen el safe de la clave primero y en claro
            // (CryptoAPI de Windows, keytool de Java). Si no es PBES2, cortamos
            // con el mensaje correcto; si lo es, seguimos.
            if keybag_pbe_oid(inner)? != ID_PBES2 {
                return Err(SmimeError::UnsupportedPkcs12);
            }
            let epki = EncryptedPrivateKeyInfo::from_der(inner)
                .map_err(|e| SmimeError::MalformedPkcs12(format!("keybag: {e}")))?;
            check_kdf_bounds(&epki.encryption_algorithm)?;
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
) -> Result<Zeroizing<Vec<u8>>, SmimeError> {
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
    check_kdf_bounds(&scheme)?;
    scheme
        .decrypt(password, ciphertext)
        .map(|v| Zeroizing::new(v.to_vec()))
        .map_err(|_| SmimeError::WrongPassword)
}

/// Rechaza parámetros de KDF fuera de rango sano **antes** de computarlos, para
/// que un `.p12` hostil no fuerce un OOM (scrypt con `N` enorme) ni una quema de
/// CPU (iteraciones gigantes). Fuera de rango: [`SmimeError::UnsupportedPkcs12`].
fn check_kdf_bounds(scheme: &pkcs5::EncryptionScheme) -> Result<(), SmimeError> {
    if let pkcs5::EncryptionScheme::Pbes2(params) = scheme {
        if let Some(pbkdf2) = params.kdf.pbkdf2() {
            if pbkdf2.iteration_count > MAX_PBKDF2_ITERS {
                return Err(SmimeError::UnsupportedPkcs12);
            }
        } else if let Some(scrypt) = params.kdf.scrypt() {
            if scrypt.cost_parameter > MAX_SCRYPT_COST
                || scrypt.block_size > MAX_SCRYPT_BLOCK
                || scrypt.parallelization > MAX_SCRYPT_PARALLEL
            {
                return Err(SmimeError::UnsupportedPkcs12);
            }
        }
    }
    Ok(())
}

/// Verifica el MAC del PFX (HMAC con el KDF de PKCS#12) sobre el contenido del
/// authSafe. Es lo que autentica el archivo con la contraseña: sin esto, un byte
/// cambiado dentro del cifrado se aceptaba con otra identidad.
///
/// La contraseña del MAC va como BMPString (lo hace `derive_key_utf8`), que es
/// otra codificación que la de PBES2 (bytes crudos); por eso se pasa como `&str`.
/// Sólo SHA-256/384/512 (sha2); un MAC con SHA-1 es de un `.p12` heredado y se
/// rechaza como no soportado, igual que su cifrado.
fn verify_mac(mac: &MacData, authsafe: &[u8], password: &[u8]) -> Result<(), SmimeError> {
    let password = std::str::from_utf8(password).map_err(|_| SmimeError::WrongPassword)?;
    let rounds = mac.iterations;
    if rounds < 1 || rounds > MAX_MAC_ITERS {
        return Err(SmimeError::UnsupportedPkcs12);
    }
    let salt = mac.mac_salt.as_bytes();
    let expected = mac.mac.digest.as_bytes();

    macro_rules! verify_with {
        ($hash:ty) => {{
            let len = <$hash as Digest>::output_size();
            let key = derive_key_utf8::<$hash>(password, salt, Pkcs12KeyType::Mac, rounds, len)
                .map_err(|e| SmimeError::MalformedPkcs12(format!("KDF del MAC: {e}")))?;
            let mut hmac = Hmac::<$hash>::new_from_slice(&key)
                .map_err(|e| SmimeError::MalformedPkcs12(format!("clave del MAC: {e}")))?;
            hmac.update(authsafe);
            // `verify_slice` compara en tiempo constante.
            hmac.verify_slice(expected)
                .map_err(|_| SmimeError::WrongPassword)
        }};
    }

    match mac.mac.algorithm.oid {
        ID_SHA_256 => verify_with!(Sha256),
        ID_SHA_384 => verify_with!(Sha384),
        ID_SHA_512 => verify_with!(Sha512),
        _ => Err(SmimeError::UnsupportedPkcs12),
    }
}

// ── Guardado y lectura en el llavero ──────────────────────────────────

/// Importa un `.p12` a la identidad `identity`: lo parsea y guarda la clave
/// privada y la cadena de certificados en el llavero.
///
/// El parseo hace KDF (PBKDF2/HMAC del MAC), que es trabajo de CPU, así que corre
/// en `spawn_blocking` para no frenar un worker de Tokio.
pub async fn import_pkcs12(
    keys: &SecretServiceKeys,
    identity: &str,
    p12_der: &[u8],
    password: &[u8],
) -> Result<(), SmimeError> {
    let der = p12_der.to_vec();
    let password = Zeroizing::new(password.to_vec());
    let imported = tokio::task::spawn_blocking(move || parse_pkcs12(&der, &password))
        .await
        .map_err(|e| SmimeError::MalformedPkcs12(format!("el parseo del .p12 se cortó: {e}")))??;
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

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::super::key::tests::{fake_keyring, lock_and_announce};
    use super::super::key::KeySource;
    use super::*;

    const PBES2_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/rsa-pbes2.p12");
    const LEGACY_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/rsa-legacy.p12");
    const SOLO_CERTS_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/solo-certs.p12");
    const SOLO_CLAVE_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/solo-clave.p12");
    const CERT_PEM: &str = include_str!("../../tests/fixtures/smime/cert.pem");
    const PASSWORD: &[u8] = b"vasak-test";
    /// `rsaEncryption`, el algoritmo de la clave de los fixtures.
    const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    /// Un «certificado» mínimo pero con forma de SEQUENCE DER, para las
    /// pruebas del llavero que sólo necesitan bytes distinguibles.
    const FAKE_CERT: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];

    fn cert_der() -> Vec<u8> {
        let b64: String = CERT_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("cert.pem es base64")
    }

    fn identity(key: &[u8], certs: Vec<Vec<u8>>) -> ImportedIdentity {
        ImportedIdentity {
            private_key_pkcs8: Zeroizing::new(key.to_vec()),
            certs,
        }
    }

    // ── parse_pkcs12 ──────────────────────────────────────────────────

    #[test]
    fn un_p12_pbes2_con_su_contrasena_da_la_clave_pkcs8_y_el_certificado() {
        let imported = parse_pkcs12(PBES2_P12, PASSWORD).expect("tiene que parsear");

        let info = pkcs8::PrivateKeyInfo::try_from(imported.private_key_pkcs8.as_slice())
            .expect("la clave es un PKCS#8 válido");
        assert_eq!(info.algorithm.oid.to_string(), RSA_ENCRYPTION);

        assert_eq!(imported.certs.len(), 1);
        assert_eq!(
            imported.certs[0],
            cert_der(),
            "el cert devuelto es el de cert.pem"
        );
    }

    #[test]
    fn una_contrasena_equivocada_no_abre_el_p12() {
        let err = parse_pkcs12(PBES2_P12, b"otra").unwrap_err();
        assert!(matches!(err, SmimeError::WrongPassword), "dio {err:?}");
        let err = parse_pkcs12(PBES2_P12, b"").unwrap_err();
        assert!(matches!(err, SmimeError::WrongPassword), "dio {err:?}");
    }

    /// Sin verificar el MAC del PFX, una contraseña equivocada que por azar
    /// deja un relleno CBC válido (1 de cada ~256) descifra basura. Lo que no
    /// puede pasar nunca es que esa basura se tome por una identidad: el
    /// resultado es siempre un error, aunque no siempre `WrongPassword`.
    #[test]
    fn una_contrasena_equivocada_nunca_devuelve_una_identidad() {
        for i in 0..300 {
            let pw = format!("mal-{i}");
            let r = parse_pkcs12(PBES2_P12, pw.as_bytes());
            assert!(
                matches!(
                    r,
                    Err(SmimeError::WrongPassword) | Err(SmimeError::MalformedPkcs12(_))
                ),
                "con {pw:?} dio {r:?}"
            );
        }
    }

    #[test]
    fn un_p12_con_cifrado_heredado_no_esta_disponible_y_dice_como_arreglarlo() {
        let err = parse_pkcs12(LEGACY_P12, PASSWORD).unwrap_err();
        assert!(matches!(err, SmimeError::UnsupportedPkcs12), "dio {err:?}");
        assert!(err.to_string().contains("sin -legacy"), "{err}");
        // Con otra contraseña también: se detecta por el algoritmo, no por la
        // clave, así que no se lo confunde con «contraseña equivocada».
        let err = parse_pkcs12(LEGACY_P12, b"otra").unwrap_err();
        assert!(matches!(err, SmimeError::UnsupportedPkcs12), "dio {err:?}");
    }

    /// Un `.p12` bien formado pero sin la clave, o sin certificados, no sirve
    /// para firmar: es un error y no una identidad a medias.
    #[test]
    fn un_p12_sin_clave_o_sin_certificados_es_malformado() {
        let sin_clave = parse_pkcs12(SOLO_CERTS_P12, PASSWORD).unwrap_err();
        assert!(
            matches!(&sin_clave, SmimeError::MalformedPkcs12(d) if d.contains("clave")),
            "dio {sin_clave:?}"
        );
        let sin_certs = parse_pkcs12(SOLO_CLAVE_P12, PASSWORD).unwrap_err();
        assert!(
            matches!(&sin_certs, SmimeError::MalformedPkcs12(d) if d.contains("certificados")),
            "dio {sin_certs:?}"
        );
    }

    #[test]
    fn lo_que_no_es_un_p12_es_malformado() {
        let casos: Vec<(&str, Vec<u8>)> = vec![
            ("vacío", Vec::new()),
            ("un byte", vec![0x30]),
            ("texto", b"esto no es un PKCS#12".to_vec()),
            ("ceros", vec![0u8; 64]),
            ("el certificado PEM", CERT_PEM.as_bytes().to_vec()),
            ("el certificado DER", cert_der()),
            ("SEQUENCE vacía", vec![0x30, 0x00]),
            (
                "longitud mentida",
                vec![0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02],
            ),
        ];
        for (nombre, bytes) in casos {
            let r = parse_pkcs12(&bytes, PASSWORD);
            assert!(
                matches!(r, Err(SmimeError::MalformedPkcs12(_))),
                "{nombre}: dio {r:?}"
            );
        }
    }

    /// El `.p12` lo escribió otro programa: truncado en cualquier punto da
    /// error, y con un byte cambiado no entra en pánico.
    #[test]
    fn un_p12_truncado_da_error_y_uno_corrompido_no_entra_en_panico() {
        for len in 0..PBES2_P12.len() {
            let r = parse_pkcs12(&PBES2_P12[..len], PASSWORD);
            assert!(r.is_err(), "truncado a {len} bytes devolvió Ok");
        }
        for i in (0..PBES2_P12.len()).step_by(11) {
            let mut roto = PBES2_P12.to_vec();
            roto[i] ^= 0xff;
            let _ = parse_pkcs12(&roto, PASSWORD);
        }
    }

    /// El MAC del PFX cierra el hueco: un `.p12` con un byte cambiado no se puede
    /// aceptar con una identidad **distinta**. Antes de verificar el MAC, medido,
    /// ~1960 de las 2670 posiciones daban `Ok` con otra identidad (1197 con otra
    /// clave privada); ahora `verify_mac` las rechaza antes de confiar en el
    /// contenido. Si para algún byte el parseo devuelve `Ok`, tiene que ser la
    /// misma identidad (p. ej. un byte fuera de lo que el MAC cubre y que no
    /// cambia nada).
    #[test]
    fn un_p12_con_un_byte_cambiado_no_se_acepta_con_otra_identidad() {
        let original = parse_pkcs12(PBES2_P12, PASSWORD).unwrap();
        for i in 0..PBES2_P12.len() {
            let mut roto = PBES2_P12.to_vec();
            roto[i] ^= 0xff;
            if let Ok(r) = parse_pkcs12(&roto, PASSWORD) {
                assert!(
                    r.private_key_pkcs8.as_slice() == original.private_key_pkcs8.as_slice()
                        && r.certs == original.certs,
                    "byte {i}: devolvió Ok con otra identidad"
                );
            }
        }
    }

    #[test]
    fn la_identidad_importada_no_imprime_la_clave() {
        let imported = parse_pkcs12(PBES2_P12, PASSWORD).unwrap();
        let printed = format!("{imported:?}");
        assert!(printed.contains("<oculto>"));
        let hex: String = imported.private_key_pkcs8[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            !printed.contains(&hex)
                && !printed.contains(&format!("{:?}", &imported.private_key_pkcs8[..8]))
        );
    }

    // ── La cadena de certificados ─────────────────────────────────────

    #[test]
    fn la_cadena_de_certificados_se_separa_igual_que_se_juntó() {
        let certs = vec![cert_der(), FAKE_CERT.to_vec(), cert_der()];
        assert_eq!(split_certs(&join_certs(&certs)).unwrap(), certs);
        assert_eq!(split_certs(&[]).unwrap(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn una_cadena_con_basura_al_final_es_un_error_y_no_un_pánico() {
        let mut blob = join_certs(&[FAKE_CERT.to_vec()]);
        blob.extend_from_slice(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]);
        assert!(split_certs(&blob).is_err());
        assert!(split_certs(&[0x30]).is_err());
    }

    // ── El llavero ────────────────────────────────────────────────────

    #[tokio::test]
    async fn guardar_y_leer_una_identidad_da_la_misma_clave_y_cadena() {
        let (keys, _server, _shared) = fake_keyring().await;
        import_pkcs12(&keys, "ana@example.com", PBES2_P12, PASSWORD)
            .await
            .unwrap();
        let expected = parse_pkcs12(PBES2_P12, PASSWORD).unwrap();

        let key = keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .expect("hay clave");
        assert_eq!(key.as_slice(), expected.private_key_pkcs8.as_slice());
        let certs = keys
            .find_smime_certs("ana@example.com")
            .await
            .unwrap()
            .expect("hay cadena");
        assert_eq!(certs, expected.certs);
    }

    #[tokio::test]
    async fn una_identidad_que_no_existe_no_tiene_ni_clave_ni_cadena() {
        let (keys, _server, _shared) = fake_keyring().await;
        assert!(keys
            .find_smime_private_key("nadie@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(keys
            .find_smime_certs("nadie@example.com")
            .await
            .unwrap()
            .is_none());
        // Borrar lo que no hay no es un error.
        keys.delete_smime_identity("nadie@example.com")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn borrar_una_identidad_quita_la_clave_y_la_cadena_y_deja_a_las_demas() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_smime_identity(
            "ana@example.com",
            &identity(b"clave-ana", vec![FAKE_CERT.to_vec()]),
        )
        .await
        .unwrap();
        keys.store_smime_identity(
            "beto@example.com",
            &identity(b"clave-beto", vec![cert_der()]),
        )
        .await
        .unwrap();

        keys.delete_smime_identity("ana@example.com").await.unwrap();

        assert!(keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(keys
            .find_smime_certs("ana@example.com")
            .await
            .unwrap()
            .is_none());
        let key = keys
            .find_smime_private_key("beto@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.as_slice(), b"clave-beto");
        assert_eq!(
            keys.find_smime_certs("beto@example.com")
                .await
                .unwrap()
                .unwrap(),
            vec![cert_der()]
        );
    }

    #[tokio::test]
    async fn dos_identidades_no_se_pisan() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_smime_identity(
            "ana@example.com",
            &identity(b"clave-ana", vec![FAKE_CERT.to_vec()]),
        )
        .await
        .unwrap();
        keys.store_smime_identity(
            "beto@example.com",
            &identity(b"clave-beto", vec![cert_der()]),
        )
        .await
        .unwrap();

        let ana = keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .unwrap();
        let beto = keys
            .find_smime_private_key("beto@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ana.as_slice(), b"clave-ana");
        assert_eq!(beto.as_slice(), b"clave-beto");
        assert_eq!(
            keys.find_smime_certs("ana@example.com")
                .await
                .unwrap()
                .unwrap(),
            vec![FAKE_CERT.to_vec()]
        );
    }

    #[tokio::test]
    async fn reimportar_una_identidad_reemplaza_y_no_duplica() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_smime_identity(
            "ana@example.com",
            &identity(b"vieja", vec![FAKE_CERT.to_vec()]),
        )
        .await
        .unwrap();
        keys.store_smime_identity("ana@example.com", &identity(b"nueva", vec![cert_der()]))
            .await
            .unwrap();

        for type_ in [TYPE_PRIVATE_KEY, TYPE_CERTS] {
            let items = keys
                .search(&smime_attributes("ana@example.com", type_))
                .await
                .unwrap();
            assert_eq!(items.len(), 1, "un solo ítem de tipo {type_}");
        }
        let key = keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.as_slice(), b"nueva");
    }

    /// Los ítems van bajo el esquema `SmimeKey` con la identidad, y no se
    /// cruzan con los de la clave del almacén (otro esquema).
    #[tokio::test]
    async fn los_items_van_bajo_el_esquema_smimekey_con_su_identidad() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_smime_identity("ana@example.com", &identity(b"k", vec![FAKE_CERT.to_vec()]))
            .await
            .unwrap();

        assert_eq!(SCHEMA, "ar.net.vasak.os.SmimeKey");
        async fn buscar(keys: &SecretServiceKeys, schema: &str, identity: &str) -> usize {
            let attrs = HashMap::from([("xdg:schema", schema), ("identity", identity)]);
            keys.search(&attrs).await.unwrap().len()
        }
        assert_eq!(
            buscar(&keys, SCHEMA, "ana@example.com").await,
            2,
            "clave + cadena"
        );
        assert_eq!(buscar(&keys, SCHEMA, "otra@example.com").await, 0);
        assert_eq!(
            buscar(&keys, super::super::key::SCHEMA, "ana@example.com").await,
            0,
            "nada bajo el esquema de la clave del almacén"
        );
        // Y el lector de la clave del almacén no se topa con ellos.
        assert!(keys.find("ana@example.com").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn la_cadena_no_lleva_la_clave_privada() {
        let (keys, _server, _shared) = fake_keyring().await;
        import_pkcs12(&keys, "ana@example.com", PBES2_P12, PASSWORD)
            .await
            .unwrap();
        let key = keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .unwrap();
        let certs = keys
            .find_smime_certs("ana@example.com")
            .await
            .unwrap()
            .unwrap()
            .concat();
        assert!(!certs.windows(32).any(|w| w == &key[..32]));
    }

    #[tokio::test]
    async fn una_contrasena_equivocada_al_importar_no_guarda_nada() {
        let (keys, _server, _shared) = fake_keyring().await;
        let err = import_pkcs12(&keys, "ana@example.com", PBES2_P12, b"mala")
            .await
            .unwrap_err();
        assert!(matches!(err, SmimeError::WrongPassword), "dio {err:?}");
        let err = import_pkcs12(&keys, "ana@example.com", LEGACY_P12, PASSWORD)
            .await
            .unwrap_err();
        assert!(matches!(err, SmimeError::UnsupportedPkcs12), "dio {err:?}");
        assert!(keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(keys
            .find_smime_certs("ana@example.com")
            .await
            .unwrap()
            .is_none());
    }

    /// Con el llavero bloqueado `SearchItems` contesta vacío: no se puede
    /// tomar por «no hay clave», es un error.
    #[tokio::test]
    async fn con_el_llavero_bloqueado_leer_y_guardar_dan_error_y_no_ausencia() {
        let (keys, server, shared) = fake_keyring().await;
        keys.store_smime_identity("ana@example.com", &identity(b"k", vec![FAKE_CERT.to_vec()]))
            .await
            .unwrap();
        lock_and_announce(&server, &shared).await.unwrap();

        assert!(matches!(
            keys.find_smime_private_key("ana@example.com").await,
            Err(KeyError::Locked)
        ));
        assert!(matches!(
            keys.find_smime_certs("ana@example.com").await,
            Err(KeyError::Locked)
        ));
        assert!(matches!(
            keys.store_smime_identity("ana@example.com", &identity(b"x", vec![FAKE_CERT.to_vec()]))
                .await,
            Err(KeyError::Locked)
        ));
        assert!(matches!(
            keys.delete_smime_identity("ana@example.com").await,
            Err(KeyError::Locked)
        ));
    }
}
