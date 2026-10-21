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
use x509_cert::Certificate;
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

    // PKCS#12 no garantiza el orden de los CertBag: el cert del end-entity puede
    // no venir primero (p. ej. un `.p12` con la CA delante). Se adelanta el cert
    // cuya clave pública es la de la clave privada, así `.first()`/`[0]` es
    // siempre el leaf en el resto del pipeline.
    // Un tipo de clave no soportado (ni RSA ni ECDSA P-256) se rechaza acá en vez
    // de devolver éxito en silencio: sin su SPKI no se puede verificar cuál cert
    // es el leaf, y `detached_signature` tampoco podría firmar con esa clave, así
    // que no es una identidad usable.
    let spki = private_key_spki(&private_key_pkcs8).ok_or_else(|| {
        SmimeError::MalformedPkcs12(
            "tipo de clave del .p12 no soportado (sólo RSA y ECDSA P-256)".into(),
        )
    })?;
    match certs
        .iter()
        .position(|c| cert_spki(c).as_deref() == Some(spki.as_slice()))
    {
        Some(0) => {}
        Some(i) => {
            let leaf = certs.remove(i);
            certs.insert(0, leaf);
        }
        None => {
            return Err(SmimeError::MalformedPkcs12(
                "ningún certificado del .p12 corresponde a la clave privada".into(),
            ))
        }
    }

    Ok(ImportedIdentity {
        private_key_pkcs8,
        certs,
    })
}

/// El SPKI (DER) de la clave pública que corresponde a una clave privada PKCS#8.
/// Sólo RSA y ECDSA P-256, que son las que el pipeline firma y descifra; otra
/// clave devuelve `None`, y el import la rechaza (no es una identidad usable).
fn private_key_spki(pkcs8_der: &[u8]) -> Option<Vec<u8>> {
    use pkcs8::DecodePrivateKey;
    use spki::EncodePublicKey;
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der) {
        return key
            .to_public_key()
            .to_public_key_der()
            .ok()
            .map(|d| d.as_bytes().to_vec());
    }
    if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der) {
        return key
            .verifying_key()
            .to_public_key_der()
            .ok()
            .map(|d| d.as_bytes().to_vec());
    }
    None
}

/// El SPKI (DER) de la clave pública de un certificado, para compararlo con el de
/// la clave privada. `None` si el cert no se puede leer.
fn cert_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    Certificate::from_der(cert_der)
        .ok()?
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()
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
    const SIN_MAC_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/sin-mac.p12");
    const MAC_SHA1_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/mac-sha1.p12");
    const MAC_SHA512_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/mac-sha512.p12");
    const CLAVE_HEREDADA_P12: &[u8] =
        include_bytes!("../../tests/fixtures/smime/clave-heredada-sola.p12");
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
    /// contenido (se prueba uno de cada 4 bytes: cubre todas las regiones y
    /// ahorra 20 s de CI). Si para algún byte el parseo devuelve `Ok`, tiene que ser la
    /// misma identidad (p. ej. un byte fuera de lo que el MAC cubre y que no
    /// cambia nada).
    #[test]
    fn un_p12_con_un_byte_cambiado_no_se_acepta_con_otra_identidad() {
        let original = parse_pkcs12(PBES2_P12, PASSWORD).unwrap();
        for i in (0..PBES2_P12.len()).step_by(4) {
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

    // ── MAC del PFX ───────────────────────────────────────────────────

    /// Re-codifica el fixture PBES2 tocando su `MacData`.
    fn con_mac(tocar: impl FnOnce(&mut MacData)) -> Vec<u8> {
        let mut pfx = Pfx::from_der(PBES2_P12).unwrap();
        tocar(pfx.mac_data.as_mut().expect("el fixture trae MAC"));
        pfx.to_der().unwrap()
    }

    #[test]
    fn un_p12_sin_mac_se_rechaza_porque_no_se_puede_verificar() {
        let r = parse_pkcs12(SIN_MAC_P12, PASSWORD);
        assert!(
            matches!(&r, Err(SmimeError::MalformedPkcs12(d)) if d.contains("no trae MAC")),
            "dio {r:?}"
        );
    }

    #[test]
    fn un_mac_con_sha1_es_heredado_y_no_esta_disponible() {
        let err = parse_pkcs12(MAC_SHA1_P12, PASSWORD).unwrap_err();
        assert!(matches!(err, SmimeError::UnsupportedPkcs12), "dio {err:?}");
        assert!(err.to_string().contains("sin -legacy"), "{err}");
    }

    #[test]
    fn un_mac_con_sha512_se_verifica_y_abre() {
        let imported = parse_pkcs12(MAC_SHA512_P12, PASSWORD).expect("tiene que abrir");
        assert_eq!(imported.certs, vec![cert_der()]);
        let err = parse_pkcs12(MAC_SHA512_P12, b"otra").unwrap_err();
        assert!(matches!(err, SmimeError::WrongPassword), "dio {err:?}");
    }

    /// El contenido está intacto pero el MAC no cuadra: es lo que ve el MAC de
    /// un `.p12` manipulado, y es `WrongPassword` de forma determinista.
    #[test]
    fn un_mac_manipulado_da_contrasena_equivocada() {
        let roto = con_mac(|m| {
            let mut digest = m.mac.digest.as_bytes().to_vec();
            digest[0] ^= 0x01;
            m.mac.digest = OctetString::new(digest).unwrap();
        });
        let err = parse_pkcs12(&roto, PASSWORD).unwrap_err();
        assert!(matches!(err, SmimeError::WrongPassword), "dio {err:?}");

        let otra_sal = con_mac(|m| {
            let mut sal = m.mac_salt.as_bytes().to_vec();
            sal[0] ^= 0x01;
            m.mac_salt = OctetString::new(sal).unwrap();
        });
        let err = parse_pkcs12(&otra_sal, PASSWORD).unwrap_err();
        assert!(matches!(err, SmimeError::WrongPassword), "dio {err:?}");
    }

    /// Sin el MAC una contraseña mala sólo se notaba por el relleno CBC (1 de
    /// cada ~256 se colaba): con el MAC es siempre `WrongPassword`.
    #[test]
    fn una_contrasena_mala_es_siempre_wrongpassword() {
        for i in 0..300 {
            let pw = format!("mal-{i}");
            let r = parse_pkcs12(PBES2_P12, pw.as_bytes());
            assert!(
                matches!(r, Err(SmimeError::WrongPassword)),
                "con {pw:?} dio {r:?}"
            );
        }
        let r = parse_pkcs12(PBES2_P12, &[0xff, 0xfe]);
        assert!(
            matches!(r, Err(SmimeError::WrongPassword)),
            "no UTF-8: {r:?}"
        );
    }

    // ── Cotas contra un .p12 hostil (DoS) ─────────────────────────────

    #[test]
    fn las_iteraciones_del_mac_fuera_de_rango_no_estan_disponibles_sin_computar_el_kdf() {
        for n in [0, -1, i32::MIN, MAX_MAC_ITERS + 1, i32::MAX] {
            let p12 = con_mac(|m| m.iterations = n);
            let t = std::time::Instant::now();
            let r = parse_pkcs12(&p12, PASSWORD);
            assert!(
                matches!(r, Err(SmimeError::UnsupportedPkcs12)),
                "n={n}: {r:?}"
            );
            assert!(
                t.elapsed() < std::time::Duration::from_secs(2),
                "n={n}: tardó {:?}, ¿computó el KDF?",
                t.elapsed()
            );
        }
    }

    /// Las iteraciones del MAC dentro de rango sí se computan: con una cantidad
    /// distinta de la real, el MAC no cuadra.
    #[test]
    fn las_iteraciones_del_mac_dentro_de_rango_se_computan_y_no_cuadran() {
        let p12 = con_mac(|m| m.iterations = 2049);
        let r = parse_pkcs12(&p12, PASSWORD);
        assert!(matches!(r, Err(SmimeError::WrongPassword)), "dio {r:?}");
    }

    fn tlv(tag: u8, contenido: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match contenido.len() {
            n if n < 0x80 => out.push(n as u8),
            // DER exige la forma mínima: 0x81 hasta 255 bytes, 0x82 desde ahí.
            n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
            n => {
                out.push(0x82);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
        }
        out.extend_from_slice(contenido);
        out
    }

    fn entero(n: u64) -> Vec<u8> {
        let mut bytes: Vec<u8> = n
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        if bytes.is_empty() || bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        tlv(0x02, &bytes)
    }

    fn oid(s: &str) -> Vec<u8> {
        tlv(0x06, ObjectIdentifier::new_unwrap(s).as_bytes())
    }

    /// `AlgorithmIdentifier` de PBES2 con el KDF dado (ya codificado).
    fn pbes2_con(kdf: Vec<u8>) -> pkcs5::EncryptionScheme<'static> {
        let cifrado = tlv(
            0x30,
            &[oid("2.16.840.1.101.3.4.1.42"), tlv(0x04, &[7u8; 16])].concat(),
        );
        let params = tlv(0x30, &[kdf, cifrado].concat());
        let alg = tlv(0x30, &[oid("1.2.840.113549.1.5.13"), params].concat());
        let alg: &'static [u8] = Box::leak(alg.into_boxed_slice());
        pkcs5::EncryptionScheme::try_from(spki::AlgorithmIdentifierRef::from_der(alg).unwrap())
            .expect("PBES2 sintético")
    }

    fn pbkdf2_con(iteraciones: u64) -> pkcs5::EncryptionScheme<'static> {
        let params = tlv(0x30, &[tlv(0x04, &[1u8; 8]), entero(iteraciones)].concat());
        pbes2_con(tlv(0x30, &[oid("1.2.840.113549.1.5.12"), params].concat()))
    }

    fn scrypt_con(n: u64, r: u64, p: u64) -> pkcs5::EncryptionScheme<'static> {
        let params = tlv(
            0x30,
            &[tlv(0x04, &[1u8; 8]), entero(n), entero(r), entero(p)].concat(),
        );
        pbes2_con(tlv(0x30, &[oid("1.3.6.1.4.1.11591.4.11"), params].concat()))
    }

    #[test]
    fn el_pbkdf2_con_demasiadas_iteraciones_no_esta_disponible() {
        assert!(check_kdf_bounds(&pbkdf2_con(2048)).is_ok());
        assert!(check_kdf_bounds(&pbkdf2_con(MAX_PBKDF2_ITERS as u64)).is_ok());
        for n in [MAX_PBKDF2_ITERS as u64 + 1, u32::MAX as u64] {
            let r = check_kdf_bounds(&pbkdf2_con(n));
            assert!(
                matches!(r, Err(SmimeError::UnsupportedPkcs12)),
                "n={n}: {r:?}"
            );
        }
    }

    #[test]
    fn el_scrypt_con_costo_de_memoria_enorme_no_esta_disponible() {
        assert!(check_kdf_bounds(&scrypt_con(1 << 14, 8, 1)).is_ok());
        assert!(check_kdf_bounds(&scrypt_con(MAX_SCRYPT_COST, 8, 1)).is_ok());
        let casos = [
            ("N > 2^20", scrypt_con(MAX_SCRYPT_COST * 2, 8, 1)),
            ("N de 2^40", scrypt_con(1 << 40, 8, 1)),
            (
                "r enorme",
                scrypt_con(1 << 14, MAX_SCRYPT_BLOCK as u64 + 1, 1),
            ),
            (
                "p enorme",
                scrypt_con(1 << 14, 8, MAX_SCRYPT_PARALLEL as u64 + 1),
            ),
        ];
        for (nombre, scheme) in casos {
            let r = check_kdf_bounds(&scheme);
            assert!(
                matches!(r, Err(SmimeError::UnsupportedPkcs12)),
                "{nombre}: {r:?}"
            );
        }
    }

    #[test]
    fn un_der_de_mas_de_8_mib_se_rechaza_sin_parsearlo() {
        // Ceros: si se parseara daría `MalformedPkcs12`; `Unsupported` prueba
        // que el tope corta antes.
        let r = parse_pkcs12(&vec![0u8; MAX_PKCS12_BYTES + 1], PASSWORD);
        assert!(matches!(r, Err(SmimeError::UnsupportedPkcs12)), "dio {r:?}");
        // En el tope exacto sí se intenta, y no es un PFX.
        let r = parse_pkcs12(&vec![0u8; MAX_PKCS12_BYTES], PASSWORD);
        assert!(
            matches!(r, Err(SmimeError::MalformedPkcs12(_))),
            "dio {r:?}"
        );
    }

    // ── Orden de los certificados: el leaf siempre primero ────────────

    const OTRO_CERT_PEM: &str = include_str!("../../tests/fixtures/smime/otro-cert.pem");
    const EC_CERT_PEM: &str = include_str!("../../tests/fixtures/smime/ec-cert.pem");
    const EC_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/ec-p256.p12");

    fn pem_a_der(pem: &str) -> Vec<u8> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("el PEM es base64")
    }

    /// Arma en memoria un `.p12` PBES2-free (safes en claro, MAC SHA-256) con la
    /// clave y los certificados **en el orden dado**. `openssl pkcs12 -export`
    /// siempre pone el leaf primero, así que el orden «CA delante» —que PKCS#12
    /// permite y otros exportadores usan— sólo se consigue armándolo a mano.
    /// Un safe con la clave (keybag en claro) y otro con los CertBag.
    fn p12_con_certs_en_orden(pkcs8: &[u8], certs: &[Vec<u8>]) -> Vec<u8> {
        const ID_DATA_S: &str = "1.2.840.113549.1.7.1";
        let safe_bag =
            |bag_oid: &str, valor: &[u8]| tlv(0x30, &[oid(bag_oid), tlv(0xA0, valor)].concat());
        let safe_contents = |bags: Vec<Vec<u8>>| tlv(0x30, &bags.concat());
        let content_info = |contenido: &[u8]| {
            tlv(
                0x30,
                &[oid(ID_DATA_S), tlv(0xA0, &tlv(0x04, contenido))].concat(),
            )
        };

        let keybag = safe_bag("1.2.840.113549.1.12.10.1.1", pkcs8);
        let certbags: Vec<Vec<u8>> = certs
            .iter()
            .map(|c| {
                let cert_bag = tlv(
                    0x30,
                    &[oid(X509_CERTIFICATE_S), tlv(0xA0, &tlv(0x04, c))].concat(),
                );
                safe_bag("1.2.840.113549.1.12.10.1.3", &cert_bag)
            })
            .collect();
        const X509_CERTIFICATE_S: &str = "1.2.840.113549.1.9.22.1";

        let authsafe = tlv(
            0x30,
            &[
                content_info(&safe_contents(vec![keybag])),
                content_info(&safe_contents(certbags)),
            ]
            .concat(),
        );

        let salt = [7u8; 8];
        let rounds = 2048;
        let pw = std::str::from_utf8(PASSWORD).unwrap();
        let key = derive_key_utf8::<Sha256>(pw, &salt, Pkcs12KeyType::Mac, rounds, 32).unwrap();
        let mut hmac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        hmac.update(&authsafe);
        let digest = hmac.finalize().into_bytes();

        let digest_info = tlv(
            0x30,
            &[
                tlv(
                    0x30,
                    &[oid("2.16.840.1.101.3.4.2.1"), vec![0x05, 0x00]].concat(),
                ),
                tlv(0x04, &digest),
            ]
            .concat(),
        );
        let mac_data = tlv(
            0x30,
            &[digest_info, tlv(0x04, &salt), entero(rounds as u64)].concat(),
        );
        tlv(
            0x30,
            &[entero(3), content_info(&authsafe), mac_data].concat(),
        )
    }

    fn assert_leaf_primero(p12: &[u8], leaf: &[u8], ca: &[u8]) {
        let parsed = parse_pkcs12(p12, PASSWORD).expect("tiene que parsear");
        assert_eq!(parsed.certs.len(), 2, "se conservan los dos certificados");
        assert_eq!(
            cert_spki(&parsed.certs[0]),
            private_key_spki(&parsed.private_key_pkcs8),
            "certs[0] tiene que ser el de la clave privada"
        );
        assert_eq!(parsed.certs[0], leaf, "primero el leaf");
        assert_eq!(parsed.certs[1], ca, "después la CA");
    }

    /// El `.p12` trae la CA delante del leaf en los CertBag: sin reordenar,
    /// `certs[0]` sería la CA y `import_smime_identity` validaría la dirección
    /// contra el cert equivocado y `detached_signature` embebería ése como firmante.
    #[test]
    fn una_ca_delante_del_leaf_en_el_p12_no_le_gana_el_primer_lugar_rsa() {
        let key = parse_pkcs12(PBES2_P12, PASSWORD).unwrap().private_key_pkcs8;
        let (leaf, ca) = (cert_der(), pem_a_der(OTRO_CERT_PEM));
        let p12 = p12_con_certs_en_orden(&key, &[ca.clone(), leaf.clone()]);
        // Precondición: el orden del archivo es el malo, o la prueba no prueba nada.
        assert_ne!(cert_spki(&ca), private_key_spki(&key));
        assert_leaf_primero(&p12, &leaf, &ca);
    }

    /// Lo mismo con una clave ECDSA P-256 (la otra rama de `private_key_spki`).
    #[test]
    fn una_ca_delante_del_leaf_en_el_p12_no_le_gana_el_primer_lugar_ecdsa() {
        let key = parse_pkcs12(EC_P12, PASSWORD).unwrap().private_key_pkcs8;
        let (leaf, ca) = (pem_a_der(EC_CERT_PEM), pem_a_der(OTRO_CERT_PEM));
        let p12 = p12_con_certs_en_orden(&key, &[ca.clone(), leaf.clone()]);
        assert_leaf_primero(&p12, &leaf, &ca);
    }

    /// Si el leaf ya venía primero, el orden no se toca.
    #[test]
    fn un_p12_con_el_leaf_primero_conserva_el_orden() {
        let key = parse_pkcs12(PBES2_P12, PASSWORD).unwrap().private_key_pkcs8;
        let (leaf, ca) = (cert_der(), pem_a_der(OTRO_CERT_PEM));
        let p12 = p12_con_certs_en_orden(&key, &[leaf.clone(), ca.clone()]);
        assert_leaf_primero(&p12, &leaf, &ca);
    }

    /// Una clave que no corresponde a ningún certificado del `.p12` no es una
    /// identidad: error, y no «el primer cert que haya».
    #[test]
    fn un_p12_cuya_clave_no_es_de_ningun_certificado_es_malformado() {
        let key = parse_pkcs12(PBES2_P12, PASSWORD).unwrap().private_key_pkcs8;
        let ajenos = [pem_a_der(OTRO_CERT_PEM), pem_a_der(EC_CERT_PEM)];
        let p12 = p12_con_certs_en_orden(&key, &ajenos);
        let r = parse_pkcs12(&p12, PASSWORD);
        assert!(
            matches!(&r, Err(SmimeError::MalformedPkcs12(d)) if d.contains("corresponde")),
            "dio {r:?}"
        );
    }

    // ── Keybag heredado primero y en claro ────────────────────────────

    /// `.p12` con sólo la clave, en un keybag con `pbeWithSHA1And3-KeyTripleDES`
    /// dentro de un safe en claro y MAC SHA-256 (como lo arman CryptoAPI o
    /// keytool): `EncryptedPrivateKeyInfo` no entiende ese PBE, y el error tiene
    /// que ser el del hint y no «no se pudo leer».
    #[test]
    fn un_keybag_heredado_primero_y_en_claro_da_el_hint_de_sin_legacy() {
        let err = parse_pkcs12(CLAVE_HEREDADA_P12, PASSWORD).unwrap_err();
        assert!(matches!(err, SmimeError::UnsupportedPkcs12), "dio {err:?}");
        assert!(err.to_string().contains("sin -legacy"), "{err}");
    }

    #[test]
    fn el_oid_del_pbe_del_keybag_se_lee_sin_exigir_que_pkcs5_lo_entienda() {
        // pbeWithSHA1And3-KeyTripleDES-CBC, con sus parámetros (sal + iteraciones).
        let legacy = tlv(
            0x30,
            &[
                tlv(
                    0x30,
                    &[
                        oid("1.2.840.113549.1.12.1.3"),
                        tlv(0x30, &[tlv(0x04, &[1u8; 8]), entero(2048)].concat()),
                    ]
                    .concat(),
                ),
                tlv(0x04, &[0u8; 16]),
            ]
            .concat(),
        );
        assert_eq!(
            keybag_pbe_oid(&legacy).unwrap().to_string(),
            "1.2.840.113549.1.12.1.3"
        );
        assert!(EncryptedPrivateKeyInfo::from_der(&legacy).is_err());

        for basura in [
            &[][..],
            &[0x30],
            &[0x30, 0x00],
            &[0x04, 0x01, 0x00],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(
                matches!(keybag_pbe_oid(basura), Err(SmimeError::MalformedPkcs12(_))),
                "{basura:?}"
            );
        }
    }

    /// El camino de `import_pkcs12` (ahora en `spawn_blocking`) sigue
    /// llegando al llavero con un `.p12` con MAC SHA-512 y propaga el error
    /// del parseo sin guardar nada con uno sin MAC.
    #[tokio::test]
    async fn importar_en_spawn_blocking_guarda_y_propaga_los_errores() {
        let (keys, _server, _shared) = fake_keyring().await;
        import_pkcs12(&keys, "ana@example.com", MAC_SHA512_P12, PASSWORD)
            .await
            .unwrap();
        assert!(keys
            .find_smime_private_key("ana@example.com")
            .await
            .unwrap()
            .is_some());

        let err = import_pkcs12(&keys, "beto@example.com", SIN_MAC_P12, PASSWORD)
            .await
            .unwrap_err();
        assert!(matches!(err, SmimeError::MalformedPkcs12(_)), "dio {err:?}");
        assert!(keys
            .find_smime_private_key("beto@example.com")
            .await
            .unwrap()
            .is_none());
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
