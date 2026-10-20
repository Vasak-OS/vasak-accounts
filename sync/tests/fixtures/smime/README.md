# Material de prueba S/MIME (descartable)

Certificado **autofirmado de juguete** y sus `.p12`, para las pruebas del parseo
de `store/smime_key.rs`. No es la clave de nadie, no se usa en ningún lado real y
se puede regenerar con `openssl` cuando se quiera. Vale commitearlo: es dato de
prueba, como los `.pem` de prueba de los propios crates de RustCrypto.

- `cert.pem` — el certificado X.509 (la parte pública), para cruzar contra lo que
  devuelve el parseo.
- `rsa-pbes2.p12` — exportado con el cifrado por omisión de openssl 3 (PBES2:
  PBKDF2-HMAC-SHA256 + AES-256-CBC). **Es el que tiene que parsear.**
- `rsa-legacy.p12` — exportado con `-legacy` (PBE heredado RC2/3DES). **Tiene que
  dar `SmimeError::UnsupportedPkcs12`.**

- `solo-certs.p12` — PBES2, **sólo el certificado, sin clave**. Tiene que dar
  `MalformedPkcs12` («no trae clave»).
- `solo-clave.p12` — PBES2, **sólo la clave, sin certificados**. Tiene que dar
  `MalformedPkcs12` («no trae certificados»).
- `sin-mac.p12` — PBES2 con clave y cert, **sin `MacData`** (`-nomac`). Tiene que dar
  `MalformedPkcs12` («no trae MAC»).
- `mac-sha1.p12` — PBES2 pero con el **MAC en SHA-1** (`-macalg sha1`). Tiene que dar
  `UnsupportedPkcs12`.
- `mac-sha512.p12` — PBES2 con MAC SHA-512 (`-macalg sha512`). Tiene que abrir.
- `clave-heredada-sola.p12` — sólo la clave, en un keybag con
  `pbeWithSHA1And3-KeyTripleDES-CBC` dentro de un safe en claro y MAC SHA-256
  (`-nocerts -legacy -keypbe PBE-SHA1-3DES -macalg sha256`): la forma de los `.p12`
  de CryptoAPI/keytool. Tiene que dar `UnsupportedPkcs12` con el hint «sin -legacy».

Contraseña de todos: `vasak-test`.

## Para firmar y verificar (`smime_sign`)

Generados con `openssl ecparam -name prime256v1 -genkey` + `openssl req -x509` +
`openssl pkcs12 -export` (PBES2 por omisión). Contraseña: `vasak-test`.

- `rsa-pbes2.p12` — RSA, SubjectAltName `prueba@vasak.test`.
- `ec-p256.p12` — ECDSA P-256, SubjectAltName `ec@vasak.test` (cert suelto: `ec-cert.pem`).
- `ec-email-en-subject.p12` — ECDSA P-256 **sin SubjectAltName**: el correo
  `subject@vasak.test` sólo está en el `emailAddress` del subject. Prueba la otra
  forma de ligar el firmante al `From`.
- `ec-vencido.p12` — ECDSA P-256, SubjectAltName `vencido@vasak.test`, vigencia
  2020-01-01 a 2021-01-01 (ya vencido).
- `ec-correo-vacio.p12` — ECDSA P-256 cuyo SubjectAltName trae un `rfc822Name`
  **vacío** (armado a mano con `cryptography`: `openssl` no lo emite). Prueba que
  un `From` vacío no «liga» con un correo vacío del cert.

## Para descifrar (`smime_sign::decrypt_message`)

Sobres reales de `openssl cms -encrypt`, cifrados a `rsa-pbes2.p12` (nuestro cert) con
el cuerpo `mensaje secreto …` (`enc-rsa-html.eml`: HTML con un texto largo, para
armar el ataque efail en las pruebas). Los de abajo se arman desde ellos en las
pruebas (cambiando el CEK cifrado, el relleno CBC o recortando el DER).

- `enc-rsa-aes128/192/256.eml` — RSAES-PKCS1-v1_5 + AES-CBC de 128/192/256 bits.
- `enc-rsa-oaep.eml` — RSAES-OAEP con SHA-1 (el valor por omisión de openssl).
- `enc-rsa-oaep-sha256.eml` — RSAES-OAEP con SHA-256 y MGF1-SHA-256 explícitos.
- `enc-rsa-multi.eml` — tres destinatarios: `otro-cert.pem` (RSA, `CN=A`, serie 1),
  nuestro cert y `ec-cert.pem` (ECC, `Kari`). En el orden en que el parser lo lee,
  **nosotros no somos el primero**.
- `enc-rsa-otro-destinatario.eml` — cifrado sólo a `otro-cert.pem`: bien formado,
  pero no es para nosotros.
- `enc-ecc-recipient.eml` — destinatario ECC (ECDH, `Kari`): no se abre.
- `enc-rsa-3des.eml` — contenido en 3DES-CBC: cifrado no soportado.
- `enc-rsa-gcm.eml` — AES-256-GCM (`AuthEnvelopedData`, `smime-type=authEnveloped-data`).
- `enc-rsa-firmado.eml` — sign-then-encrypt: el contenido de adentro es un
  `pkcs7-mime` firmado por `prueba@vasak.test`; el `From` sólo está en el sobre.
- `enc-rsa-manipulado.eml` — el DER del sobre alterado: no parsea.
- `otro-cert.pem` — certificado RSA de juguete; **la clave privada se descartó**.
