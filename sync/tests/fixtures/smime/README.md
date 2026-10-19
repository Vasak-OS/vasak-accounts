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

Contraseña de todos: `vasak-test`.
