# Material de prueba OpenPGP (descartable)

Dato de prueba, no es la clave de nadie.

- `firmante.pub.asc` — clave pública de `Alice <alice@vasak.test>` (Ed25519 + subclave
  de firma y de cifrado), generada con rPGP. Es la clave **candidata** del peerstate.
- `smime-enveloped-con-firma-pgp.eml` — un sobre S/MIME (`openssl cms -encrypt -aes256`,
  cifrado a `../smime/rsa-pbes2.p12`) cuyo contenido de adentro es un cleartext PGP firmado
  por la subclave de firma de `firmante.pub.asc`. Prueba que una firma PGP dentro de un
  sobre S/MIME abierto se verifica (`opened_rows_decrypting`).

Regenerar: abrir el sobre con la clave S/MIME no cambia; si se rehace, la firma de adentro
tiene que ser de la clave de `firmante.pub.asc`.
