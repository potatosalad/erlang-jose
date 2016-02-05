# Algorithms

| Algorithm         | Purpose    | OTP 17 | OTP 18 | Fallback | Definition |
| ----------------- | ---------- | ------ | ------ | -------- | ---------- |
| AES CBC 128-bit   | Encryption | X      | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES CBC 192-bit   | Encryption |        |        | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES CBC 256-bit   | Encryption | X      | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES CTR 128-bit   | Encryption | X      | X      |          | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES CTR 192-bit   | Encryption | X      | X      |          | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES CTR 256-bit   | Encryption | X      | X      |          | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES ECB 128-bit   | Encryption |        | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES ECB 192-bit   | Encryption |        |        | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES ECB 256-bit   | Encryption |        | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38A](http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf) |
| AES GCM 128-bit   | Encryption |        | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38D](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) |
| AES GCM 192-bit   | Encryption |        | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38D](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) |
| AES GCM 256-bit   | Encryption |        | X      | [`jose_jwa_aes`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) | [NIST.800-38D](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) |
| RSAES-OAEP        | Encryption | X      | X      | [`jose_jwa_pkcs1`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) | [RFC 3447](https://tools.ietf.org/html/rfc3447) |
| RSAES-OAEP-256    | Encryption |        |        | [`jose_jwa_pkcs1`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) | [RFC 3447](https://tools.ietf.org/html/rfc3447) |
| RSAES-PKCS1-v1_5  | Encryption | X      | X      | [`jose_jwa_pkcs1`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) | [RFC 3447](https://tools.ietf.org/html/rfc3447) |
| RSASSA-PKCS1-v1_5 | Signature  | X      | X      | [`jose_jwa_pkcs1`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) | [RFC 3447](https://tools.ietf.org/html/rfc3447) |
| RSASSA-PSS        | Signature  |        |        | [`jose_jwa_pkcs1`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) | [RFC 3447](https://tools.ietf.org/html/rfc3447) |

There are also several "helper" algorithms used with the above that have no native implementations currently in OTP:

| Algorithm         | Purpose         | Fallback | Definition |
| ----------------- | --------------- | -------- | ---------- |
| AES Key Wrap      | Key Wrap        | [`jose_jwa_aes_kw`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes_kw.erl) | [RFC 3394](https://tools.ietf.org/html/rfc3394) |
| Concat KDF        | Key Derivation  | [`jose_jwa_concat_kdf`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_concat_kdf.erl) | [NIST.800-56A](https://dx.doi.org/10.6028/NIST.SP.800-56Ar2) |
| MGF1              | Mask Generation | [`jose_jwa_pkcs1`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) | [RFC 3447](https://tools.ietf.org/html/rfc3447) |
| PBKDF1            | Key Derivation  | [`jose_jwa_pkcs5`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs5.erl) | [RFC 2898](https://tools.ietf.org/html/rfc2898) |
| PBKDF2            | Key Derivation  | [`jose_jwa_pkcs5`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs5.erl) | [RFC 2898](https://tools.ietf.org/html/rfc2898) |
| PKCS #7 Padding   | Padding         | [`jose_jwa_pkcs7`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs7.erl) | [RFC 2315](https://tools.ietf.org/html/rfc2315) |

The following are algorithms related to the draft [CFRG ECDH and signatures in JOSE](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves):

| Algorithm | Purpose      | External | Fallback | Definition |
| --------- | ------------ | -------- | -------- | ---------- |
| Ed25519   | Signature    | [`libsodium`](https://github.com/potatosalad/erlang-libsodium) | [`jose_jwa_curve25519`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_curve25519.erl) | [EdDSA](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa#section-5.1) |
| Ed25519ph | Signature    | [`libsodium`](https://github.com/potatosalad/erlang-libsodium) | [`jose_jwa_curve25519`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_curve25519.erl) | [EdDSA](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa#section-5.1) |
| Ed448     | Signature    |          | [`jose_jwa_curve448`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_curve448.erl) | [EdDSA](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa#section-5.2) |
| Ed448ph   | Signature    |          | [`jose_jwa_curve448`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_curve448.erl) | [EdDSA](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa#section-5.2) |
| SHAKE256  | Hashing      | [`keccakf1600`](https://github.com/potatosalad/erlang-keccakf1600) | [`jose_jwa_sha3`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_sha3.erl) | [Keccak](http://keccak.noekeon.org/) |
| X25519    | Key Exchange | [`libsodium`](https://github.com/potatosalad/erlang-libsodium) | [`jose_jwa_curve25519`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_curve25519.erl) | [RFC 7748](https://tools.ietf.org/html/rfc7748#section-5) |
| X448      | Key Exchange |          | [`jose_jwa_curve448`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_curve448.erl) | [RFC 7748](https://tools.ietf.org/html/rfc7748#section-5) |
