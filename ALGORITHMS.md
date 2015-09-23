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
