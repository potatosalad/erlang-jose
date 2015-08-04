# JOSE

[![Build Status](https://travis-ci.org/potatosalad/erlang-jose.png?branch=master)](https://travis-ci.org/potatosalad/erlang-jose)

JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.

## Algorithm Support

### JSON Web Encryption (JWE) [RFC 7516](https://tools.ietf.org/html/rfc7516)

#### `"alg"` [RFC 7518 Section 4](https://tools.ietf.org/html/rfc7518#section-4)

- [X] `RSA1_5`
- [X] `RSA-OAEP`
- [X] `RSA-OAEP-256` <sup>[1](#footnote-1)</sup>
- [X] `A128KW`
- [X] `A192KW` <sup>[2](#footnote-2)</sup>
- [X] `A256KW`
- [X] `dir`
- [X] `ECDH-ES`
- [X] `ECDH-ES+A128KW`
- [X] `ECDH-ES+A192KW` <sup>[2](#footnote-2)</sup>
- [X] `ECDH-ES+A256KW`
- [X] `A128GCMKW`
- [X] `A192GCMKW`
- [X] `A256GCMKW`
- [X] `PBES2-HS256+A128KW`
- [X] `PBES2-HS384+A192KW` <sup>[2](#footnote-2)</sup>
- [X] `PBES2-HS512+A256KW`

#### `"enc"` [RFC 7518 Section 5](https://tools.ietf.org/html/rfc7518#section-5)

- [X] `A128CBC-HS256`
- [X] `A192CBC-HS384` <sup>[2](#footnote-2)</sup>
- [X] `A256CBC-HS512`
- [X] `A128GCM`
- [X] `A192GCM`
- [X] `A256GCM`

#### `"zip"` [RFC 7518 Section 7.3](https://tools.ietf.org/html/rfc7518#section-7.3)

- [X] `DEF`

### JSON Web Key (JWK) [RFC 7517](https://tools.ietf.org/html/rfc7517)

#### `"alg"` [RFC 7518 Section 6](https://tools.ietf.org/html/rfc7518#section-6)

- [X] `EC`
- [X] `RSA`
- [X] `oct`

### JSON Web Signature (JWS) [RFC 7515](https://tools.ietf.org/html/rfc7515)

#### `"alg"` [RFC 7518 Section 3](https://tools.ietf.org/html/rfc7518#section-3)

- [X] `HS256`
- [X] `HS384`
- [X] `HS512`
- [X] `RS256`
- [X] `RS384`
- [X] `RS512`
- [X] `ES256`
- [X] `ES384`
- [X] `ES512`
- [X] `PS256` <sup>[3](#footnote-3)</sup>
- [X] `PS384` <sup>[3](#footnote-3)</sup>
- [X] `PS512` <sup>[3](#footnote-3)</sup>
- [X] `none`

<a name="footnote-1">1</a>: Implemented mostly in pure Erlang.  May be less performant than other supported encryption algorithms.  See [`jose_jwa_pkcs1.erl`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) for implementation details.

<a name="footnote-2">2</a>: Implemented in pure Erlang.  May be less performant than other supported encryption algorithms.  See [`jose_jwa_aes.erl`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_aes.erl) for implementation details.

<a name="footnote-3">3</a>: Implemented mostly in pure Erlang.  May be less performant than other supported signature algorithms.  See [`jose_jwa_pkcs1.erl`](https://github.com/potatosalad/erlang-jose/blob/master/src/jose_jwa_pkcs1.erl) for implementation details.
