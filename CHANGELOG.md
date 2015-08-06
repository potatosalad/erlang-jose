# Changelog

## 1.1.0 (2015-08-06)

* Enhancements
  * Detect supported `crypto` AES ciphers and use fallbacks when necessary.
  * Detect EC key mode (to support OTP 17.5).
  * Mostly pure Erlang implementation of AES GCM and GHASH functions.
  * Add `JOSE.JWA` module for Elixir.

* Fixes
  * All tests now pass on OTP 17.5 and OTP 18.
  * Fallback to non-native crypto implementations for OTP 17.5.

## 1.0.1 (2015-08-05)

* Dependencies
  * Use [`base64url`](https://hex.pm/packages/base64url) package from hex.pm

## 1.0.0 (2015-08-05)

* Initial Release

* Algorithm Support
  * JSON Web Encryption (JWE) [RFC 7516](https://tools.ietf.org/html/rfc7516)
    * `"alg"` [RFC 7518 Section 4](https://tools.ietf.org/html/rfc7518#section-4)
      * `RSA1_5`
      * `RSA-OAEP`
      * `RSA-OAEP-256`
      * `A128KW`
      * `A192KW`
      * `A256KW`
      * `dir`
      * `ECDH-ES`
      * `ECDH-ES+A128KW`
      * `ECDH-ES+A192KW`
      * `ECDH-ES+A256KW`
      * `A128GCMKW`
      * `A192GCMKW`
      * `A256GCMKW`
      * `PBES2-HS256+A128KW`
      * `PBES2-HS384+A192KW`
      * `PBES2-HS512+A256KW`
    * `"enc"` [RFC 7518 Section 5](https://tools.ietf.org/html/rfc7518#section-5)
      * `A128CBC-HS256`
      * `A192CBC-HS384`
      * `A256CBC-HS512`
      * `A128GCM`
      * `A192GCM`
      * `A256GCM`
    * `"zip"` [RFC 7518 Section 7.3](https://tools.ietf.org/html/rfc7518#section-7.3)
      * `DEF`
  * JSON Web Key (JWK) [RFC 7517](https://tools.ietf.org/html/rfc7517)
    * `"alg"` [RFC 7518 Section 6](https://tools.ietf.org/html/rfc7518#section-6)
      * `EC`
      * `RSA`
      * `oct`
  * JSON Web Signature (JWS) [RFC 7515](https://tools.ietf.org/html/rfc7515)
    * `"alg"` [RFC 7518 Section 3](https://tools.ietf.org/html/rfc7518#section-3)
      * `HS256`
      * `HS384`
      * `HS512`
      * `RS256`
      * `RS384`
      * `RS512`
      * `ES256`
      * `ES384`
      * `ES512`
      * `PS256`
      * `PS384`
      * `PS512`
      * `none`
