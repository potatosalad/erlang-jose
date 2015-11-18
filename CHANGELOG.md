# Changelog

## 1.4.1 (2015-11-18)

* Enhancements
  * Added `JOSE.JWS.peek_signature/1` for inspecting the signature parts of a signed binary.
  * `JOSE.JWS.compact/1` and `JOSE.JWS.expand/1` now work with signed lists.
  * First pass at documenting all of the major `JOSE` modules. `JOSE.JWE` still needs more examples. Closes #7

* Fixes
  * Fix infinite loop on `JOSE.JWE.key_decrypt/3` when no `"enc"` has been specified.
  * Fix various functions on `JOSE.JWE` that would fail due to `JOSE.JWE.from_record/1` on wrong terms.

## 1.4.0 (2015-11-17)

* Enhancements
  * Added `JOSE.unsecured_signing/0` and `JOSE.unsecured_signing/1` for disabling the `"none"` algorithm due to the [unsecured signing vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/) and in relation to #10
  * Added `JOSE.JWK.verify_strict/3`, `JOSE.JWS.verify_strict/3`, and `JOSE.JWT.verify_strict/3` for whitelisting which signing algorithms are allowed for verification.
  * Added `JOSE.JWT.peek_payload/1` and `JOSE.JWT.peek_protected/1` for inspecting the payload and protected parts of a signature.

## 1.3.0 (2015-09-22)

* Enhancements
  * `oct` key management (see `JOSE.JWK.from_oct/1,2`)
  * Key generation functions for `EC`, `RSA`, and `oct` keys (see `JOSE.JWK.generate_key/1`)
  * Add `JOSE.JWK.box_encrypt/2` which generates an ephemeral private key based on the given key curve.
  * Add support for detecting OTP version 18 and up with optional_callbacks.
  * Document key generation under `examples/KEY-GENERATION.md`
  * jiffy and jsone JSON support
  * Begin documenting the Elixir API (thanks to #8)
  * Add support for `jose_jws:peek/1` and `jose_jwt:peek/1`
  * Preparations for future upstream OTP crypto changes.
    * Improved detection of AES CBC, ECB, and GCM support.
    * Improved detection of RSAES-OAEP, RSAES-PKCS1-v1_5, RSASSA-PKCS1-v1_5, and RSASSA-PSS support.
    * Implemented fallback RSAES-PKCS1-v1_5 and RSASSA-PKCS1-v1_5 algorithms.
    * Improved selection of encryptor for oct keys.
    * Improved algorithm support detection for jose_jwa.

* Fixes
  * Remove "sph" from jose_jws (removed from [JWS Unencoded Payload Option](https://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-02)).

* Tests
  * Only run 1 in 10 for AES GCM and 1 in 5 for AES KW CAVP test vectors to speed up tests.
  * Additional tests for RSAES-PKCS1-v1_5 and RSASSA-PKCS1-v1_5 algorithms.

## 1.2.0 (2015-08-14)

* Enhancements
  * Add RSA PKCS-1 algorithms to support detection.
  * Add support for `crypto_fallback` option to enable/disable non-native cryptographic algorithms.
  * Add support for `json_module` option for encoding/decoding of JSON.

* Fixes
  * Fix AES GCM algorithm for non 96-bit IV values.
  * Allow RSA OAEP to specify Seed on encrypt.

* Tests
  * NIST and EMC test vectors for AES, PKCS-1, and PKCS-5.
  * Concat KDF, PBKDF1, and PKCS-7 Padding informal verification.
  * AES Key Wrap informal verification with NIST test vectors.

## 1.1.3 (2015-08-10)

* Fixes
  * Missed a case where jose was not starting automatically (see 1.1.2).

## 1.1.2 (2015-08-10)

* Enhancements
  * Automatically start jose if one of the fallback algorithms is required.

## 1.1.1 (2015-08-07)

* Fixes
  * Fix bit sizes for A128CBC-HS256, A192CBC-HS384, and A256CBC-HS512 algorithms.
  * Don't precompute the GHASH table (speeds up AES GCM fallback on OTP 17).
  * Use case statement instead of map pattern matching for block_decrypt (fixes map pattern matching bug on OTP 17).
  * Allow mostly empty EC keys to be converted back to JSON.
  * Add jose_jwk_props property test for full algorithm range of encryption and decryption.

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
