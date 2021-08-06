# Changelog

## 1.11.2 (2021-08-06)

* Fixes
  * Add compatability with OTP 24

## 1.11.1 (2020-12-23)

* Fixes
  * Fix compatibility with older OTP versions
  * Fix AES detection on OTP 23
  * Fix AES GCM bugs on OTP 23

## 1.11.0 (2020-11-24)

* Fixes
  * Add compatability layer to fix deprecated `crypto` functions.
  * Use `:extra_applications` instead of `:applications` (bumps Elixir requirement to `~> 1.4`).
  * Conditionally compile `Poison` modules used for testing.

## 1.10.1 (2020-01-08)

* Fixes
  * Add PEM/DER compatibility layer for PKCS-8 incompatibilities with various versions of OTP, `crypto`, and `public_key`; see [#82](https://github.com/potatosalad/erlang-jose/issues/82)

## 1.10.0 (2020-01-03)

* Enhancements
  * Remove [base64url](https://github.com/dvv/base64url) dependency and include embedded version.
  * Add support for `C20P` and `XC20P` encryption based on [draft-amringer-jose-chacha](https://tools.ietf.org/html/draft-amringer-jose-chacha-01) (ChaCha20/Poly1305 and XChaCha20/Poly1305).
  * Add support for ECDH-ES keywrapping for AES-GCM, ChaCha20/Poly1305, and XChaCha20/Poly1305.
  * Add support for PBES2 keywrapping for AES-GCM, ChaCha20/Poly1305, and XChaCha20/Poly1305.
  * Add support for `ECDH-1PU` encryption based on [draft-madden-jose-ecdh-1pu](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-02).
  * Add support for reading/writing DER format (or PKCS8 format).

* Fixes
  * Fix PSS salt length (thanks to [@ntrepid8](https://github.com/ntrepid8), see [#65](https://github.com/potatosalad/erlang-jose/pull/65))
  * Speed up and stabilize tests on CI environment.

## 1.9.0 (2018-12-31)

* Enhancements
  * Add support for [Jason](https://github.com/michalmuskala/jason) JSON encoding and decoding.
  * Add support for Poison 4.x and lexical ordering.
  * Use `public_key` over `cutkey` for RSA key generation if available.
  * Drop support for older versions of OTP (19+ now required).
  * Relicense library under MIT license.

* Fixes
  * Add macro so the application compiles without warnings after `erlang:get_stacktrace/0` has been deprecated.
  * Extra sanity check for RSA padding modes when falling back.

## 1.8.4 (2017-05-18)

* Enhancements
  * Add support for reading and writing PEM files for Ed25519, Ed448, X25519, and X448 keys based on [draft-ietf-curdle-pkix](https://tools.ietf.org/html/draft-ietf-curdle-pkix).
  * Add support for [ojson](https://github.com/potatosalad/erlang-json) adapter for encoding/decoding JSON.

## 1.8.3 (2017-03-30)

* Fixes
  * Regression fix from 1.8.2 for OTP-17 (thanks to [@alexandrejbr](https://github.com/alexandrejbr), see [#35](https://github.com/potatosalad/erlang-jose/issues/35) and [#36](https://github.com/potatosalad/erlang-jose/pull/36))

## 1.8.2 (2017-03-15)

* Enhancements
  * Add support for decoding firebase certificate public keys (thanks to [@noizu](https://github.com/noizu), see [#30](https://github.com/potatosalad/erlang-jose/issues/30))

* Fixes
  * Fix cross-platform issues with EC signatures (specifically S and R sizes, thanks to [@alexandrejbr](https://github.com/alexandrejbr), see [#32](https://github.com/potatosalad/erlang-jose/pull/32))
  * Typo in documentation for `JOSE.encode/1` (thanks to [@DaveLampton](https://github.com/DaveLampton), see [#31](https://github.com/potatosalad/erlang-jose/issues/31))

* Tests
  * Tested against OTP 19.3, Elixir 1.4.x, and Poison 3.x

## 1.8.1 (2017-02-02)

* Fixes
  * Parentheses to remove ambiguity on Elixir 1.4 [#26](https://github.com/potatosalad/erlang-jose/pull/26), thanks [@alexandrubagu](https://github.com/alexandrubagu)

## 1.8.0 (2016-08-08)

* Enhancements
  * ChaCha20/Poly1305 encryption and one-time message authentication functions are experimentally supported based on [RFC 7539](https://tools.ietf.org/html/rfc7539).

* Fixes
  * Handling invalid token without raising Exception [#22](https://github.com/potatosalad/erlang-jose/issues/22)
  * `JOSE.JWT.verify` uses CPU intensively when signed is nil [#23](https://github.com/potatosalad/erlang-jose/issues/23)

Examples of new functionality:

```elixir
iex> # Encrypt
iex> jwe = %{"alg" => "dir", "enc" => "ChaCha20/Poly1305"}
iex> jwk = JOSE.JWE.generate_key(jwe) |> JOSE.JWK.to_map |> elem(1)
%{"alg" => "dir", "enc" => "ChaCha20/Poly1305", "k" => "EffEuY2nbShIVtizmek8AuR7ftSuY2e8XRxGjMc8QAc", "kty" => "oct", "use" => "enc"}
iex> plain_text = "message to encrypt"
iex> encrypted = JOSE.JWK.block_encrypt(plain_text, jwk) |> JOSE.JWE.compact |> elem(1)
"eyJhbGciOiJkaXIiLCJlbmMiOiJDaGFDaGEyMC9Qb2x5MTMwNSJ9..lbsERynEgQS8CRXZ.D_kt8ChsaYWX9gL9tJlJ2n0E.y0o_TYjGlaB9sEEcA9o12A"

iex> # Decrypt
iex> plain_text == JOSE.JWK.block_decrypt(encrypted, jwk) |> elem(0)
true

iex> # Sign
iex> jws = %{"alg" => "Poly1305"}
iex> jwk = JOSE.JWS.generate_key(jws) |> JOSE.JWK.to_map |> elem(1)
%{"alg" => "Poly1305", "k" => "2X-OZVLA41Wy7mAjqWRaZyOw8FLyL3O3_f8d16D_-tQ", "kty" => "oct", "use" => "sig"}
iex> message = "message to sign"
iex> signed = JOSE.JWK.sign(message, jwk) |> JOSE.JWS.compact |> elem(1)
"eyJhbGciOiJQb2x5MTMwNSIsIm5vbmNlIjoicGExU1dlQzJVQzhwZlQ1NCJ9.bWVzc2FnZSB0byBzaWdu.IUI-PvN5bh_9jX-MeDtetw"

iex> # Verify
iex> JOSE.JWK.verify_strict(signed, ["Poly1305"], jwk) |> elem(0)
true
```

## 1.7.9 (2016-07-13)

* Fixes
  * Fixed JSON encoding bug in `jose_json_poison_compat_encoder` for projects using Poison as the JSON encoder where Erlang loads Elixir as a dependency.

## 1.7.8 (2016-07-08)

* Enhancements
  * Updated EdDSA tests to comply with draft 04 of [draft-ietf-jose-cfrg-curves-04](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-04).

* Fixes
  * Fixed compression encoding bug for `{"zip":"DEF"}` operations (thanks to [@amadden734](https://github.com/amadden734) see [potatosalad/ruby-jose#3](https://github.com/potatosalad/ruby-jose/pull/3))

## 1.7.7 (2016-06-30)

* Enhancements
  * Improved handling of RSA private keys in SMF (Straightforward Method) form to CRT (Chinese Remainder Theorem) form, see [#19](https://github.com/potatosalad/erlang-jose/issues/19)  This is especially useful for keys produced by Java programs using the `RSAPrivateKeySpec` API as mentioned in [Section 9.3 of RFC 7517](https://tools.ietf.org/html/rfc7517#section-9.3).
  * Updated EdDSA operations to comply with draft 02 of [draft-ietf-jose-cfrg-curves-02](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-02).

Example RSA SMF to CRT usage:

```erlang
%% The following map of an RSA secret key is in SMF (Straightforward Method) form.
%% Notice that we only have d, e, and n for this secret key.
JWK = jose_jwk:from(#{
  <<"d">> => <<"WSAGFGM7fSyYn5NyBL0dp3kjHjQ3djjhQoOAFasoyeE">>,
  <<"e">> => <<"AQAB">>,
  <<"kty">> => <<"RSA">>,
  <<"n">> => <<"0PM6Aooi_KYkDA1r-S24SauFpfTRc5kiPLF3a1EhuY8">>
}).

%% If we convert it back to a map, it is now in CRT (Chinese Remainder Theorem) form.
%% Notice that the dp, dq, p, q, and qi have been restored.
element(2, jose_jwk:to_map(JWK)) =:= #{
  <<"d">> => <<"WSAGFGM7fSyYn5NyBL0dp3kjHjQ3djjhQoOAFasoyeE">>,
  <<"dp">> => <<"G00J545ym1bqC9hnFDo3aQ">>,
  <<"dq">> => <<"tt0FvEZgKli6IL4rVKx3cw">>,
  <<"e">> => <<"AQAB">>,
  <<"kty">> => <<"RSA">>,
  <<"n">> => <<"0PM6Aooi_KYkDA1r-S24SauFpfTRc5kiPLF3a1EhuY8">>,
  <<"p">> => <<"9O5YQ0w6PIpDl6c6yqwyKQ">>,
  <<"q">> => <<"2mScgy86M3q6b301UAU09w">>,
  <<"qi">> => <<"Wrp0SgcGgTT5WmeuHD6Sqw">>
}.
```

## 1.7.6 (2016-06-29)

* Fixes
  * Compatibility fixes for OTP 19 and Elixir 1.3

## 1.7.5 (2016-05-13)

* Fixes
  * Removed leftover development file accidentally included in last release.

## 1.7.4 (2016-05-13)

* Enhancements
  * More detailed documentation on [key generation](https://hexdocs.pm/jose/key-generation.html).

* Fixes
  * Replaced usage of `crypto:rand_bytes/1` with `crypto:strong_rand_bytes/1` in preparation for Elixir 1.3 and OTP 19 (thanks to [@asonge](https://github.com/asonge) for [#17](https://github.com/potatosalad/erlang-jose/pull/17)).

## 1.7.3 (2016-03-17)

* Fixes
  * `JOSE.JWT.encrypt/2` now uses `JOSE.JWK.block_encryptor/1` properly.

## 1.7.2 (2016-03-16)

* Enhancements
  * Better support for lists of terms.
  * Added merge functions:
    * `JOSE.JWE.merge/2`
    * `JOSE.JWK.merge/2`
    * `JOSE.JWS.merge/2`
    * `JOSE.JWT.merge/2`
  * Added signer, verifier, and block_encryptor functions:
    * `JOSE.JWK.signer/1`
    * `JOSE.JWK.verifier/1`
    * `JOSE.JWK.block_encryptor/1`
  * Support for `"alg"`, `"enc"`, and `"use"` on keys.

Examples of new functionality:

```elixir
iex> # Let's generate a 64 byte octet key
iex> jwk = JOSE.JWK.generate_key({:oct, 64}) |> JOSE.JWK.to_map |> elem(1)
%{"k" => "FXSy7PufOayusvfyKQzdxCegm7yWIMp1b0LD13v57Nq2wF_B-fcr7LDOkufDikmFFsVYWLgrA2zEB--_qqDn3g", "kty" => "oct"}

iex> # Based on the key's size and type, a default signer (JWS) can be determined
iex> JOSE.JWK.signer(jwk)
%{"alg" => "HS512"}

iex> # A list of algorithms for which this key type can be verified against can also be determined
iex> JOSE.JWK.verifier(jwk)
["HS256", "HS384", "HS512"]

iex> # Based on the key's size and type, a default enctypro (JWE) can be determined
iex> JOSE.JWK.block_encryptor(jwk)
%{"alg" => "dir", "enc" => "A256CBC-HS512"}

iex> # Keys can be generated based on the signing algorithm (JWS)
iex> JOSE.JWS.generate_key(%{"alg" => "HS256"}) |> JOSE.JWK.to_map |> elem(1)
%{"alg" => "HS256", "k" => "UuP3Tw2xbGV5N3BGh34cJNzzC2R1zU7i4rOnF9A8nqY", "kty" => "oct", "use" => "sig"}

iex> # Keys can be generated based on the encryption algorithm (JWE)
iex> JOSE.JWE.generate_key(%{"alg" => "dir", "enc" => "A128GCM"}) |> JOSE.JWK.to_map |> elem(1)
%{"alg" => "dir", "enc" => "A128GCM", "k" => "8WNdBjXXwg6QTwrrOnvEPw", "kty" => "oct", "use" => "enc"}

iex> # Example of merging a map into an existing JWS (also works with JWE, JWK, and JWT)
iex> jws = JOSE.JWS.from(%{"alg" => "HS256"})
iex> JOSE.JWS.merge(jws, %{"typ" => "JWT"}) |> JOSE.JWS.to_map |> elem(1)
%{"alg" => "HS256", "typ" => "JWT"}
```

## 1.7.1 (2016-03-08)

* Enhancements
  * New [Edwards-curve Digital Signature Algorithm (EdDSA) version 04](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-04) is out, update test vectors and remove support for 32 byte secrets for Ed448 and Ed448ph.

## 1.7.0 (2016-03-01)

* Enhancements
  * Add support for [libdecaf](https://github.com/potatosalad/erlang-libdecaf) NIF which provides support for;
    * `Ed25519`
    * `Ed25519ph`
    * `Ed448`
    * `Ed448ph`
    * `X25519`
    * `X448`

* Fixes
  * Return 56 bytes instead of 57 bytes when converting between edwards448 and curve448.
  * EdDSA related refactoring/cleanup.

## 1.6.1 (2016-02-05)

* Enhancements
  * Add support for NIF version of [keccakf1600](https://github.com/potatosalad/erlang-keccakf1600) library with `jose_sha3_keccakf1600_nif` (version 2 and up) for even faster SHA-3 operations.

## 1.6.0 (2016-01-20)

* Enhancements
  * Add `Ed448` and `Ed448ph` standards from [draft-irtf-cfrg-eddsa](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa).
  * Add support for [keccakf1600](https://github.com/potatosalad/erlang-keccakf1600) library with `jose_sha3_keccakf1600` for faster SHA-3 operations.
  * Many, many more tests.

* Fixes
  * Fix pure Erlang implementation of SHA-3 algorithms.

## 1.5.2 (2016-01-19)

* Enhancements
  * Documentation of the encryption algorithms, specifically [`JOSE.JWE`](https://hexdocs.pm/jose/JOSE.JWE.html).

* Fixes
  * Corrected optional callbacks issue for Elixir.
  * More consistent behavior for ECDH related encryption and decryption.

## 1.5.1 (2016-01-16)

* Fixes
  * Corrected formatting on some of the documentation.
  * Fixed optional callbacks for `jose_jwk_kty:sign/3`

## 1.5.0 (2016-01-16)

* Enhancements
  * Support [OKP](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves) key type with the following curves:
    * `Ed25519` (external [libsodium](https://github.com/potatosalad/erlang-libsodium) or fallback supported)
    * `Ed25519ph` (external [libsodium](https://github.com/potatosalad/erlang-libsodium) or fallback supported)
    * `X25519` (external [libsodium](https://github.com/potatosalad/erlang-libsodium) or fallback supported)
    * `Ed448` (no external, no fallback)
    * `Ed448ph` (no external, no fallback)
    * `X448` (no external, but fallback supported)
  * Support [SHA-3](https://en.wikipedia.org/wiki/SHA-3) functions for future use with `Ed448` and `Ed448ph`.
  * Add `jose_jwk:shared_secret/2` for computing the shared secret between two `EC` or `OKP` keys.

## 1.4.2 (2015-11-30)

* Enhancements
  * Support [PKCS#8](https://www.openssl.org/docs/manmaster/apps/pkcs8.html) formatted private key PEM files. See #13

* Fixes
  * Add missing guards in `jose_jws:sign/4` #11
  * Add missing guards in `jose_jwe:block_encrypt/5`

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
