%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwe_enc_aes_cbc_hmac).

-behaviour(jose_jwe).
-behaviour(jose_jwe_enc).

%% jose_jwe callbacks
-export([
    from_map/1,
    to_map/2
]).
%% jose_jwe_enc callbacks
-export([
    algorithm/1,
    key_bit_size/1,
    content_decrypt/6,
    content_encrypt/5,
    generate_content_encryption_key/1,
    generate_nonce/1
]).

%% Types
-type state() :: aes_128_cbc_hmac_sha256 | aes_192_cbc_hmac_sha384 | aes_256_cbc_hmac_sha512.

-export_type([
    state/0
]).

%% Macros
-define(is_state(X),
    ((X) =:= aes_128_cbc_hmac_sha256 orelse (X) =:= aes_192_cbc_hmac_sha384 orelse (X) =:= aes_256_cbc_hmac_sha512)
).

%%%=============================================================================
%%% jose_jwe callbacks
%%%=============================================================================

from_map(F = #{<<"enc">> := <<"A128CBC-HS256">>}) ->
    {aes_128_cbc_hmac_sha256, maps:remove(<<"enc">>, F)};
from_map(F = #{<<"enc">> := <<"A192CBC-HS384">>}) ->
    {aes_192_cbc_hmac_sha384, maps:remove(<<"enc">>, F)};
from_map(F = #{<<"enc">> := <<"A256CBC-HS512">>}) ->
    {aes_256_cbc_hmac_sha512, maps:remove(<<"enc">>, F)}.

to_map(aes_128_cbc_hmac_sha256, F) ->
    F#{<<"enc">> => <<"A128CBC-HS256">>};
to_map(aes_192_cbc_hmac_sha384, F) ->
    F#{<<"enc">> => <<"A192CBC-HS384">>};
to_map(aes_256_cbc_hmac_sha512, F) ->
    F#{<<"enc">> => <<"A256CBC-HS512">>}.

%%%=============================================================================
%%% jose_jwe_enc callbacks
%%%=============================================================================

-spec algorithm(ENC) -> Algorithm when
    ENC :: jose_jwe_enc:internal_state(state()),
    Algorithm :: jose_jwe_enc:algorithm().
algorithm(aes_128_cbc_hmac_sha256) -> <<"A128CBC-HS256">>;
algorithm(aes_192_cbc_hmac_sha384) -> <<"A192CBC-HS384">>;
algorithm(aes_256_cbc_hmac_sha512) -> <<"A256CBC-HS512">>.

-spec key_bit_size(ENC) -> KeyBitSize when
    ENC :: jose_jwe_enc:internal_state(state()),
    KeyBitSize :: jose_jwe_enc:key_bit_size().
key_bit_size(aes_128_cbc_hmac_sha256) -> 256;
key_bit_size(aes_192_cbc_hmac_sha384) -> 384;
key_bit_size(aes_256_cbc_hmac_sha512) -> 512.

-spec content_decrypt(ENC, CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    ENC :: jose_jwe_enc:internal_state(state()),
    CipherText :: jose_aes_cbc_hmac:cipher_text(),
    CipherTag :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag(),
    AAD :: jose_aes_cbc_hmac:additional_authenticated_data(),
    IV :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
    CEK :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
    PlainText :: jose_aes_cbc_hmac:plain_text().
content_decrypt(aes_128_cbc_hmac_sha256, CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 128 andalso
        bit_size(CEK) =:= 256
->
    jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_decrypt(CipherText, CipherTag, AAD, IV, CEK);
content_decrypt(aes_192_cbc_hmac_sha384, CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 192 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 128 andalso
        bit_size(CEK) =:= 384
->
    jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_decrypt(CipherText, CipherTag, AAD, IV, CEK);
content_decrypt(aes_256_cbc_hmac_sha512, CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 256 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 128 andalso
        bit_size(CEK) =:= 512
->
    jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_decrypt(CipherText, CipherTag, AAD, IV, CEK).

-spec content_encrypt(ENC, PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    ENC :: jose_jwe_enc:internal_state(state()),
    PlainText :: jose_aes_cbc_hmac:plain_text(),
    AAD :: jose_aes_cbc_hmac:additional_authenticated_data(),
    IV :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
    CEK :: jose_aes_cbc_hmac:aes_128_key() | jose_aes_cbc_hmac:aes_192_key() | jose_aes_cbc_hmac:aes_256_key(),
    CipherText :: jose_aes_cbc_hmac:cipher_text(),
    CipherTag :: jose_aes_cbc_hmac:aes_cbc_hmac_gmac().
content_encrypt(aes_128_cbc_hmac_sha256, PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 128 andalso
        bit_size(CEK) =:= 256
->
    jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_encrypt(PlainText, AAD, IV, CEK);
content_encrypt(aes_192_cbc_hmac_sha384, PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 128 andalso
        bit_size(CEK) =:= 384
->
    jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_encrypt(PlainText, AAD, IV, CEK);
content_encrypt(aes_256_cbc_hmac_sha512, PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 128 andalso
        bit_size(CEK) =:= 512
->
    jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_encrypt(PlainText, AAD, IV, CEK).

-spec generate_content_encryption_key(ENC) -> CEK when
    ENC :: jose_jwe_enc:internal_state(state()),
    CEK :: jose_jwe_enc:content_encryption_key().
generate_content_encryption_key(ENC) when ?is_state(ENC) ->
    KeyBitSize = key_bit_size(ENC),
    jose_csprng:random_bits(KeyBitSize).

-spec generate_nonce(ENC) -> Nonce when
    ENC :: jose_jwe_enc:internal_state(),
    Nonce :: jose_jwe_enc:nonce().
generate_nonce(ENC) when ?is_state(ENC) ->
    jose_csprng:random_bits(128).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
