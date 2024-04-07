%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwe_enc_aes_gcm).

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
-type state() :: aes_128_gcm | aes_192_gcm | aes_256_gcm.

-export_type([
    state/0
]).

%% Macros
-define(is_state(X), ((X) =:= aes_128_gcm orelse (X) =:= aes_192_gcm orelse (X) =:= aes_256_gcm)).

%%%=============================================================================
%% jose_jwe callbacks
%%%=============================================================================

from_map(F = #{<<"enc">> := <<"A128GCM">>}) ->
    {aes_128_gcm, maps:remove(<<"enc">>, F)};
from_map(F = #{<<"enc">> := <<"A192GCM">>}) ->
    {aes_192_gcm, maps:remove(<<"enc">>, F)};
from_map(F = #{<<"enc">> := <<"A256GCM">>}) ->
    {aes_256_gcm, maps:remove(<<"enc">>, F)}.

to_map(aes_128_gcm, F) ->
    F#{<<"enc">> => <<"A128GCM">>};
to_map(aes_192_gcm, F) ->
    F#{<<"enc">> => <<"A192GCM">>};
to_map(aes_256_gcm, F) ->
    F#{<<"enc">> => <<"A256GCM">>}.

%%%=============================================================================
%% jose_jwe_enc callbacks
%%%=============================================================================

-spec algorithm(ENC) -> Algorithm when
    ENC :: jose_jwe_enc:internal_state(state()),
    Algorithm :: jose_jwe_enc:algorithm().
algorithm(aes_128_gcm) -> <<"A128GCM">>;
algorithm(aes_192_gcm) -> <<"A192GCM">>;
algorithm(aes_256_gcm) -> <<"A256GCM">>.

-spec key_bit_size(ENC) -> KeyBitSize when
    ENC :: jose_jwe_enc:internal_state(state()),
    KeyBitSize :: jose_jwe_enc:key_bit_size().
key_bit_size(aes_128_gcm) -> 128;
key_bit_size(aes_192_gcm) -> 192;
key_bit_size(aes_256_gcm) -> 256.

-spec content_decrypt(ENC, CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    ENC :: jose_jwe_enc:internal_state(state()),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_128_key() | jose_aes_gcm:aes_192_key() | jose_aes_gcm:aes_256_key(),
    PlainText :: jose_aes_gcm:plain_text().
content_decrypt(aes_128_gcm, CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 128
->
    jose_aes_gcm:aes_128_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK);
content_decrypt(aes_192_gcm, CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 192
->
    jose_aes_gcm:aes_192_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK);
content_decrypt(aes_256_gcm, CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 256
->
    jose_aes_gcm:aes_256_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK).

-spec content_encrypt(ENC, PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    ENC :: jose_jwe_enc:internal_state(state()),
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_128_key() | jose_aes_gcm:aes_192_key() | jose_aes_gcm:aes_256_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().
content_encrypt(aes_128_gcm, PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 128
->
    jose_aes_gcm:aes_128_gcm_encrypt(PlainText, AAD, IV, CEK);
content_encrypt(aes_192_gcm, PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 192
->
    jose_aes_gcm:aes_192_gcm_encrypt(PlainText, AAD, IV, CEK);
content_encrypt(aes_256_gcm, PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 256
->
    jose_aes_gcm:aes_256_gcm_encrypt(PlainText, AAD, IV, CEK).

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
    jose_csprng:random_bits(96).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
