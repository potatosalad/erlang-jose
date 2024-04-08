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
%%% Created :  31 May 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwe_enc_c20p).

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
-type state() :: chacha20_poly1305.

-export_type([
    state/0
]).

%% Macros
-define(is_state(X), ((X) =:= chacha20_poly1305)).

%%%=============================================================================
%%% jose_jwe callbacks
%%%=============================================================================

from_map(F = #{<<"enc">> := <<"C20P">>}) ->
    {chacha20_poly1305, maps:remove(<<"enc">>, F)}.

to_map(chacha20_poly1305, F) ->
    F#{<<"enc">> => <<"C20P">>}.

%%%=============================================================================
%%% jose_jwe_enc callbacks
%%%=============================================================================

-spec algorithm(ENC) -> Algorithm when
    ENC :: jose_jwe_enc:internal_state(state()),
    Algorithm :: jose_jwe_enc:algorithm().
algorithm(chacha20_poly1305) -> <<"C20P">>.

-spec key_bit_size(ENC) -> KeyBitSize when
    ENC :: jose_jwe_enc:internal_state(state()),
    KeyBitSize :: jose_jwe_enc:key_bit_size().
key_bit_size(chacha20_poly1305) -> 256.

-spec content_decrypt(ENC, CipherText, CipherTag, AAD, Nonce, CEK) -> PlainText | error when
    ENC :: jose_jwe_enc:internal_state(state()),
    CipherText :: jose_chacha20_poly1305:cipher_text(),
    CipherTag :: jose_chacha20_poly1305:chacha20_poly1305_mac(),
    AAD :: jose_chacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    CEK :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    PlainText :: jose_chacha20_poly1305:plain_text().
content_decrypt(chacha20_poly1305, CipherText, CipherTag, AAD, Nonce, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(CEK) =:= 256
->
    jose_chacha20_poly1305:chacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, CEK).

-spec content_encrypt(ENC, PlainText, AAD, Nonce, CEK) -> {CipherText, CipherTag} when
    ENC :: jose_jwe_enc:internal_state(state()),
    PlainText :: jose_chacha20_poly1305:plain_text(),
    AAD :: jose_chacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    CEK :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    CipherText :: jose_chacha20_poly1305:cipher_text(),
    CipherTag :: jose_chacha20_poly1305:chacha20_poly1305_mac().
content_encrypt(chacha20_poly1305, PlainText, AAD, Nonce, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(CEK) =:= 256
->
    jose_chacha20_poly1305:chacha20_poly1305_encrypt(PlainText, AAD, Nonce, CEK).

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
