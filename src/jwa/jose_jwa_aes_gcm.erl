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
%%% Created :  03 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_aes_gcm).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-behaviour(jose_provider).
-behaviour(jose_aes_gcm).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_aes_gcm callbacks
-export([
    aes_128_gcm_decrypt/5,
    aes_128_gcm_encrypt/4,
    aes_192_gcm_decrypt/5,
    aes_192_gcm_encrypt/4,
    aes_256_gcm_decrypt/5,
    aes_256_gcm_encrypt/4
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_aes_gcm,
        priority => low,
        requirements => [
            {app, crypto},
            crypto,
            {app, jose},
            jose_jwa_aes
        ]
    }.

%%%=============================================================================
%%% jose_aes_gcm callbacks
%%%=============================================================================

-spec aes_128_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_128_key(),
    PlainText :: jose_aes_gcm:plain_text().
aes_128_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 128
->
    jose_jwa_aes:block_decrypt({aes_gcm, 128}, CEK, IV, {AAD, CipherText, CipherTag}).

-spec aes_128_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_128_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().
aes_128_gcm_encrypt(PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 128
->
    jose_jwa_aes:block_encrypt({aes_gcm, 128}, CEK, IV, {AAD, PlainText}).

-spec aes_192_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_192_key(),
    PlainText :: jose_aes_gcm:plain_text().
aes_192_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 192
->
    jose_jwa_aes:block_decrypt({aes_gcm, 192}, CEK, IV, {AAD, CipherText, CipherTag}).

-spec aes_192_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_192_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().
aes_192_gcm_encrypt(PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 192
->
    jose_jwa_aes:block_encrypt({aes_gcm, 192}, CEK, IV, {AAD, PlainText}).

-spec aes_256_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_256_key(),
    PlainText :: jose_aes_gcm:plain_text().
aes_256_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) when
    is_bitstring(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 256
->
    jose_jwa_aes:block_decrypt({aes_gcm, 256}, CEK, IV, {AAD, CipherText, CipherTag}).

-spec aes_256_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_256_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().
aes_256_gcm_encrypt(PlainText, AAD, IV, CEK) when
    is_bitstring(PlainText) andalso
        is_bitstring(AAD) andalso
        bit_size(IV) =:= 96 andalso
        bit_size(CEK) =:= 256
->
    jose_jwa_aes:block_encrypt({aes_gcm, 256}, CEK, IV, {AAD, PlainText}).
