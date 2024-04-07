%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  03 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_aes_cbc).

-behaviour(jose_provider).
-behaviour(jose_aes_cbc).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_aes_cbc callbacks
-export([
    aes_128_cbc_decrypt/3,
    aes_128_cbc_encrypt/3,
    aes_192_cbc_decrypt/3,
    aes_192_cbc_encrypt/3,
    aes_256_cbc_decrypt/3,
    aes_256_cbc_encrypt/3
]).

%%====================================================================
%% jose_support_impl callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_aes_cbc,
        priority => low,
        requirements => [
            {app, crypto},
            crypto,
            {app, jose},
            jose_jwa_aes
        ]
    }.

%%====================================================================
%% jose_aes_cbc callbacks
%%====================================================================

-spec aes_128_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
    CipherText :: jose_aes_cbc:cipher_text(),
    IV :: jose_aes_cbc:aes_cbc_iv(),
    CEK :: jose_aes_cbc:aes_128_key(),
    PlainText :: jose_aes_cbc:plain_text().
aes_128_cbc_decrypt(CipherText, IV, CEK) when
    bit_size(CipherText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 128
->
    jose_jwa_aes:block_decrypt({aes_cbc, 128}, CEK, IV, CipherText).

-spec aes_128_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
    PlainText :: jose_aes_cbc:plain_text(),
    IV :: jose_aes_cbc:aes_cbc_iv(),
    CEK :: jose_aes_cbc:aes_128_key(),
    CipherText :: jose_aes_cbc:cipher_text().
aes_128_cbc_encrypt(PlainText, IV, CEK) when
    bit_size(PlainText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 128
->
    jose_jwa_aes:block_encrypt({aes_cbc, 128}, CEK, IV, PlainText).

-spec aes_192_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
    CipherText :: jose_aes_cbc:cipher_text(),
    IV :: jose_aes_cbc:aes_cbc_iv(),
    CEK :: jose_aes_cbc:aes_192_key(),
    PlainText :: jose_aes_cbc:plain_text().
aes_192_cbc_decrypt(CipherText, IV, CEK) when
    bit_size(CipherText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 192
->
    jose_jwa_aes:block_decrypt({aes_cbc, 192}, CEK, IV, CipherText).

-spec aes_192_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
    PlainText :: jose_aes_cbc:plain_text(),
    IV :: jose_aes_cbc:aes_cbc_iv(),
    CEK :: jose_aes_cbc:aes_192_key(),
    CipherText :: jose_aes_cbc:cipher_text().
aes_192_cbc_encrypt(PlainText, IV, CEK) when
    bit_size(PlainText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 192
->
    jose_jwa_aes:block_encrypt({aes_cbc, 192}, CEK, IV, PlainText).

-spec aes_256_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
    CipherText :: jose_aes_cbc:cipher_text(),
    IV :: jose_aes_cbc:aes_cbc_iv(),
    CEK :: jose_aes_cbc:aes_256_key(),
    PlainText :: jose_aes_cbc:plain_text().
aes_256_cbc_decrypt(CipherText, IV, CEK) when
    bit_size(CipherText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 256
->
    jose_jwa_aes:block_decrypt({aes_cbc, 256}, CEK, IV, CipherText).

-spec aes_256_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
    PlainText :: jose_aes_cbc:plain_text(),
    IV :: jose_aes_cbc:aes_cbc_iv(),
    CEK :: jose_aes_cbc:aes_256_key(),
    CipherText :: jose_aes_cbc:cipher_text().
aes_256_cbc_encrypt(PlainText, IV, CEK) when
    bit_size(PlainText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 256
->
    jose_jwa_aes:block_encrypt({aes_cbc, 256}, CEK, IV, PlainText).
