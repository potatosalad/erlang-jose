%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
%%%-----------------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%%-----------------------------------------------------------------------------
-module(jose_crypto_compat).

-include("jose_compat.hrl").

%% API
-export([crypto_init/4]).
-export([crypto_one_time/4]).
-export([crypto_one_time/5]).
-export([crypto_update_encrypt/2]).
-export([mac/3]).
-export([mac/4]).
-export([mac/5]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

%% "New API" for OTP 23 and higher
-ifdef(JOSE_CRYPTO_OTP_23).

crypto_init(Cipher, Key, IV, FlagOrOptions) ->
    crypto:crypto_init(Cipher, Key, IV, FlagOrOptions).

crypto_one_time(Cipher, Key, Data, FlagOrOptions) ->
    crypto:crypto_one_time(Cipher, Key, Data, FlagOrOptions).

crypto_one_time(Cipher, Key, IV, {AAD, PlainText}, FlagOrOptions) ->
    crypto:crypto_one_time_aead(Cipher, Key, IV, PlainText, AAD, FlagOrOptions);
crypto_one_time(Cipher, Key, IV, {AAD, PlainText, TagOrTagLength}, FlagOrOptions) ->
    crypto:crypto_one_time_aead(Cipher, Key, IV, PlainText, AAD, TagOrTagLength, FlagOrOptions);
crypto_one_time(Cipher, Key, IV, Data, FlagOrOptions) ->
    crypto:crypto_one_time(Cipher, Key, IV, Data, FlagOrOptions).

crypto_update_encrypt(State, Data) ->
    Result = crypto:crypto_update(State, Data),
    {State, Result}.

mac(Type, Key, Data) ->
    crypto:mac(Type, Key, Data).

mac(Type, SubType, Key, Data) ->
    crypto:mac(Type, SubType, Key, Data).

mac(Type, SubType, Key, Data, MacLength) ->
    crypto:macN(Type, SubType, Key, Data, MacLength).

%% "Old API" for OTP 22 and earlier
-else.

crypto_init(Cipher, Key, IV, _FlagOrOptions) ->
    crypto:stream_init(legacy_cipher_iv(Cipher), Key, IV).

crypto_one_time(Cipher, Key, Data, true) ->
    crypto:block_encrypt(legacy_cipher_no_iv(Cipher), Key, Data);
crypto_one_time(Cipher, Key, Data, false) ->
    crypto:block_decrypt(legacy_cipher_no_iv(Cipher), Key, Data).

crypto_one_time(Cipher, Key, IV, Data, true) ->
    crypto:block_encrypt(legacy_cipher_iv(Cipher), Key, IV, Data);
crypto_one_time(Cipher, Key, IV, Data, false) ->
    crypto:block_decrypt(legacy_cipher_iv(Cipher), Key, IV, Data).

crypto_update_encrypt(State, Data) ->
    crypto:stream_encrypt(State, Data).

mac(poly1305, Key, Data) ->
    crypto:poly1305(Key, Data).

mac(hmac, SubType, Key, Data) ->
    crypto:hmac(SubType, Key, Data).

mac(hmac, SubType, Key, Data, MacLength) ->
    crypto:hmac(SubType, Key, Data, MacLength).

-endif.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

-ifndef(JOSE_CRYPTO_OTP_23).

legacy_cipher_no_iv(aes_128_ecb) -> aes_ecb;
legacy_cipher_no_iv(aes_192_ecb) -> aes_ecb;
legacy_cipher_no_iv(aes_256_ecb) -> aes_ecb;
legacy_cipher_no_iv(Cipher) -> Cipher.

legacy_cipher_iv(aes_128_cbc) -> aes_cbc128;
legacy_cipher_iv(aes_192_cbc) -> aes_cbc192;
legacy_cipher_iv(aes_256_cbc) -> aes_cbc256;
legacy_cipher_iv(aes_128_ctr) -> aes_ctr;
legacy_cipher_iv(aes_192_ctr) -> aes_ctr;
legacy_cipher_iv(aes_256_ctr) -> aes_ctr;
legacy_cipher_iv(Cipher) -> Cipher.

-endif.
