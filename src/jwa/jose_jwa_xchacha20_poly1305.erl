%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305
%%% See https://tools.ietf.org/html/draft-irtf-cfrg-xchacha
%%% @end
%%% Created :  14 Sep 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_xchacha20_poly1305).

-behaviour(jose_provider).
-behaviour(jose_xchacha20_poly1305).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_xchacha20_poly1305 callbacks
-export([
    xchacha20_poly1305_decrypt/5,
    xchacha20_poly1305_encrypt/4,
    xchacha20_poly1305_authenticate/3,
    xchacha20_poly1305_verify/4
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_xchacha20_poly1305,
        priority => low,
        requirements => [
            {app, jose},
            jose_chacha20_poly1305
        ]
    }.

%%%=============================================================================
%%% jose_xchacha20_poly1305 callbacks
%%%=============================================================================

-spec xchacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, Key) -> PlainText | error when
    CipherText :: jose_xchacha20_poly1305:cipher_text(),
    CipherTag :: jose_xchacha20_poly1305:xchacha20_poly1305_mac(),
    AAD :: jose_xchacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    PlainText :: jose_xchacha20_poly1305:plain_text().
xchacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, Key) when
    is_binary(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_binary(AAD) andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    {ChaCha20Subkey, ChaCha20Nonce} = jose_jwa_xchacha20:subkey_and_nonce(Key, Nonce),
    jose_chacha20_poly1305:chacha20_poly1305_decrypt(CipherText, CipherTag, AAD, ChaCha20Nonce, ChaCha20Subkey).

-spec xchacha20_poly1305_encrypt(PlainText, AAD, Nonce, Key) -> {CipherText, CipherTag} when
    PlainText :: jose_xchacha20_poly1305:plain_text(),
    AAD :: jose_xchacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    CipherText :: jose_xchacha20_poly1305:cipher_text(),
    CipherTag :: jose_xchacha20_poly1305:xchacha20_poly1305_mac().
xchacha20_poly1305_encrypt(PlainText, AAD, Nonce, Key) when
    is_binary(PlainText) andalso
        is_binary(AAD) andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    {ChaCha20Subkey, ChaCha20Nonce} = jose_jwa_xchacha20:subkey_and_nonce(Key, Nonce),
    jose_chacha20_poly1305:chacha20_poly1305_encrypt(PlainText, AAD, ChaCha20Nonce, ChaCha20Subkey).

-spec xchacha20_poly1305_authenticate(Message, Nonce, Key) -> MAC when
    Message :: jose_xchacha20_poly1305:message(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    MAC :: jose_xchacha20_poly1305:xchacha20_poly1305_mac().
xchacha20_poly1305_authenticate(Message, Nonce, Key) when
    is_binary(Message) andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    {ChaCha20Subkey, ChaCha20Nonce} = jose_jwa_xchacha20:subkey_and_nonce(Key, Nonce),
    jose_chacha20_poly1305:chacha20_poly1305_authenticate(Message, ChaCha20Nonce, ChaCha20Subkey).

-spec xchacha20_poly1305_verify(MAC, Message, Nonce, Key) -> boolean() when
    MAC :: jose_xchacha20_poly1305:xchacha20_poly1305_mac(),
    Message :: jose_xchacha20_poly1305:message(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key().
xchacha20_poly1305_verify(MAC, Message, Nonce, Key) when
    is_binary(MAC) andalso
        is_binary(Message) andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    {ChaCha20Subkey, ChaCha20Nonce} = jose_jwa_xchacha20:subkey_and_nonce(Key, Nonce),
    jose_chacha20_poly1305:chacha20_poly1305_verify(MAC, Message, ChaCha20Nonce, ChaCha20Subkey).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
