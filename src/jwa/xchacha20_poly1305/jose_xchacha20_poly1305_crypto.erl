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
%%% Created :  14 Sep 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_xchacha20_poly1305_crypto).

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
%% Internal API
-export([
    poly1305_key_gen/2,
    xchacha20_subkey_and_nonce/2
]).

% %% Types
% -type chacha20_key() :: <<_:256>>.
% -type chacha20_nonce() :: <<_:96>>.
% -type hchacha20_nonce() :: <<_:128>>.
% -type hchacha20_block() :: <<_:256>>.
% -type poly1305_otk() :: <<_:256>>.
% -type xchacha20_nonce() :: <<_:192>>.

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_xchacha20_poly1305,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
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
    {C20PKey, C20PNonce} = xchacha20_subkey_and_nonce(Key, Nonce),
    crypto:crypto_one_time_aead(chacha20_poly1305, C20PKey, C20PNonce, CipherText, AAD, CipherTag, false).

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
    {C20PKey, C20PNonce} = xchacha20_subkey_and_nonce(Key, Nonce),
    crypto:crypto_one_time_aead(chacha20_poly1305, C20PKey, C20PNonce, PlainText, AAD, true).

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
    {C20PKey, C20PNonce} = xchacha20_subkey_and_nonce(Key, Nonce),
    OTK = poly1305_key_gen(C20PNonce, C20PKey),
    jose_poly1305:poly1305_mac(Message, OTK).

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
    Challenge = xchacha20_poly1305_authenticate(Message, Nonce, Key),
    jose_jwa:constant_time_compare(MAC, Challenge).

%%%=============================================================================
%%% Internal API Functions
%%%=============================================================================

%% @private
-spec poly1305_key_gen(Nonce, Key) -> OneTimeKey when
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    OneTimeKey :: jose_poly1305:poly1305_one_time_key().
poly1305_key_gen(<<Nonce:96/bits>>, <<Key:256/bits>>) ->
    crypto:crypto_one_time(chacha20, Key, <<0:32, Nonce:96/bits>>, <<0:256>>, true).

%% @private
-spec xchacha20_subkey_and_nonce(Key, Nonce) -> {C20PKey, C20PNonce} when
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    C20PKey :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    C20PNonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce().
xchacha20_subkey_and_nonce(<<Key:256/bits>>, <<Nonce0:128/bits, Nonce1:64/bits>>) ->
    C20PNonce = <<0:32, Nonce1:64/bits>>,
    C20PKey = jose_hchacha20:hchacha20_subkey(Nonce0, Key),
    {C20PKey, C20PNonce}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
