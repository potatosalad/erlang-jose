%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  31 Aug 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_xchacha20_poly1305_libsodium).

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
-export([poly1305_key_gen/2]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_xchacha20_poly1305,
        priority => normal,
        requirements => [
            {app, libsodium},
            libsodium_crypto_aead_xchacha20poly1305,
            libsodium_crypto_onetimeauth_poly1305,
            libsodium_crypto_stream_xchacha20
        ]
    }.

%%====================================================================
%% jose_xchacha20_poly1305 callbacks
%%====================================================================

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
    case libsodium_crypto_aead_xchacha20poly1305:ietf_decrypt_detached(CipherText, CipherTag, AAD, Nonce, Key) of
        -1 ->
            error;
        PlainText when is_binary(PlainText) ->
            PlainText
    end.

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
    libsodium_crypto_aead_xchacha20poly1305:ietf_encrypt_detached(PlainText, AAD, Nonce, Key).

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
    OTK = poly1305_key_gen(Nonce, Key),
    libsodium_crypto_onetimeauth_poly1305:crypto_onetimeauth_poly1305(Message, OTK).

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
    OTK = poly1305_key_gen(Nonce, Key),
    case libsodium_crypto_onetimeauth_poly1305:verify(MAC, Message, OTK) of
        0 ->
            true;
        _ ->
            false
    end.

%%====================================================================
%% Internal API Functions
%%====================================================================

-spec poly1305_key_gen(Nonce, Key) -> OneTimeKey when
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    OneTimeKey :: jose_poly1305:poly1305_one_time_key().
poly1305_key_gen(<<Nonce:192/bitstring>>, <<Key:256/bitstring>>) ->
    libsodium_crypto_stream_xchacha20:xor_ic(<<0:256>>, Nonce, 0, Key).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
