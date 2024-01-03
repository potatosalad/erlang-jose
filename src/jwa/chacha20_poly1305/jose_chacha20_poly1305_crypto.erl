%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Aug 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_chacha20_poly1305_crypto).

-behaviour(jose_provider).
-behaviour(jose_chacha20_poly1305).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_chacha20_poly1305 callbacks
-export([
    chacha20_poly1305_decrypt/5,
    chacha20_poly1305_encrypt/4,
    chacha20_poly1305_authenticate/3,
    chacha20_poly1305_verify/4
]).
%% Internal API
-export([poly1305_key_gen/2]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_chacha20_poly1305,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%====================================================================
%% jose_chacha20_poly1305 callbacks
%%====================================================================

-spec chacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, Key) -> PlainText | error when
    CipherText :: jose_chacha20_poly1305:cipher_text(),
    CipherTag :: jose_chacha20_poly1305:chacha20_poly1305_mac(),
    AAD :: jose_chacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    PlainText :: jose_chacha20_poly1305:plain_text().
chacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, Key) when
    is_binary(CipherText) andalso
        bit_size(CipherTag) =:= 128 andalso
        is_binary(AAD) andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, CipherText, AAD, CipherTag, false).

-spec chacha20_poly1305_encrypt(PlainText, AAD, Nonce, Key) -> {CipherText, CipherTag} when
    PlainText :: jose_chacha20_poly1305:plain_text(),
    AAD :: jose_chacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    CipherText :: jose_chacha20_poly1305:cipher_text(),
    CipherTag :: jose_chacha20_poly1305:chacha20_poly1305_mac().
chacha20_poly1305_encrypt(PlainText, AAD, Nonce, Key) when
    is_binary(PlainText) andalso
        is_binary(AAD) andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, PlainText, AAD, true).

-spec chacha20_poly1305_authenticate(Message, Nonce, Key) -> MAC when
    Message :: jose_chacha20_poly1305:message(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    MAC :: jose_chacha20_poly1305:chacha20_poly1305_mac().
chacha20_poly1305_authenticate(Message, Nonce, Key) when
    is_binary(Message) andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    OTK = poly1305_key_gen(Nonce, Key),
    jose_poly1305:poly1305_mac(Message, OTK).

-spec chacha20_poly1305_verify(MAC, Message, Nonce, Key) -> boolean() when
    MAC :: jose_chacha20_poly1305:chacha20_poly1305_mac(),
    Message :: jose_chacha20_poly1305:message(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key().
chacha20_poly1305_verify(MAC, Message, Nonce, Key) when
    is_binary(MAC) andalso
        is_binary(Message) andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    Challenge = chacha20_poly1305_authenticate(Message, Nonce, Key),
    jose_jwa:constant_time_compare(MAC, Challenge).

%%====================================================================
%% Internal API Functions
%%====================================================================

-spec poly1305_key_gen(Nonce, Key) -> OneTimeKey when
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    OneTimeKey :: jose_poly1305:poly1305_one_time_key().
poly1305_key_gen(<<Nonce:96/bitstring>>, <<Key:256/bitstring>>) ->
    crypto:crypto_one_time(chacha20, Key, <<0:32, Nonce:96/bits>>, <<0:256>>, true).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
