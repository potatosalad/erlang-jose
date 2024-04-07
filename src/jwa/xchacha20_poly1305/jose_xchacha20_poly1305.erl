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
%%% Created :  14 Sep 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_xchacha20_poly1305).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type additional_authenticated_data() :: binary().
-type cipher_text() :: binary().
-type message() :: binary().
-type plain_text() :: binary().
-type xchacha20_poly1305_mac() :: <<_:128>>.
-type xchacha20_poly1305_nonce() :: <<_:192>>.
-type xchacha20_poly1305_key() :: <<_:256>>.

-export_type([
    additional_authenticated_data/0,
    cipher_text/0,
    message/0,
    plain_text/0,
    xchacha20_poly1305_mac/0,
    xchacha20_poly1305_nonce/0,
    xchacha20_poly1305_key/0
]).

%% Callbacks
-callback xchacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, Key) -> PlainText | error when
    CipherText :: jose_xchacha20_poly1305:cipher_text(),
    CipherTag :: jose_xchacha20_poly1305:xchacha20_poly1305_mac(),
    AAD :: jose_xchacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    PlainText :: jose_xchacha20_poly1305:plain_text().
-callback xchacha20_poly1305_encrypt(PlainText, AAD, Nonce, Key) -> {CipherText, CipherTag} when
    PlainText :: jose_xchacha20_poly1305:plain_text(),
    AAD :: jose_xchacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    CipherText :: jose_xchacha20_poly1305:cipher_text(),
    CipherTag :: jose_xchacha20_poly1305:xchacha20_poly1305_mac().
-callback xchacha20_poly1305_authenticate(Message, Nonce, Key) -> MAC when
    Message :: jose_xchacha20_poly1305:message(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key(),
    MAC :: jose_xchacha20_poly1305:xchacha20_poly1305_mac().
-callback xchacha20_poly1305_verify(MAC, Message, Nonce, Key) -> boolean() when
    MAC :: jose_xchacha20_poly1305:xchacha20_poly1305_mac(),
    Message :: jose_xchacha20_poly1305:message(),
    Nonce :: jose_xchacha20_poly1305:xchacha20_poly1305_nonce(),
    Key :: jose_xchacha20_poly1305:xchacha20_poly1305_key().

-optional_callbacks([
    xchacha20_poly1305_decrypt/5,
    xchacha20_poly1305_encrypt/4,
    xchacha20_poly1305_authenticate/3,
    xchacha20_poly1305_verify/4
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_xchacha20_poly1305 callbacks
-export([
    xchacha20_poly1305_decrypt/5,
    xchacha20_poly1305_encrypt/4,
    xchacha20_poly1305_authenticate/3,
    xchacha20_poly1305_verify/4
]).

%% Macros
-define(TV_PlainText(), <<"abcdefghijklmnopqrstuvwxyz">>).
-define(TV_AAD(), <<"0123456789">>).
-define(TV_XChaCha20_Poly1305_Nonce(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_XChaCha20_Poly1305_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_XChaCha20_Poly1305_CipherText(), ?b16d("19fcf5ed8046ea17b08b98a9d85a70389e6ad24a34ffefd5a3a7")).
-define(TV_XChaCha20_Poly1305_CipherTag(), ?b16d("b91ed45dc350f05f7fafa5a07169504b")).
% 2 x 128-bit AES blocks
-define(TV_Message(), <<"abcdefghijklmnopqrstuvwxyz012345">>).
-define(TV_XChaCha20_Poly1305_MAC(), ?b16d("42391ecd1b705e19048692c1cc757a8f")).

%%%=============================================================================
%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{xchacha20_poly1305_decrypt, 5}, [
                {jose_chacha20_poly1305, [{chacha20_poly1305_decrypt, 5}]}, {jose_hchacha20, [{hchacha20_subkey, 2}]}
            ]},
            {{xchacha20_poly1305_encrypt, 4}, [
                {jose_chacha20_poly1305, [{chacha20_poly1305_encrypt, 4}]}, {jose_hchacha20, [{hchacha20_subkey, 2}]}
            ]},
            {{xchacha20_poly1305_authenticate, 3}, [
                {jose_chacha20_poly1305, [{chacha20_poly1305_authenticate, 3}]},
                {jose_hchacha20, [{hchacha20_subkey, 2}]}
            ]},
            {{xchacha20_poly1305_verify, 4}, [
                {jose_chacha20_poly1305, [{chacha20_poly1305_verify, 4}]}, {jose_hchacha20, [{hchacha20_subkey, 2}]}
            ]}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, xchacha20_poly1305_decrypt, 5) ->
    CipherText = ?TV_XChaCha20_Poly1305_CipherText(),
    CipherTag = ?TV_XChaCha20_Poly1305_CipherTag(),
    AAD = ?TV_AAD(),
    Nonce = ?TV_XChaCha20_Poly1305_Nonce(),
    Key = ?TV_XChaCha20_Poly1305_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, xchacha20_poly1305_decrypt, [CipherText, CipherTag, AAD, Nonce, Key]);
support_check(Module, xchacha20_poly1305_encrypt, 4) ->
    PlainText = ?TV_PlainText(),
    AAD = ?TV_AAD(),
    Nonce = ?TV_XChaCha20_Poly1305_Nonce(),
    Key = ?TV_XChaCha20_Poly1305_Key(),
    CipherText = ?TV_XChaCha20_Poly1305_CipherText(),
    CipherTag = ?TV_XChaCha20_Poly1305_CipherTag(),
    ?expect({CipherText, CipherTag}, Module, xchacha20_poly1305_encrypt, [PlainText, AAD, Nonce, Key]);
support_check(Module, xchacha20_poly1305_authenticate, 3) ->
    Message = ?TV_Message(),
    Nonce = ?TV_XChaCha20_Poly1305_Nonce(),
    Key = ?TV_XChaCha20_Poly1305_Key(),
    MAC = ?TV_XChaCha20_Poly1305_MAC(),
    ?expect(MAC, Module, xchacha20_poly1305_authenticate, [Message, Nonce, Key]);
support_check(Module, xchacha20_poly1305_verify, 4) ->
    MAC = ?TV_XChaCha20_Poly1305_MAC(),
    Message = ?TV_Message(),
    Nonce = ?TV_XChaCha20_Poly1305_Nonce(),
    Key = ?TV_XChaCha20_Poly1305_Key(),
    ?expect(true, Module, xchacha20_poly1305_verify, [MAC, Message, Nonce, Key]).

%%%=============================================================================
%% jose_xchacha20_poly1305 callbacks
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
    ?resolve([CipherText, CipherTag, AAD, Nonce, Key]).

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
    ?resolve([PlainText, AAD, Nonce, Key]).

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
    ?resolve([Message, Nonce, Key]).

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
    ?resolve([MAC, Message, Nonce, Key]).
