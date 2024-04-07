%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  31 May 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_chacha20_poly1305).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type additional_authenticated_data() :: binary().
-type cipher_text() :: binary().
-type message() :: binary().
-type plain_text() :: binary().
-type chacha20_poly1305_mac() :: <<_:128>>.
-type chacha20_poly1305_nonce() :: <<_:96>>.
-type chacha20_poly1305_key() :: <<_:256>>.

-export_type([
    additional_authenticated_data/0,
    cipher_text/0,
    message/0,
    plain_text/0,
    chacha20_poly1305_mac/0,
    chacha20_poly1305_nonce/0,
    chacha20_poly1305_key/0
]).

%% Callbacks
-callback chacha20_poly1305_decrypt(CipherText, CipherTag, AAD, Nonce, Key) -> PlainText | error when
    CipherText :: jose_chacha20_poly1305:cipher_text(),
    CipherTag :: jose_chacha20_poly1305:chacha20_poly1305_mac(),
    AAD :: jose_chacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    PlainText :: jose_chacha20_poly1305:plain_text().
-callback chacha20_poly1305_encrypt(PlainText, AAD, Nonce, Key) -> {CipherText, CipherTag} when
    PlainText :: jose_chacha20_poly1305:plain_text(),
    AAD :: jose_chacha20_poly1305:additional_authenticated_data(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    CipherText :: jose_chacha20_poly1305:cipher_text(),
    CipherTag :: jose_chacha20_poly1305:chacha20_poly1305_mac().
-callback chacha20_poly1305_authenticate(Message, Nonce, Key) -> MAC when
    Message :: jose_chacha20_poly1305:message(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key(),
    MAC :: jose_chacha20_poly1305:chacha20_poly1305_mac().
-callback chacha20_poly1305_verify(MAC, Message, Nonce, Key) -> boolean() when
    MAC :: jose_chacha20_poly1305:chacha20_poly1305_mac(),
    Message :: jose_chacha20_poly1305:message(),
    Nonce :: jose_chacha20_poly1305:chacha20_poly1305_nonce(),
    Key :: jose_chacha20_poly1305:chacha20_poly1305_key().

-optional_callbacks([
    chacha20_poly1305_decrypt/5,
    chacha20_poly1305_encrypt/4,
    chacha20_poly1305_authenticate/3,
    chacha20_poly1305_verify/4
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_chacha20_poly1305 callbacks
-export([
    chacha20_poly1305_decrypt/5,
    chacha20_poly1305_encrypt/4,
    chacha20_poly1305_authenticate/3,
    chacha20_poly1305_verify/4
]).

%% Macros
-define(TV_PlainText(), <<"abcdefghijklmnopqrstuvwxyz">>).
-define(TV_AAD(), <<"0123456789">>).
-define(TV_ChaCha20_Poly1305_Nonce(), ?b16d("000000000000000000000000")).
-define(TV_ChaCha20_Poly1305_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_ChaCha20_Poly1305_CipherText(), ?b16d("fe6584da30375f12f1d0fc101e43677dba7d5ad43d9512116bbc")).
-define(TV_ChaCha20_Poly1305_CipherTag(), ?b16d("f2d4cb28e1e2cdddb1e90f307ef6b8bf")).
% 2 x 128-bit AES blocks
-define(TV_Message(), <<"abcdefghijklmnopqrstuvwxyz012345">>).
-define(TV_ChaCha20_Poly1305_MAC(), ?b16d("79b048dec10fbbdb0a46ac011cc6827b")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{chacha20_poly1305_decrypt, 5}, [
                {jose_chacha20, [{chacha20_exor, 4}]}, {jose_poly1305, [{poly1305_mac, 2}]}
            ]},
            {{chacha20_poly1305_encrypt, 4}, [
                {jose_chacha20, [{chacha20_exor, 4}]}, {jose_poly1305, [{poly1305_mac, 2}]}
            ]},
            {{chacha20_poly1305_authenticate, 3}, [
                {jose_chacha20, [{chacha20_exor, 4}]}, {jose_poly1305, [{poly1305_mac, 2}]}
            ]},
            {{chacha20_poly1305_verify, 4}, [
                {jose_chacha20, [{chacha20_exor, 4}]}, {jose_poly1305, [{poly1305_mac, 2}]}
            ]}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, chacha20_poly1305_decrypt, 5) ->
    CipherText = ?TV_ChaCha20_Poly1305_CipherText(),
    CipherTag = ?TV_ChaCha20_Poly1305_CipherTag(),
    AAD = ?TV_AAD(),
    Nonce = ?TV_ChaCha20_Poly1305_Nonce(),
    Key = ?TV_ChaCha20_Poly1305_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, chacha20_poly1305_decrypt, [CipherText, CipherTag, AAD, Nonce, Key]);
support_check(Module, chacha20_poly1305_encrypt, 4) ->
    PlainText = ?TV_PlainText(),
    AAD = ?TV_AAD(),
    Nonce = ?TV_ChaCha20_Poly1305_Nonce(),
    Key = ?TV_ChaCha20_Poly1305_Key(),
    CipherText = ?TV_ChaCha20_Poly1305_CipherText(),
    CipherTag = ?TV_ChaCha20_Poly1305_CipherTag(),
    ?expect({CipherText, CipherTag}, Module, chacha20_poly1305_encrypt, [PlainText, AAD, Nonce, Key]);
support_check(Module, chacha20_poly1305_authenticate, 3) ->
    Message = ?TV_Message(),
    Nonce = ?TV_ChaCha20_Poly1305_Nonce(),
    Key = ?TV_ChaCha20_Poly1305_Key(),
    MAC = ?TV_ChaCha20_Poly1305_MAC(),
    ?expect(MAC, Module, chacha20_poly1305_authenticate, [Message, Nonce, Key]);
support_check(Module, chacha20_poly1305_verify, 4) ->
    MAC = ?TV_ChaCha20_Poly1305_MAC(),
    Message = ?TV_Message(),
    Nonce = ?TV_ChaCha20_Poly1305_Nonce(),
    Key = ?TV_ChaCha20_Poly1305_Key(),
    ?expect(true, Module, chacha20_poly1305_verify, [MAC, Message, Nonce, Key]).

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
    ?resolve([CipherText, CipherTag, AAD, Nonce, Key]).

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
    ?resolve([PlainText, AAD, Nonce, Key]).

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
    ?resolve([Message, Nonce, Key]).

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
    ?resolve([MAC, Message, Nonce, Key]).
