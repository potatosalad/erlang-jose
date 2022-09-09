%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  03 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_aes_gcm).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type additional_authenticated_data() :: binary().
-type plain_text() :: binary().
-type cipher_text() :: binary().
-type aes_gcm_gmac() :: <<_:128>>.
-type aes_gcm_iv() :: <<_:96>>.
-type aes_128_key() :: <<_:128>>.
-type aes_192_key() :: <<_:192>>.
-type aes_256_key() :: <<_:256>>.

-export_type([
    additional_authenticated_data/0,
    plain_text/0,
    cipher_text/0,
    aes_gcm_gmac/0,
    aes_gcm_iv/0,
    aes_128_key/0,
    aes_192_key/0,
    aes_256_key/0
]).

%% Callbacks
-callback aes_128_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_128_key(),
    PlainText :: jose_aes_gcm:plain_text().
-callback aes_128_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_128_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().
-callback aes_192_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_192_key(),
    PlainText :: jose_aes_gcm:plain_text().
-callback aes_192_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_192_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().
-callback aes_256_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_256_key(),
    PlainText :: jose_aes_gcm:plain_text().
-callback aes_256_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
    PlainText :: jose_aes_gcm:plain_text(),
    AAD :: jose_aes_gcm:additional_authenticated_data(),
    IV :: jose_aes_gcm:aes_gcm_iv(),
    CEK :: jose_aes_gcm:aes_256_key(),
    CipherText :: jose_aes_gcm:cipher_text(),
    CipherTag :: jose_aes_gcm:aes_gcm_gmac().

-optional_callbacks([
    aes_128_gcm_decrypt/5,
    aes_128_gcm_encrypt/4,
    aes_192_gcm_decrypt/5,
    aes_192_gcm_encrypt/4,
    aes_256_gcm_decrypt/5,
    aes_256_gcm_encrypt/4
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_aes_gcm callbacks
-export([
    aes_128_gcm_decrypt/5,
    aes_128_gcm_encrypt/4,
    aes_192_gcm_decrypt/5,
    aes_192_gcm_encrypt/4,
    aes_256_gcm_decrypt/5,
    aes_256_gcm_encrypt/4
]).

%% Macros
-define(TV_PlainText(), <<"abcdefghijklmnopqrstuvwxyz">>).
-define(TV_AAD(), <<"0123456789">>).
-define(TV_AES_GCM_IV(), ?b16d("000000000000000000000000")).
-define(TV_AES_128_GCM_Key(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_GCM_CipherText(), ?b16d("62eab9aa05d0c4fa9a42a9d51cdc910886e7d9df3c3d2e5b8e87")).
-define(TV_AES_128_GCM_CipherTag(), ?b16d("998c09448dd7ca8c1d551e9d1f04c463")).
-define(TV_AES_192_GCM_Key(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_AES_192_GCM_CipherText(), ?b16d("f985471862969929754c152fe9de99705b46e0921743991fa796")).
-define(TV_AES_192_GCM_CipherTag(), ?b16d("fa2713924138c099fc78bb545e000dc1")).
-define(TV_AES_256_GCM_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_256_GCM_CipherText(), ?b16d("afc5235928060c066e24aebfd79df268031270be42d05d0ca8d8")).
-define(TV_AES_256_GCM_CipherTag(), ?b16d("d55b76f3438f51441eedd65413dafada")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{aes_128_gcm_decrypt, 5}, [
                {jose_aes_ctr, [{aes_128_ctr_stream_init, 2}, {aes_128_ctr_stream_exor, 2}, {aes_128_ctr_stream_final, 1}]}
            ]},
            {{aes_128_gcm_encrypt, 4}, [
                {jose_aes_ctr, [{aes_128_ctr_stream_init, 2}, {aes_128_ctr_stream_exor, 2}, {aes_128_ctr_stream_final, 1}]}
            ]},
            {{aes_192_gcm_decrypt, 5}, [
                {jose_aes_ctr, [{aes_192_ctr_stream_init, 2}, {aes_192_ctr_stream_exor, 2}, {aes_192_ctr_stream_final, 1}]}
            ]},
            {{aes_192_gcm_encrypt, 4}, [
                {jose_aes_ctr, [{aes_192_ctr_stream_init, 2}, {aes_192_ctr_stream_exor, 2}, {aes_192_ctr_stream_final, 1}]}
            ]},
            {{aes_256_gcm_decrypt, 5}, [
                {jose_aes_ctr, [{aes_256_ctr_stream_init, 2}, {aes_256_ctr_stream_exor, 2}, {aes_256_ctr_stream_final, 1}]}
            ]},
            {{aes_256_gcm_encrypt, 4}, [
                {jose_aes_ctr, [{aes_256_ctr_stream_init, 2}, {aes_256_ctr_stream_exor, 2}, {aes_256_ctr_stream_final, 1}]}
            ]}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, aes_128_gcm_decrypt, 5) ->
    CipherText = ?TV_AES_128_GCM_CipherText(),
    CipherTag = ?TV_AES_128_GCM_CipherTag(),
    AAD = ?TV_AAD(),
    IV = ?TV_AES_GCM_IV(),
    CEK = ?TV_AES_128_GCM_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, aes_128_gcm_decrypt, [CipherText, CipherTag, AAD, IV, CEK]);
support_check(Module, aes_128_gcm_encrypt, 4) ->
    PlainText = ?TV_PlainText(),
    AAD = ?TV_AAD(),
    IV = ?TV_AES_GCM_IV(),
    CEK = ?TV_AES_128_GCM_Key(),
    CipherText = ?TV_AES_128_GCM_CipherText(),
    CipherTag = ?TV_AES_128_GCM_CipherTag(),
    ?expect({CipherText, CipherTag}, Module, aes_128_gcm_encrypt, [PlainText, AAD, IV, CEK]);
support_check(Module, aes_192_gcm_decrypt, 5) ->
    CipherText = ?TV_AES_192_GCM_CipherText(),
    CipherTag = ?TV_AES_192_GCM_CipherTag(),
    AAD = ?TV_AAD(),
    IV = ?TV_AES_GCM_IV(),
    CEK = ?TV_AES_192_GCM_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, aes_192_gcm_decrypt, [CipherText, CipherTag, AAD, IV, CEK]);
support_check(Module, aes_192_gcm_encrypt, 4) ->
    PlainText = ?TV_PlainText(),
    AAD = ?TV_AAD(),
    IV = ?TV_AES_GCM_IV(),
    CEK = ?TV_AES_192_GCM_Key(),
    CipherText = ?TV_AES_192_GCM_CipherText(),
    CipherTag = ?TV_AES_192_GCM_CipherTag(),
    ?expect({CipherText, CipherTag}, Module, aes_192_gcm_encrypt, [PlainText, AAD, IV, CEK]);
support_check(Module, aes_256_gcm_decrypt, 5) ->
    CipherText = ?TV_AES_256_GCM_CipherText(),
    CipherTag = ?TV_AES_256_GCM_CipherTag(),
    AAD = ?TV_AAD(),
    IV = ?TV_AES_GCM_IV(),
    CEK = ?TV_AES_256_GCM_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, aes_256_gcm_decrypt, [CipherText, CipherTag, AAD, IV, CEK]);
support_check(Module, aes_256_gcm_encrypt, 4) ->
    PlainText = ?TV_PlainText(),
    AAD = ?TV_AAD(),
    IV = ?TV_AES_GCM_IV(),
    CEK = ?TV_AES_256_GCM_Key(),
    CipherText = ?TV_AES_256_GCM_CipherText(),
    CipherTag = ?TV_AES_256_GCM_CipherTag(),
    ?expect({CipherText, CipherTag}, Module, aes_256_gcm_encrypt, [PlainText, AAD, IV, CEK]).

%%====================================================================
%% jose_aes_gcm callbacks
%%====================================================================

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
    ?resolve([CipherText, CipherTag, AAD, IV, CEK]).

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
    ?resolve([PlainText, AAD, IV, CEK]).

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
    ?resolve([CipherText, CipherTag, AAD, IV, CEK]).

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
    ?resolve([PlainText, AAD, IV, CEK]).

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
    ?resolve([CipherText, CipherTag, AAD, IV, CEK]).

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
    ?resolve([PlainText, AAD, IV, CEK]).
