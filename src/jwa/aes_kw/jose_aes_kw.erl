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
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_aes_kw).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type plain_text() :: <<_:64, _:_*64>>.
-type cipher_text() :: <<_:64, _:_*64>>.
-type aes_128_key() :: <<_:128>>.
-type aes_192_key() :: <<_:192>>.
-type aes_256_key() :: <<_:256>>.

-export_type([
    plain_text/0,
    cipher_text/0,
    aes_128_key/0,
    aes_192_key/0,
    aes_256_key/0
]).

%% Callbacks
-callback aes_128_kw_unwrap(CipherText, KEK) -> PlainText | error when
    CipherText :: jose_aes_kw:cipher_text(),
    KEK :: jose_aes_kw:aes_128_key(),
    PlainText :: jose_aes_kw:plain_text().
-callback aes_128_kw_wrap(PlainText, KEK) -> CipherText when
    PlainText :: jose_aes_kw:plain_text(),
    KEK :: jose_aes_kw:aes_128_key(),
    CipherText :: jose_aes_kw:cipher_text().
-callback aes_192_kw_unwrap(CipherText, KEK) -> PlainText | error when
    CipherText :: jose_aes_kw:cipher_text(),
    KEK :: jose_aes_kw:aes_192_key(),
    PlainText :: jose_aes_kw:plain_text().
-callback aes_192_kw_wrap(PlainText, KEK) -> CipherText when
    PlainText :: jose_aes_kw:plain_text(),
    KEK :: jose_aes_kw:aes_192_key(),
    CipherText :: jose_aes_kw:cipher_text().
-callback aes_256_kw_unwrap(CipherText, KEK) -> PlainText | error when
    CipherText :: jose_aes_kw:cipher_text(),
    KEK :: jose_aes_kw:aes_256_key(),
    PlainText :: jose_aes_kw:plain_text().
-callback aes_256_kw_wrap(PlainText, KEK) -> CipherText when
    PlainText :: jose_aes_kw:plain_text(),
    KEK :: jose_aes_kw:aes_256_key(),
    CipherText :: jose_aes_kw:cipher_text().

-optional_callbacks([
    aes_128_kw_unwrap/2,
    aes_128_kw_wrap/2,
    aes_192_kw_unwrap/2,
    aes_192_kw_wrap/2,
    aes_256_kw_unwrap/2,
    aes_256_kw_wrap/2
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_aes_kw callbacks
-export([
    aes_128_kw_unwrap/2,
    aes_128_kw_wrap/2,
    aes_192_kw_unwrap/2,
    aes_192_kw_wrap/2,
    aes_256_kw_unwrap/2,
    aes_256_kw_wrap/2
]).

%% Macros
-define(TV_PlainText128(), ?b16d("00000000000000000000000000000000")).
-define(TV_PlainText192(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_PlainText256(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_PlainText384(),
    ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
).
-define(TV_PlainText512(),
    ?b16d(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
).
-define(TV_AES_128_KW_KEK(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_KW_CipherText128(), ?b16d("bf3b77b5e90caa9f5009fe9626e4efe20ded75ee3b1ac0d5")).
-define(TV_AES_128_KW_CipherText192(), ?b16d("1a07acab6c906e50883173c29441db1de91d34f45c435b5f99c822867fb3956f")).
-define(TV_AES_128_KW_CipherText256(),
    ?b16d("74d6ff238877ed2a9bcde9043e4ca62a2a0d340f067d3c9fc2c8d2ebf9a969998585c83951b53cca")
).
-define(TV_AES_128_KW_CipherText384(),
    ?b16d(
        "f5de08259c69159eb7de6b863c4ab88f7abad96fb24185e3980bb66c863639d8d132d51ce194faa4bee31bc99d552ef83f192414b30dc3b4"
    )
).
-define(TV_AES_128_KW_CipherText512(),
    ?b16d(
        "71d6e55360942d83436ec7258351414909faf5b044591d3fb361c0c71722a2379b7d024747c060c3f913e8ce07c33c308b639ea192b593ab6f86cf528541f41569d9ef0e29147834"
    )
).
-define(TV_AES_192_KW_KEK(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_AES_192_KW_CipherText128(), ?b16d("a0aeab397c0dc4b3df22df8c52cedce111a2ec9cbde5defc")).
-define(TV_AES_192_KW_CipherText192(), ?b16d("3530731ac8a475c69a5e41bd93bfa7e07ec48bfa79f043e7e639f8a54e06b8a8")).
-define(TV_AES_192_KW_CipherText256(),
    ?b16d("6bc803debb9cdad9b6d65942aa3e6d16c34a2719dc5c567353c1028c551f2422cc19518ca3f0d5e6")
).
-define(TV_AES_192_KW_CipherText384(),
    ?b16d(
        "d22370501342c04736c0dd6b3c44bf9621c2acf6a70eeb72f7a4b236fb143265e01048cb53fc52700c8b6c83f8a99d16ec6a43d435677734"
    )
).
-define(TV_AES_192_KW_CipherText512(),
    ?b16d(
        "e852a65c34583329cf033c09fe6b1445c4a11441e841a1bbdbe9fd4630c506f47dfcca4aeaff4f1cd9e718376e76c48077a9fce5d0457542aa10f95ec8a06d81f6bd6d8510180a90"
    )
).
-define(TV_AES_256_KW_KEK(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_256_KW_CipherText128(), ?b16d("b595a1c0afbe7a89ce43807cb3b2ba5737ff5d71d0a35cd7")).
-define(TV_AES_256_KW_CipherText192(), ?b16d("52b6a524f70e2cb89ff71c6da7ea8c89b42dd2272e3fa93b82478c452b09272f")).
-define(TV_AES_256_KW_CipherText256(),
    ?b16d("97317494343807e690fd1e431413963dc0e3deb4907fb89fa36ce65126d0ea1301381fb3a2941e2f")
).
-define(TV_AES_256_KW_CipherText384(),
    ?b16d(
        "5aa7cd66ea9a2f00ef9f00d26da3035a45fcd163e29aa62671aa875bb46de76cf6ae0eb598fd5985138ad0fca4acc9902f44060a49f022dd"
    )
).
-define(TV_AES_256_KW_CipherText512(),
    ?b16d(
        "d38e3b5540589fbe6eb44c3326fa764ced2f70500e6e6f43a53f03d097a40d0784f0d47fb03957f85551c7cb3ea573e218ac91d62b5149663a852232600d4277af4060a3c39919d5"
    )
).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{aes_128_kw_unwrap, 2}, [{jose_aes_ecb, [{aes_128_ecb_decrypt, 2}]}]},
            {{aes_128_kw_wrap, 2}, [{jose_aes_ecb, [{aes_128_ecb_encrypt, 2}]}]},
            {{aes_192_kw_unwrap, 2}, [{jose_aes_ecb, [{aes_192_ecb_decrypt, 2}]}]},
            {{aes_192_kw_wrap, 2}, [{jose_aes_ecb, [{aes_192_ecb_encrypt, 2}]}]},
            {{aes_256_kw_unwrap, 2}, [{jose_aes_ecb, [{aes_256_ecb_decrypt, 2}]}]},
            {{aes_256_kw_wrap, 2}, [{jose_aes_ecb, [{aes_256_ecb_encrypt, 2}]}]}
        ]
    }.

-spec support_check(Module :: module(), Funname :: jose_support:funname(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, aes_128_kw_unwrap, 2) ->
    CipherText128 = ?TV_AES_128_KW_CipherText128(),
    CipherText192 = ?TV_AES_128_KW_CipherText192(),
    CipherText256 = ?TV_AES_128_KW_CipherText256(),
    CipherText384 = ?TV_AES_128_KW_CipherText384(),
    CipherText512 = ?TV_AES_128_KW_CipherText512(),
    KEK = ?TV_AES_128_KW_KEK(),
    PlainText128 = ?TV_PlainText128(),
    PlainText192 = ?TV_PlainText192(),
    PlainText256 = ?TV_PlainText256(),
    PlainText384 = ?TV_PlainText384(),
    PlainText512 = ?TV_PlainText512(),
    ActualPlainText128 = Module:aes_128_kw_unwrap(CipherText128, KEK),
    ActualPlainText192 = Module:aes_128_kw_unwrap(CipherText192, KEK),
    ActualPlainText256 = Module:aes_128_kw_unwrap(CipherText256, KEK),
    ActualPlainText384 = Module:aes_128_kw_unwrap(CipherText384, KEK),
    ActualPlainText512 = Module:aes_128_kw_unwrap(CipherText512, KEK),
    ?expect([
        {PlainText128, ActualPlainText128, Module, aes_128_kw_unwrap, [CipherText128, KEK]},
        {PlainText192, ActualPlainText192, Module, aes_128_kw_unwrap, [CipherText192, KEK]},
        {PlainText256, ActualPlainText256, Module, aes_128_kw_unwrap, [CipherText256, KEK]},
        {PlainText384, ActualPlainText384, Module, aes_128_kw_unwrap, [CipherText384, KEK]},
        {PlainText512, ActualPlainText512, Module, aes_128_kw_unwrap, [CipherText512, KEK]}
    ]);
support_check(Module, aes_128_kw_wrap, 2) ->
    PlainText128 = ?TV_PlainText128(),
    PlainText192 = ?TV_PlainText192(),
    PlainText256 = ?TV_PlainText256(),
    PlainText384 = ?TV_PlainText384(),
    PlainText512 = ?TV_PlainText512(),
    KEK = ?TV_AES_128_KW_KEK(),
    CipherText128 = ?TV_AES_128_KW_CipherText128(),
    CipherText192 = ?TV_AES_128_KW_CipherText192(),
    CipherText256 = ?TV_AES_128_KW_CipherText256(),
    CipherText384 = ?TV_AES_128_KW_CipherText384(),
    CipherText512 = ?TV_AES_128_KW_CipherText512(),
    ActualCipherText128 = Module:aes_128_kw_wrap(PlainText128, KEK),
    ActualCipherText192 = Module:aes_128_kw_wrap(PlainText192, KEK),
    ActualCipherText256 = Module:aes_128_kw_wrap(PlainText256, KEK),
    ActualCipherText384 = Module:aes_128_kw_wrap(PlainText384, KEK),
    ActualCipherText512 = Module:aes_128_kw_wrap(PlainText512, KEK),
    ?expect([
        {CipherText128, ActualCipherText128, Module, aes_128_kw_wrap, [PlainText128, KEK]},
        {CipherText192, ActualCipherText192, Module, aes_128_kw_wrap, [PlainText192, KEK]},
        {CipherText256, ActualCipherText256, Module, aes_128_kw_wrap, [PlainText256, KEK]},
        {CipherText384, ActualCipherText384, Module, aes_128_kw_wrap, [PlainText384, KEK]},
        {CipherText512, ActualCipherText512, Module, aes_128_kw_wrap, [PlainText512, KEK]}
    ]);
support_check(Module, aes_192_kw_unwrap, 2) ->
    CipherText128 = ?TV_AES_192_KW_CipherText128(),
    CipherText192 = ?TV_AES_192_KW_CipherText192(),
    CipherText256 = ?TV_AES_192_KW_CipherText256(),
    CipherText384 = ?TV_AES_192_KW_CipherText384(),
    CipherText512 = ?TV_AES_192_KW_CipherText512(),
    KEK = ?TV_AES_192_KW_KEK(),
    PlainText128 = ?TV_PlainText128(),
    PlainText192 = ?TV_PlainText192(),
    PlainText256 = ?TV_PlainText256(),
    PlainText384 = ?TV_PlainText384(),
    PlainText512 = ?TV_PlainText512(),
    ActualPlainText128 = Module:aes_192_kw_unwrap(CipherText128, KEK),
    ActualPlainText192 = Module:aes_192_kw_unwrap(CipherText192, KEK),
    ActualPlainText256 = Module:aes_192_kw_unwrap(CipherText256, KEK),
    ActualPlainText384 = Module:aes_192_kw_unwrap(CipherText384, KEK),
    ActualPlainText512 = Module:aes_192_kw_unwrap(CipherText512, KEK),
    ?expect([
        {PlainText128, ActualPlainText128, Module, aes_192_kw_unwrap, [CipherText128, KEK]},
        {PlainText192, ActualPlainText192, Module, aes_192_kw_unwrap, [CipherText192, KEK]},
        {PlainText256, ActualPlainText256, Module, aes_192_kw_unwrap, [CipherText256, KEK]},
        {PlainText384, ActualPlainText384, Module, aes_192_kw_unwrap, [CipherText384, KEK]},
        {PlainText512, ActualPlainText512, Module, aes_192_kw_unwrap, [CipherText512, KEK]}
    ]);
support_check(Module, aes_192_kw_wrap, 2) ->
    PlainText128 = ?TV_PlainText128(),
    PlainText192 = ?TV_PlainText192(),
    PlainText256 = ?TV_PlainText256(),
    PlainText384 = ?TV_PlainText384(),
    PlainText512 = ?TV_PlainText512(),
    KEK = ?TV_AES_192_KW_KEK(),
    CipherText128 = ?TV_AES_192_KW_CipherText128(),
    CipherText192 = ?TV_AES_192_KW_CipherText192(),
    CipherText256 = ?TV_AES_192_KW_CipherText256(),
    CipherText384 = ?TV_AES_192_KW_CipherText384(),
    CipherText512 = ?TV_AES_192_KW_CipherText512(),
    ActualCipherText128 = Module:aes_192_kw_wrap(PlainText128, KEK),
    ActualCipherText192 = Module:aes_192_kw_wrap(PlainText192, KEK),
    ActualCipherText256 = Module:aes_192_kw_wrap(PlainText256, KEK),
    ActualCipherText384 = Module:aes_192_kw_wrap(PlainText384, KEK),
    ActualCipherText512 = Module:aes_192_kw_wrap(PlainText512, KEK),
    ?expect([
        {CipherText128, ActualCipherText128, Module, aes_192_kw_wrap, [PlainText128, KEK]},
        {CipherText192, ActualCipherText192, Module, aes_192_kw_wrap, [PlainText192, KEK]},
        {CipherText256, ActualCipherText256, Module, aes_192_kw_wrap, [PlainText256, KEK]},
        {CipherText384, ActualCipherText384, Module, aes_192_kw_wrap, [PlainText384, KEK]},
        {CipherText512, ActualCipherText512, Module, aes_192_kw_wrap, [PlainText512, KEK]}
    ]);
support_check(Module, aes_256_kw_unwrap, 2) ->
    CipherText128 = ?TV_AES_256_KW_CipherText128(),
    CipherText192 = ?TV_AES_256_KW_CipherText192(),
    CipherText256 = ?TV_AES_256_KW_CipherText256(),
    CipherText384 = ?TV_AES_256_KW_CipherText384(),
    CipherText512 = ?TV_AES_256_KW_CipherText512(),
    KEK = ?TV_AES_256_KW_KEK(),
    PlainText128 = ?TV_PlainText128(),
    PlainText192 = ?TV_PlainText192(),
    PlainText256 = ?TV_PlainText256(),
    PlainText384 = ?TV_PlainText384(),
    PlainText512 = ?TV_PlainText512(),
    ActualPlainText128 = Module:aes_256_kw_unwrap(CipherText128, KEK),
    ActualPlainText192 = Module:aes_256_kw_unwrap(CipherText192, KEK),
    ActualPlainText256 = Module:aes_256_kw_unwrap(CipherText256, KEK),
    ActualPlainText384 = Module:aes_256_kw_unwrap(CipherText384, KEK),
    ActualPlainText512 = Module:aes_256_kw_unwrap(CipherText512, KEK),
    ?expect([
        {PlainText128, ActualPlainText128, Module, aes_256_kw_unwrap, [CipherText128, KEK]},
        {PlainText192, ActualPlainText192, Module, aes_256_kw_unwrap, [CipherText192, KEK]},
        {PlainText256, ActualPlainText256, Module, aes_256_kw_unwrap, [CipherText256, KEK]},
        {PlainText384, ActualPlainText384, Module, aes_256_kw_unwrap, [CipherText384, KEK]},
        {PlainText512, ActualPlainText512, Module, aes_256_kw_unwrap, [CipherText512, KEK]}
    ]);
support_check(Module, aes_256_kw_wrap, 2) ->
    PlainText128 = ?TV_PlainText128(),
    PlainText192 = ?TV_PlainText192(),
    PlainText256 = ?TV_PlainText256(),
    PlainText384 = ?TV_PlainText384(),
    PlainText512 = ?TV_PlainText512(),
    KEK = ?TV_AES_256_KW_KEK(),
    CipherText128 = ?TV_AES_256_KW_CipherText128(),
    CipherText192 = ?TV_AES_256_KW_CipherText192(),
    CipherText256 = ?TV_AES_256_KW_CipherText256(),
    CipherText384 = ?TV_AES_256_KW_CipherText384(),
    CipherText512 = ?TV_AES_256_KW_CipherText512(),
    ActualCipherText128 = Module:aes_256_kw_wrap(PlainText128, KEK),
    ActualCipherText192 = Module:aes_256_kw_wrap(PlainText192, KEK),
    ActualCipherText256 = Module:aes_256_kw_wrap(PlainText256, KEK),
    ActualCipherText384 = Module:aes_256_kw_wrap(PlainText384, KEK),
    ActualCipherText512 = Module:aes_256_kw_wrap(PlainText512, KEK),
    ?expect([
        {CipherText128, ActualCipherText128, Module, aes_256_kw_wrap, [PlainText128, KEK]},
        {CipherText192, ActualCipherText192, Module, aes_256_kw_wrap, [PlainText192, KEK]},
        {CipherText256, ActualCipherText256, Module, aes_256_kw_wrap, [PlainText256, KEK]},
        {CipherText384, ActualCipherText384, Module, aes_256_kw_wrap, [PlainText384, KEK]},
        {CipherText512, ActualCipherText512, Module, aes_256_kw_wrap, [PlainText512, KEK]}
    ]).

%%%=============================================================================
%%% jose_aes_kw callbacks
%%%=============================================================================

-spec aes_128_kw_unwrap(CipherText, KEK) -> PlainText | error when
    CipherText :: jose_aes_kw:cipher_text(),
    KEK :: jose_aes_kw:aes_128_key(),
    PlainText :: jose_aes_kw:plain_text().
aes_128_kw_unwrap(CipherText, KEK) when bit_size(CipherText) rem 64 =:= 0 andalso bit_size(KEK) =:= 128 ->
    ?resolve([CipherText, KEK]).

-spec aes_128_kw_wrap(PlainText, KEK) -> CipherText when
    PlainText :: jose_aes_kw:plain_text(),
    KEK :: jose_aes_kw:aes_128_key(),
    CipherText :: jose_aes_kw:cipher_text().
aes_128_kw_wrap(PlainText, KEK) when bit_size(PlainText) rem 64 =:= 0 andalso bit_size(KEK) =:= 128 ->
    ?resolve([PlainText, KEK]).

-spec aes_192_kw_unwrap(CipherText, KEK) -> PlainText | error when
    CipherText :: jose_aes_kw:cipher_text(),
    KEK :: jose_aes_kw:aes_192_key(),
    PlainText :: jose_aes_kw:plain_text().
aes_192_kw_unwrap(CipherText, KEK) when bit_size(CipherText) rem 64 =:= 0 andalso bit_size(KEK) =:= 192 ->
    ?resolve([CipherText, KEK]).

-spec aes_192_kw_wrap(PlainText, KEK) -> CipherText when
    PlainText :: jose_aes_kw:plain_text(),
    KEK :: jose_aes_kw:aes_192_key(),
    CipherText :: jose_aes_kw:cipher_text().
aes_192_kw_wrap(PlainText, KEK) when bit_size(PlainText) rem 64 =:= 0 andalso bit_size(KEK) =:= 192 ->
    ?resolve([PlainText, KEK]).

-spec aes_256_kw_unwrap(CipherText, KEK) -> PlainText | error when
    CipherText :: jose_aes_kw:cipher_text(),
    KEK :: jose_aes_kw:aes_256_key(),
    PlainText :: jose_aes_kw:plain_text().
aes_256_kw_unwrap(CipherText, KEK) when bit_size(CipherText) rem 64 =:= 0 andalso bit_size(KEK) =:= 256 ->
    ?resolve([CipherText, KEK]).

-spec aes_256_kw_wrap(PlainText, KEK) -> CipherText when
    PlainText :: jose_aes_kw:plain_text(),
    KEK :: jose_aes_kw:aes_256_key(),
    CipherText :: jose_aes_kw:cipher_text().
aes_256_kw_wrap(PlainText, KEK) when bit_size(PlainText) rem 64 =:= 0 andalso bit_size(KEK) =:= 256 ->
    ?resolve([PlainText, KEK]).
