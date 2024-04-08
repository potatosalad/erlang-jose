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
%%% Created :  02 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_aes_ecb).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type plain_text() :: <<_:128, _:_*128>>.
-type cipher_text() :: <<_:128, _:_*128>>.
-type aes_block() :: <<_:128>>.
-type aes_128_key() :: <<_:128>>.
-type aes_192_key() :: <<_:192>>.
-type aes_256_key() :: <<_:256>>.

-export_type([
    plain_text/0,
    cipher_text/0,
    aes_block/0,
    aes_128_key/0,
    aes_192_key/0,
    aes_256_key/0
]).

%% Callbacks
-callback aes_128_ecb_decrypt(CipherText, CEK) -> PlainText when
    CipherText :: jose_aes_ecb:cipher_text(),
    CEK :: jose_aes_ecb:aes_128_key(),
    PlainText :: jose_aes_ecb:plain_text().
-callback aes_128_ecb_encrypt(PlainText, CEK) -> CipherText when
    PlainText :: jose_aes_ecb:plain_text(),
    CEK :: jose_aes_ecb:aes_128_key(),
    CipherText :: jose_aes_ecb:cipher_text().
-callback aes_192_ecb_decrypt(CipherText, CEK) -> PlainText when
    CipherText :: jose_aes_ecb:cipher_text(),
    CEK :: jose_aes_ecb:aes_192_key(),
    PlainText :: jose_aes_ecb:plain_text().
-callback aes_192_ecb_encrypt(PlainText, CEK) -> CipherText when
    PlainText :: jose_aes_ecb:plain_text(),
    CEK :: jose_aes_ecb:aes_192_key(),
    CipherText :: jose_aes_ecb:cipher_text().
-callback aes_256_ecb_decrypt(CipherText, CEK) -> PlainText when
    CipherText :: jose_aes_ecb:cipher_text(),
    CEK :: jose_aes_ecb:aes_256_key(),
    PlainText :: jose_aes_ecb:plain_text().
-callback aes_256_ecb_encrypt(PlainText, CEK) -> CipherText when
    PlainText :: jose_aes_ecb:plain_text(),
    CEK :: jose_aes_ecb:aes_256_key(),
    CipherText :: jose_aes_ecb:cipher_text().

-optional_callbacks([
    aes_128_ecb_decrypt/2,
    aes_128_ecb_encrypt/2,
    aes_192_ecb_decrypt/2,
    aes_192_ecb_encrypt/2,
    aes_256_ecb_decrypt/2,
    aes_256_ecb_encrypt/2
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_aes_ecb callbacks
-export([aes_128_ecb_decrypt/2]).
-export([aes_128_ecb_encrypt/2]).
-export([aes_192_ecb_decrypt/2]).
-export([aes_192_ecb_encrypt/2]).
-export([aes_256_ecb_decrypt/2]).
-export([aes_256_ecb_encrypt/2]).

%% Macros

% 2 x 128-bit AES blocks
-define(TV_PlainText(), <<"abcdefghijklmnopqrstuvwxyz012345">>).
-define(TV_AES_128_ECB_Key(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_ECB_CipherText(), ?b16d("c3af71addfe4fcac6941286a76ddedc2fd0d82d1d988f9868b8248ce2a6ac4c7")).
-define(TV_AES_192_ECB_Key(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_AES_192_ECB_CipherText(), ?b16d("ec6374e75e004afc29beafbfb25c057d242e36b0f29f1963f4def269201032a9")).
-define(TV_AES_256_ECB_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_256_ECB_CipherText(), ?b16d("ac9c9eb761551ffb7d78d88b5e2330149954e153190e5ef962356ac0e183b343")).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{aes_128_ecb_decrypt, 2}, []},
            {{aes_128_ecb_encrypt, 2}, []},
            {{aes_192_ecb_decrypt, 2}, []},
            {{aes_192_ecb_encrypt, 2}, []},
            {{aes_256_ecb_decrypt, 2}, []},
            {{aes_256_ecb_encrypt, 2}, []}
        ]
    }.

-spec support_check(Module :: module(), Funname :: jose_support:funname(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, aes_128_ecb_decrypt, 2) ->
    CipherText = ?TV_AES_128_ECB_CipherText(),
    CEK = ?TV_AES_128_ECB_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, aes_128_ecb_decrypt, [CipherText, CEK]);
support_check(Module, aes_128_ecb_encrypt, 2) ->
    PlainText = ?TV_PlainText(),
    CEK = ?TV_AES_128_ECB_Key(),
    CipherText = ?TV_AES_128_ECB_CipherText(),
    ?expect(CipherText, Module, aes_128_ecb_encrypt, [PlainText, CEK]);
support_check(Module, aes_192_ecb_decrypt, 2) ->
    CipherText = ?TV_AES_192_ECB_CipherText(),
    CEK = ?TV_AES_192_ECB_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, aes_192_ecb_decrypt, [CipherText, CEK]);
support_check(Module, aes_192_ecb_encrypt, 2) ->
    PlainText = ?TV_PlainText(),
    CEK = ?TV_AES_192_ECB_Key(),
    CipherText = ?TV_AES_192_ECB_CipherText(),
    ?expect(CipherText, Module, aes_192_ecb_encrypt, [PlainText, CEK]);
support_check(Module, aes_256_ecb_decrypt, 2) ->
    CipherText = ?TV_AES_256_ECB_CipherText(),
    CEK = ?TV_AES_256_ECB_Key(),
    PlainText = ?TV_PlainText(),
    ?expect(PlainText, Module, aes_256_ecb_decrypt, [CipherText, CEK]);
support_check(Module, aes_256_ecb_encrypt, 2) ->
    PlainText = ?TV_PlainText(),
    CEK = ?TV_AES_256_ECB_Key(),
    CipherText = ?TV_AES_256_ECB_CipherText(),
    ?expect(CipherText, Module, aes_256_ecb_encrypt, [PlainText, CEK]).

%%%=============================================================================
%%% jose_aes_ecb callbacks
%%%=============================================================================

-spec aes_128_ecb_decrypt(CipherText, CEK) -> PlainText when
    CipherText :: jose_aes_ecb:cipher_text(),
    CEK :: jose_aes_ecb:aes_128_key(),
    PlainText :: jose_aes_ecb:plain_text().
aes_128_ecb_decrypt(CipherText, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(CEK) =:= 128 ->
    ?resolve([CipherText, CEK]).

-spec aes_128_ecb_encrypt(PlainText, CEK) -> CipherText when
    PlainText :: jose_aes_ecb:plain_text(),
    CEK :: jose_aes_ecb:aes_128_key(),
    CipherText :: jose_aes_ecb:cipher_text().
aes_128_ecb_encrypt(PlainText, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(CEK) =:= 128 ->
    ?resolve([PlainText, CEK]).

-spec aes_192_ecb_decrypt(CipherText, CEK) -> PlainText when
    CipherText :: jose_aes_ecb:cipher_text(),
    CEK :: jose_aes_ecb:aes_192_key(),
    PlainText :: jose_aes_ecb:plain_text().
aes_192_ecb_decrypt(CipherText, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(CEK) =:= 192 ->
    ?resolve([CipherText, CEK]).

-spec aes_192_ecb_encrypt(PlainText, CEK) -> CipherText when
    PlainText :: jose_aes_ecb:plain_text(),
    CEK :: jose_aes_ecb:aes_192_key(),
    CipherText :: jose_aes_ecb:cipher_text().
aes_192_ecb_encrypt(PlainText, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(CEK) =:= 192 ->
    ?resolve([PlainText, CEK]).

-spec aes_256_ecb_decrypt(CipherText, CEK) -> PlainText when
    CipherText :: jose_aes_ecb:cipher_text(),
    CEK :: jose_aes_ecb:aes_256_key(),
    PlainText :: jose_aes_ecb:plain_text().
aes_256_ecb_decrypt(CipherText, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(CEK) =:= 256 ->
    ?resolve([CipherText, CEK]).

-spec aes_256_ecb_encrypt(PlainText, CEK) -> CipherText when
    PlainText :: jose_aes_ecb:plain_text(),
    CEK :: jose_aes_ecb:aes_256_key(),
    CipherText :: jose_aes_ecb:cipher_text().
aes_256_ecb_encrypt(PlainText, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(CEK) =:= 256 ->
    ?resolve([PlainText, CEK]).
