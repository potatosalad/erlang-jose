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
-module(jose_pbkdf2_hmac).

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type password() :: binary().
-type salt() :: binary().
-type iterations() :: pos_integer().
-type key_len() :: pos_integer().
-type key() :: binary().

-export_type([
    password/0,
    salt/0,
    iterations/0,
    key_len/0,
    key/0
]).

%% Callbacks
-callback pbkdf2_hmac_sha256(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
-callback pbkdf2_hmac_sha384(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
-callback pbkdf2_hmac_sha512(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().

-optional_callbacks([
    pbkdf2_hmac_sha256/4,
    pbkdf2_hmac_sha384/4,
    pbkdf2_hmac_sha512/4
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_hchacha20 callbacks
-export([
    pbkdf2_hmac_sha256/4,
    pbkdf2_hmac_sha384/4,
    pbkdf2_hmac_sha512/4
]).

%% Macros
-define(TV_Password(), <<"password">>).
-define(TV_Salt(), <<"salt">>).
-define(TV_Iterations(), 10).
-define(TV_PBKDF2_HMAC_SHA256_Key(), ?b16d("653cc888d937efe22810a5cbdb25a5bd82e2ebb27a800f85cfa360a6d925198e")).
-define(TV_PBKDF2_HMAC_SHA384_Key(), ?b16d("e03f8ca570b98475a9bcd7f73442f3990c3ec87f8815478954ceb62ac2f3d709")).
-define(TV_PBKDF2_HMAC_SHA512_Key(), ?b16d("ded5fd36ace28019108070acb5acc9db892eb04230f71ecda77c0dbf97e38a8d")).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{pbkdf2_hmac_sha256, 4}, [{jose_hmac, [{hmac_sha256, 2}]}]},
            {{pbkdf2_hmac_sha384, 4}, [{jose_hmac, [{hmac_sha384, 2}]}]},
            {{pbkdf2_hmac_sha512, 4}, [{jose_hmac, [{hmac_sha512, 2}]}]}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, pbkdf2_hmac_sha256, 4) ->
    Password = ?TV_Password(),
    Salt = ?TV_Salt(),
    Iterations = ?TV_Iterations(),
    Key = ?TV_PBKDF2_HMAC_SHA256_Key(),
    KeyLen = byte_size(Key),
    ?expect(Key, Module, pbkdf2_hmac_sha256, [Password, Salt, Iterations, KeyLen]);
support_check(Module, pbkdf2_hmac_sha384, 4) ->
    Password = ?TV_Password(),
    Salt = ?TV_Salt(),
    Iterations = ?TV_Iterations(),
    Key = ?TV_PBKDF2_HMAC_SHA384_Key(),
    KeyLen = byte_size(Key),
    ?expect(Key, Module, pbkdf2_hmac_sha384, [Password, Salt, Iterations, KeyLen]);
support_check(Module, pbkdf2_hmac_sha512, 4) ->
    Password = ?TV_Password(),
    Salt = ?TV_Salt(),
    Iterations = ?TV_Iterations(),
    Key = ?TV_PBKDF2_HMAC_SHA512_Key(),
    KeyLen = byte_size(Key),
    ?expect(Key, Module, pbkdf2_hmac_sha512, [Password, Salt, Iterations, KeyLen]).

%%%=============================================================================
%%% jose_hchacha20 callbacks
%%%=============================================================================

-spec pbkdf2_hmac_sha256(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
pbkdf2_hmac_sha256(Password, Salt, Iterations, KeyLen) when
    is_binary(Password) andalso
        is_binary(Salt) andalso
        (is_integer(Iterations) andalso Iterations >= 1) andalso
        (is_integer(KeyLen) andalso KeyLen >= 1)
->
    ?resolve([Password, Salt, Iterations, KeyLen]).

-spec pbkdf2_hmac_sha384(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
pbkdf2_hmac_sha384(Password, Salt, Iterations, KeyLen) when
    is_binary(Password) andalso
        is_binary(Salt) andalso
        (is_integer(Iterations) andalso Iterations >= 1) andalso
        (is_integer(KeyLen) andalso KeyLen >= 1)
->
    ?resolve([Password, Salt, Iterations, KeyLen]).

-spec pbkdf2_hmac_sha512(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
pbkdf2_hmac_sha512(Password, Salt, Iterations, KeyLen) when
    is_binary(Password) andalso
        is_binary(Salt) andalso
        (is_integer(Iterations) andalso Iterations >= 1) andalso
        (is_integer(KeyLen) andalso KeyLen >= 1)
->
    ?resolve([Password, Salt, Iterations, KeyLen]).
