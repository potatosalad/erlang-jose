%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_hmac).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type hmac_key() :: binary().
-type hmac_sha1_output() :: <<_:160>>.
-type hmac_sha224_output() :: <<_:224>>.
-type hmac_sha256_output() :: <<_:256>>.
-type hmac_sha384_output() :: <<_:384>>.
-type hmac_sha512_output() :: <<_:512>>.

-export_type([
	input/0,
    hmac_key/0,
    hmac_sha1_output/0,
	hmac_sha224_output/0,
	hmac_sha256_output/0,
	hmac_sha384_output/0,
	hmac_sha512_output/0
]).

-callback hmac_sha1(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha1_output().
-callback hmac_sha224(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha224_output().
-callback hmac_sha256(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha256_output().
-callback hmac_sha384(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha384_output().
-callback hmac_sha512(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha512_output().

-optional_callbacks([
	hmac_sha1/2,
	hmac_sha224/2,
	hmac_sha256/2,
	hmac_sha384/2,
    hmac_sha512/2
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_hmac callbacks
-export([
	hmac_sha1/2,
	hmac_sha224/2,
	hmac_sha256/2,
	hmac_sha384/2,
    hmac_sha512/2
]).

%% Macros
-define(TV_Input(), <<"abc">>).
-define(TV_HMAC_SHA1_Key(), ?b16d("0000000000000000000000000000000000000000")).
-define(TV_HMAC_SHA1_Output(), ?b16d("9b4a918f398d74d3e367970aba3cbe54e4d2b5d9")).
-define(TV_HMAC_SHA224_Key(), ?b16d("00000000000000000000000000000000000000000000000000000000")).
-define(TV_HMAC_SHA224_Output(), ?b16d("d473c456fa6aad72bbec9c6ad63ca92d8675caa0b7f451fa4b692081")).
-define(TV_HMAC_SHA256_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_HMAC_SHA256_Output(), ?b16d("fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351")).
-define(TV_HMAC_SHA384_Key(), ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_HMAC_SHA384_Output(), ?b16d("948f7c5caa500c31d7d4a0f52f3e3da7e33c8a9fe6ef528b8a9ac3e4adc4e24d908e6f40b737510e82354759dc5e9f06")).
-define(TV_HMAC_SHA512_Key(), ?b16d("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_HMAC_SHA512_Output(), ?b16d("29689f6b79a8dd686068c2eeae97fd8769ad3ba65cb5381f838358a8045a358ee3ba1739c689c7805e31734fb6072f87261d1256995370d55725cba00d10bdd0")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [],
		callbacks => [
			{{hmac_sha1, 2}, [{jose_sha1, [{sha1, 1}]}]},
			{{hmac_sha224, 2}, [{jose_sha2, [{sha224, 1}]}]},
			{{hmac_sha256, 2}, [{jose_sha2, [{sha256, 1}]}]},
			{{hmac_sha384, 2}, [{jose_sha2, [{sha384, 1}]}]},
			{{hmac_sha512, 2}, [{jose_sha2, [{sha512, 1}]}]}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, hmac_sha1, 2) ->
    Key = ?TV_HMAC_SHA1_Key(),
	Input = ?TV_Input(),
	Output = ?TV_HMAC_SHA1_Output(),
	?expect(Output, Module, hmac_sha1, [Key, Input]);
support_check(Module, hmac_sha224, 2) ->
    Key = ?TV_HMAC_SHA224_Key(),
	Input = ?TV_Input(),
	Output = ?TV_HMAC_SHA224_Output(),
	?expect(Output, Module, hmac_sha224, [Key, Input]);
support_check(Module, hmac_sha256, 2) ->
    Key = ?TV_HMAC_SHA256_Key(),
	Input = ?TV_Input(),
	Output = ?TV_HMAC_SHA256_Output(),
	?expect(Output, Module, hmac_sha256, [Key, Input]);
support_check(Module, hmac_sha384, 2) ->
    Key = ?TV_HMAC_SHA384_Key(),
	Input = ?TV_Input(),
	Output = ?TV_HMAC_SHA384_Output(),
	?expect(Output, Module, hmac_sha384, [Key, Input]);
support_check(Module, hmac_sha512, 2) ->
    Key = ?TV_HMAC_SHA512_Key(),
	Input = ?TV_Input(),
	Output = ?TV_HMAC_SHA512_Output(),
	?expect(Output, Module, hmac_sha512, [Key, Input]).

%%====================================================================
%% jose_hmac callbacks
%%====================================================================

-spec hmac_sha1(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha1_output().
hmac_sha1(Key, Input) ->
	?resolve([Key, Input]).

-spec hmac_sha224(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha224_output().
hmac_sha224(Key, Input) ->
	?resolve([Key, Input]).

-spec hmac_sha256(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha256_output().
hmac_sha256(Key, Input) ->
	?resolve([Key, Input]).

-spec hmac_sha384(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha384_output().
hmac_sha384(Key, Input) ->
	?resolve([Key, Input]).

-spec hmac_sha512(Key, Input) -> Output when
	Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha512_output().
hmac_sha512(Key, Input) ->
	?resolve([Key, Input]).
