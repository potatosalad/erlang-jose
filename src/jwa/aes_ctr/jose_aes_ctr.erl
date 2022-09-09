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
-module(jose_aes_ctr).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type output() :: binary().
-type aes_ctr_iv() :: <<_:128>>.
-type aes_128_key() :: <<_:128>>.
-type aes_192_key() :: <<_:192>>.
-type aes_256_key() :: <<_:256>>.
-type aes_128_ctr_state() :: term().
-type aes_192_ctr_state() :: term().
-type aes_256_ctr_state() :: term().

-export_type([
	input/0,
	output/0,
	aes_ctr_iv/0,
	aes_128_key/0,
	aes_192_key/0,
	aes_256_key/0,
	aes_128_ctr_state/0,
	aes_192_ctr_state/0,
	aes_256_ctr_state/0
]).

%% Callbacks
-callback aes_128_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_128_key(),
	Output :: jose_aes_ctr:output().
-callback aes_128_ctr_stream_init(IV, Key) -> Aes128CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_128_key(),
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state().
-callback aes_128_ctr_stream_exor(Aes128CtrState, Input) -> {NewAes128CtrState, Output} when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
-callback aes_128_ctr_stream_final(Aes128CtrState) -> Output when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
-callback aes_192_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Output :: jose_aes_ctr:output().
-callback aes_192_ctr_stream_init(IV, Key) -> Aes192CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state().
-callback aes_192_ctr_stream_exor(Aes192CtrState, Input) -> {NewAes192CtrState, Output} when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
-callback aes_192_ctr_stream_final(Aes192CtrState) -> Output when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
-callback aes_256_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Output :: jose_aes_ctr:output().
-callback aes_256_ctr_stream_init(IV, Key) -> Aes256CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state().
-callback aes_256_ctr_stream_exor(Aes256CtrState, Input) -> {NewAes256CtrState, Output} when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
-callback aes_256_ctr_stream_final(Aes256CtrState) -> Output when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().

-optional_callbacks([
	aes_128_ctr_exor/3,
	aes_128_ctr_stream_init/2,
	aes_128_ctr_stream_exor/2,
	aes_128_ctr_stream_final/1,
	aes_192_ctr_exor/3,
	aes_192_ctr_stream_init/2,
	aes_192_ctr_stream_exor/2,
	aes_192_ctr_stream_final/1,
	aes_256_ctr_exor/3,
	aes_256_ctr_stream_init/2,
	aes_256_ctr_stream_exor/2,
	aes_256_ctr_stream_final/1
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_aes_ctr callbacks
-export([
	aes_128_ctr_exor/3,
	aes_128_ctr_stream_init/2,
	aes_128_ctr_stream_exor/2,
	aes_128_ctr_stream_final/1,
	aes_192_ctr_exor/3,
	aes_192_ctr_stream_init/2,
	aes_192_ctr_stream_exor/2,
	aes_192_ctr_stream_final/1,
	aes_256_ctr_exor/3,
	aes_256_ctr_stream_init/2,
	aes_256_ctr_stream_exor/2,
	aes_256_ctr_stream_final/1
]).

%% Macros
-define(TV_PlainText0(), <<"abcdefghijklmnopqrstuvwxyz012345">>). % 2 x 128-bit AES blocks
-define(TV_PlainText1(), <<"abcdefgh">>). % 1/2 x 128-bit AES block
-define(TV_PlainText2(), <<"abcdefghijklmnop">>). % 1 x 128-bit AES block
-define(TV_AES_CTR_IV(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_CTR_Key(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_CTR_CipherText0(), ?b16d("078b28b08aec4b53e1269135a75a445e29908fba8f0847194f052d6696d4716f")).
-define(TV_AES_128_CTR_CipherText1(), ?b16d("62eab9aa05d0c4fa")).
-define(TV_AES_128_CTR_CipherText2(), ?b16d("924aa1dd14d499109effc1c724253653")).
-define(TV_AES_192_CTR_Key(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_AES_192_CTR_CipherText0(), ?b16d("cb820af6c9d935cb819ec202a45e64a7bc41c1feb2058033d974e1c220641000")).
-define(TV_AES_192_CTR_CipherText1(), ?b16d("f985471862969929")).
-define(TV_AES_192_CTR_CipherText2(), ?b16d("7d441d27e1d69168435ef88a0f5b8117")).
-define(TV_AES_256_CTR_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_256_CTR_CipherText0(), ?b16d("bdf7a31cc726eee1c422c978ffea4ff7227df98fb23341c1d01984c0f6f847be")).
-define(TV_AES_256_CTR_CipherText1(), ?b16d("afc5235928060c06")).
-define(TV_AES_256_CTR_CipherText2(), ?b16d("662ca6b7df95fa701b0a68a65ac84504")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [
			[
				{aes_128_ctr_stream_init, 2},
				{aes_128_ctr_stream_exor, 2},
				{aes_128_ctr_stream_final, 1}
			],
			[
				{aes_192_ctr_stream_init, 2},
				{aes_192_ctr_stream_exor, 2},
				{aes_192_ctr_stream_final, 1}
			],
			[
				{aes_256_ctr_stream_init, 2},
				{aes_256_ctr_stream_exor, 2},
				{aes_256_ctr_stream_final, 1}
			]
		],
		callbacks => [
			{{aes_128_ctr_exor, 3}, [{jose_aes_ctr, [{aes_128_ctr_stream_init, 2}, {aes_128_ctr_stream_exor, 2}, {aes_128_ctr_stream_final, 1}]}]},
			{{aes_128_ctr_stream_init, 2}, [{jose_aes_ecb, [{aes_128_ecb_encrypt, 2}]}]},
			{{aes_128_ctr_stream_exor, 2}, [{jose_aes_ctr, [{aes_128_ctr_stream_init, 2}]}]},
			{{aes_128_ctr_stream_final, 1}, [{jose_aes_ctr, [{aes_128_ctr_stream_init, 2}, {aes_128_ctr_stream_exor, 2}]}]},
			{{aes_192_ctr_exor, 3}, [{jose_aes_ctr, [{aes_192_ctr_stream_init, 2}, {aes_192_ctr_stream_exor, 2}, {aes_192_ctr_stream_final, 1}]}]},
			{{aes_192_ctr_stream_init, 2}, [{jose_aes_ecb, [{aes_192_ecb_encrypt, 2}]}]},
			{{aes_192_ctr_stream_exor, 2}, [{jose_aes_ctr, [{aes_192_ctr_stream_init, 2}]}]},
			{{aes_192_ctr_stream_final, 1}, [{jose_aes_ctr, [{aes_192_ctr_stream_init, 2}, {aes_192_ctr_stream_exor, 2}]}]},
			{{aes_256_ctr_exor, 3}, [{jose_aes_ctr, [{aes_256_ctr_stream_init, 2}, {aes_256_ctr_stream_exor, 2}, {aes_256_ctr_stream_final, 1}]}]},
			{{aes_256_ctr_stream_init, 2}, [{jose_aes_ecb, [{aes_256_ecb_encrypt, 2}]}]},
			{{aes_256_ctr_stream_exor, 2}, [{jose_aes_ctr, [{aes_256_ctr_stream_init, 2}]}]},
			{{aes_256_ctr_stream_final, 1}, [{jose_aes_ctr, [{aes_256_ctr_stream_init, 2}, {aes_256_ctr_stream_exor, 2}]}]}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, aes_128_ctr_exor, 3) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_128_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_AES_128_CTR_CipherText0(),
	CipherText1 = ?TV_AES_128_CTR_CipherText1(),
	CipherText2 = ?TV_AES_128_CTR_CipherText2(),
	PlainText = <<PlainText0/binary, PlainText1/binary, PlainText2/binary>>,
	CipherText = <<CipherText0/binary, CipherText1/binary, CipherText2/binary>>,
	?expect(CipherText, Module, aes_128_ctr_exor, [PlainText, IV, Key]);
support_check(Module, aes_128_ctr_stream_init, 2) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_128_CTR_Key(),
	State = Module:aes_128_ctr_stream_init(IV, Key),
	_ = Module:aes_128_ctr_stream_final(State),
	ok;
support_check(Module, aes_128_ctr_stream_exor, 2) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_128_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_AES_128_CTR_CipherText0(),
	CipherText1 = ?TV_AES_128_CTR_CipherText1(),
	CipherText2 = ?TV_AES_128_CTR_CipherText2(),
	State0 = Module:aes_128_ctr_stream_init(IV, Key),
	{State1, ActualCipherText0} = Module:aes_128_ctr_stream_exor(State0, PlainText0),
	{State2, ActualCipherText1} = Module:aes_128_ctr_stream_exor(State1, PlainText1),
	{State3, ActualCipherText2} = Module:aes_128_ctr_stream_exor(State2, PlainText2),
	_ = Module:aes_128_ctr_stream_final(State3),
	?expect([
		{{State1, CipherText0}, {State1, ActualCipherText0}, Module, aes_128_cbc_stream_exor, [State0, PlainText0]},
		{{State2, CipherText1}, {State2, ActualCipherText1}, Module, aes_128_cbc_stream_exor, [State1, PlainText1]},
		{{State3, CipherText2}, {State3, ActualCipherText2}, Module, aes_128_cbc_stream_exor, [State2, PlainText2]}
	]);
support_check(Module, aes_128_ctr_stream_final, 1) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_128_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	State0 = Module:aes_128_ctr_stream_init(IV, Key),
	{State1, _ActualCipherText0} = Module:aes_128_ctr_stream_exor(State0, PlainText0),
	{State2, _ActualCipherText1} = Module:aes_128_ctr_stream_exor(State1, PlainText1),
	{State3, _ActualCipherText2} = Module:aes_128_ctr_stream_exor(State2, PlainText2),
	?expect(<<>>, Module, aes_128_ctr_stream_final, [State3]);
support_check(Module, aes_192_ctr_exor, 3) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_192_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_AES_192_CTR_CipherText0(),
	CipherText1 = ?TV_AES_192_CTR_CipherText1(),
	CipherText2 = ?TV_AES_192_CTR_CipherText2(),
	PlainText = <<PlainText0/binary, PlainText1/binary, PlainText2/binary>>,
	CipherText = <<CipherText0/binary, CipherText1/binary, CipherText2/binary>>,
	?expect(CipherText, Module, aes_192_ctr_exor, [PlainText, IV, Key]);
support_check(Module, aes_192_ctr_stream_init, 2) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_192_CTR_Key(),
	State = Module:aes_192_ctr_stream_init(IV, Key),
	_ = Module:aes_192_ctr_stream_final(State),
	ok;
support_check(Module, aes_192_ctr_stream_exor, 2) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_192_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_AES_192_CTR_CipherText0(),
	CipherText1 = ?TV_AES_192_CTR_CipherText1(),
	CipherText2 = ?TV_AES_192_CTR_CipherText2(),
	State0 = Module:aes_192_ctr_stream_init(IV, Key),
	{State1, ActualCipherText0} = Module:aes_192_ctr_stream_exor(State0, PlainText0),
	{State2, ActualCipherText1} = Module:aes_192_ctr_stream_exor(State1, PlainText1),
	{State3, ActualCipherText2} = Module:aes_192_ctr_stream_exor(State2, PlainText2),
	_ = Module:aes_192_ctr_stream_final(State3),
	?expect([
		{{State1, CipherText0}, {State1, ActualCipherText0}, Module, aes_192_cbc_stream_exor, [State0, PlainText0]},
		{{State2, CipherText1}, {State2, ActualCipherText1}, Module, aes_192_cbc_stream_exor, [State1, PlainText1]},
		{{State3, CipherText2}, {State3, ActualCipherText2}, Module, aes_192_cbc_stream_exor, [State2, PlainText2]}
	]);
support_check(Module, aes_192_ctr_stream_final, 1) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_192_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	State0 = Module:aes_192_ctr_stream_init(IV, Key),
	{State1, _ActualCipherText0} = Module:aes_192_ctr_stream_exor(State0, PlainText0),
	{State2, _ActualCipherText1} = Module:aes_192_ctr_stream_exor(State1, PlainText1),
	{State3, _ActualCipherText2} = Module:aes_192_ctr_stream_exor(State2, PlainText2),
	?expect(<<>>, Module, aes_192_ctr_stream_final, [State3]);
support_check(Module, aes_256_ctr_exor, 3) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_256_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_AES_256_CTR_CipherText0(),
	CipherText1 = ?TV_AES_256_CTR_CipherText1(),
	CipherText2 = ?TV_AES_256_CTR_CipherText2(),
	PlainText = <<PlainText0/binary, PlainText1/binary, PlainText2/binary>>,
	CipherText = <<CipherText0/binary, CipherText1/binary, CipherText2/binary>>,
	?expect(CipherText, Module, aes_256_ctr_exor, [PlainText, IV, Key]);
support_check(Module, aes_256_ctr_stream_init, 2) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_256_CTR_Key(),
	State = Module:aes_256_ctr_stream_init(IV, Key),
	_ = Module:aes_256_ctr_stream_final(State),
	ok;
support_check(Module, aes_256_ctr_stream_exor, 2) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_256_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_AES_256_CTR_CipherText0(),
	CipherText1 = ?TV_AES_256_CTR_CipherText1(),
	CipherText2 = ?TV_AES_256_CTR_CipherText2(),
	State0 = Module:aes_256_ctr_stream_init(IV, Key),
	{State1, ActualCipherText0} = Module:aes_256_ctr_stream_exor(State0, PlainText0),
	{State2, ActualCipherText1} = Module:aes_256_ctr_stream_exor(State1, PlainText1),
	{State3, ActualCipherText2} = Module:aes_256_ctr_stream_exor(State2, PlainText2),
	_ = Module:aes_256_ctr_stream_final(State3),
	?expect([
		{{State1, CipherText0}, {State1, ActualCipherText0}, Module, aes_256_cbc_stream_exor, [State0, PlainText0]},
		{{State2, CipherText1}, {State2, ActualCipherText1}, Module, aes_256_cbc_stream_exor, [State1, PlainText1]},
		{{State3, CipherText2}, {State3, ActualCipherText2}, Module, aes_256_cbc_stream_exor, [State2, PlainText2]}
	]);
support_check(Module, aes_256_ctr_stream_final, 1) ->
	IV = ?TV_AES_CTR_IV(),
	Key = ?TV_AES_256_CTR_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	State0 = Module:aes_256_ctr_stream_init(IV, Key),
	{State1, _ActualCipherText0} = Module:aes_256_ctr_stream_exor(State0, PlainText0),
	{State2, _ActualCipherText1} = Module:aes_256_ctr_stream_exor(State1, PlainText1),
	{State3, _ActualCipherText2} = Module:aes_256_ctr_stream_exor(State2, PlainText2),
	?expect(<<>>, Module, aes_256_ctr_stream_final, [State3]).

%%====================================================================
%% jose_aes_ctr callbacks
%%====================================================================

-spec aes_128_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_128_key(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 128 ->
	?resolve([Input, IV, Key]).

-spec aes_128_ctr_stream_init(IV, Key) -> Aes128CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_128_key(),
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state().
aes_128_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 128 ->
	?resolve([IV, Key]).

-spec aes_128_ctr_stream_exor(Aes128CtrState, Input) -> {NewAes128CtrState, Output} when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_stream_exor(State, Input) ->
	?resolve([State, Input]).

-spec aes_128_ctr_stream_final(Aes128CtrState) -> Output when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_stream_final(State) ->
	?resolve([State]).

-spec aes_192_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 192 ->
	?resolve([Input, IV, Key]).

-spec aes_192_ctr_stream_init(IV, Key) -> Aes192CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state().
aes_192_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 192 ->
	?resolve([IV, Key]).

-spec aes_192_ctr_stream_exor(Aes192CtrState, Input) -> {NewAes192CtrState, Output} when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_stream_exor(State, Input) ->
	?resolve([State, Input]).

-spec aes_192_ctr_stream_final(Aes192CtrState) -> Output when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_stream_final(State) ->
	?resolve([State]).

-spec aes_256_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 256 ->
	?resolve([Input, IV, Key]).

-spec aes_256_ctr_stream_init(IV, Key) -> Aes256CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state().
aes_256_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 256 ->
	?resolve([IV, Key]).

-spec aes_256_ctr_stream_exor(Aes256CtrState, Input) -> {NewAes256CtrState, Output} when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_stream_exor(State, Input) ->
	?resolve([State, Input]).

-spec aes_256_ctr_stream_final(Aes256CtrState) -> Output when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_stream_final(State) ->
	?resolve([State]).
