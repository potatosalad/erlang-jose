%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_chacha20).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type output() :: binary().
-type chacha20_key() :: <<_:256>>.
-type chacha20_nonce() :: <<_:96>>.
-type chacha20_count() :: <<_:32>>.
-type chacha20_state() :: term().

-export_type([
	input/0,
	output/0,
	chacha20_key/0,
	chacha20_nonce/0,
	chacha20_count/0,
	chacha20_state/0
]).

%% Callbacks
-callback chacha20_exor(Input, Count, Nonce, Key) -> Output when
	Input :: jose_chacha20:input(),
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	Key :: jose_chacha20:chacha20_key(),
	Output :: jose_chacha20:output().
-callback chacha20_stream_init(Count, Nonce, Key) -> ChaCha20State when
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	Key :: jose_chacha20:chacha20_key(),
	ChaCha20State :: jose_chacha20:chacha20_state().
-callback chacha20_stream_exor(ChaCha20State, Input) -> {NewChaCha20State, Output} when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Input :: jose_chacha20:input(),
	NewChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
-callback chacha20_stream_final(ChaCha20State) -> Output when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().

-optional_callbacks([
	chacha20_exor/4,
	chacha20_stream_init/3,
	chacha20_stream_exor/2,
	chacha20_stream_final/1
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_chacha20 callbacks
-export([
	chacha20_exor/4,
	chacha20_stream_init/3,
	chacha20_stream_exor/2,
	chacha20_stream_final/1
]).

%% Macros
-define(TV_PlainText0(), <<"abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345">>). % 4 x 128-bit AES blocks
-define(TV_PlainText1(), <<"abcdefgh">>). % 1/2 x 128-bit AES block
-define(TV_PlainText2(), <<"abcdefghijklmnop">>). % 1 x 128-bit AES block
-define(TV_CHACHA20_Count(), ?b16d("00000000")).
-define(TV_CHACHA20_Nonce(), ?b16d("000000000000000000000000")).
-define(TV_CHACHA20_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_CHACHA20_CipherText0(), ?b16d("17da83c9c5975af8293701893ee8d258cca06accd5fb9a62d14cdffdb94439f2bb233a1834312fe51e4e8b53d5b625471b31cb80606ed664bafd865880dd51b3")).
-define(TV_CHACHA20_CipherText1(), ?b16d("fe6584da30375f12")).
-define(TV_CHACHA20_CipherText2(), ?b16d("f9d8f418164b6f65a26542cc258d0a19")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [
			[
				{chacha20_stream_init, 3},
				{chacha20_stream_exor, 2},
				{chacha20_stream_final, 1}
			]
		],
		callbacks => [
			{{chacha20_exor, 4}, [{jose_chacha20, [{chacha20_stream_init, 3}, {chacha20_stream_exor, 2}, {chacha20_stream_final, 1}]}]},
			{{chacha20_stream_init, 3}, []},
			{{chacha20_stream_exor, 2}, [{jose_chacha20, [{chacha20_stream_init, 3}]}]},
			{{chacha20_stream_final, 1}, [{jose_chacha20, [{chacha20_stream_init, 3}, {chacha20_stream_exor, 2}]}]}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, chacha20_exor, 4) ->
	Count = ?TV_CHACHA20_Count(),
	Nonce = ?TV_CHACHA20_Nonce(),
	Key = ?TV_CHACHA20_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_CHACHA20_CipherText0(),
	CipherText1 = ?TV_CHACHA20_CipherText1(),
	CipherText2 = ?TV_CHACHA20_CipherText2(),
	PlainText = <<PlainText0/binary, PlainText1/binary, PlainText2/binary>>,
	CipherText = <<CipherText0/binary, CipherText1/binary, CipherText2/binary>>,
	?expect(CipherText, Module, chacha20_exor, [PlainText, Count, Nonce, Key]);
support_check(Module, chacha20_stream_init, 3) ->
	Count = ?TV_CHACHA20_Count(),
	Nonce = ?TV_CHACHA20_Nonce(),
	Key = ?TV_CHACHA20_Key(),
	State = Module:chacha20_stream_init(Count, Nonce, Key),
	_ = Module:chacha20_stream_final(State),
	ok;
support_check(Module, chacha20_stream_exor, 2) ->
	Count = ?TV_CHACHA20_Count(),
	Nonce = ?TV_CHACHA20_Nonce(),
	Key = ?TV_CHACHA20_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	CipherText0 = ?TV_CHACHA20_CipherText0(),
	CipherText1 = ?TV_CHACHA20_CipherText1(),
	CipherText2 = ?TV_CHACHA20_CipherText2(),
	State0 = Module:chacha20_stream_init(Count, Nonce, Key),
	{State1, ActualCipherText0} = Module:chacha20_stream_exor(State0, PlainText0),
	{State2, ActualCipherText1} = Module:chacha20_stream_exor(State1, PlainText1),
	{State3, ActualCipherText2} = Module:chacha20_stream_exor(State2, PlainText2),
	_ = Module:chacha20_stream_final(State3),
	?expect([
		{{State1, CipherText0}, {State1, ActualCipherText0}, Module, chacha20_stream_exor, [State0, PlainText0]},
		{{State2, CipherText1}, {State2, ActualCipherText1}, Module, chacha20_stream_exor, [State1, PlainText1]},
		{{State3, CipherText2}, {State3, ActualCipherText2}, Module, chacha20_stream_exor, [State1, PlainText2]}
	]);
support_check(Module, chacha20_stream_final, 1) ->
	Count = ?TV_CHACHA20_Count(),
	Nonce = ?TV_CHACHA20_Nonce(),
	Key = ?TV_CHACHA20_Key(),
	PlainText0 = ?TV_PlainText0(),
	PlainText1 = ?TV_PlainText1(),
	PlainText2 = ?TV_PlainText2(),
	State0 = Module:chacha20_stream_init(Count, Nonce, Key),
	{State1, _ActualCipherText0} = Module:chacha20_stream_exor(State0, PlainText0),
	{State2, _ActualCipherText1} = Module:chacha20_stream_exor(State1, PlainText1),
	{State3, _ActualCipherText2} = Module:chacha20_stream_exor(State2, PlainText2),
	?expect(<<>>, Module, chacha20_stream_final, [State3]).

%%====================================================================
%% jose_chacha20 callbacks
%%====================================================================

-spec chacha20_exor(Input, Count, Nonce, Key) -> Output when
	Input :: jose_chacha20:input(),
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	Key :: jose_chacha20:chacha20_key(),
	Output :: jose_chacha20:output().
chacha20_exor(Input, Count, Nonce, Key)
		when is_binary(Input)
		andalso bit_size(Count) =:= 32
		andalso bit_size(Nonce) =:= 96
		andalso bit_size(Key) =:= 256 ->
	?resolve([Input, Count, Nonce, Key]).

-spec chacha20_stream_init(Count, Nonce, Key) -> ChaCha20State when
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	Key :: jose_chacha20:chacha20_key(),
	ChaCha20State :: jose_chacha20:chacha20_state().
chacha20_stream_init(Count, Nonce, Key)
		when bit_size(Count) =:= 32
		andalso bit_size(Nonce) =:= 96
		andalso bit_size(Key) =:= 256 ->
	?resolve([Count, Nonce, Key]).

-spec chacha20_stream_exor(ChaCha20State, Input) -> {NewChaCha20State, Output} when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Input :: jose_chacha20:input(),
	NewChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
chacha20_stream_exor(State, Input) ->
	?resolve([State, Input]).

-spec chacha20_stream_final(ChaCha20State) -> Output when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
chacha20_stream_final(State) ->
	?resolve([State]).
