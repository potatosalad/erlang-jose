%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_chacha20_crypto).

-behaviour(jose_provider).
-behaviour(jose_chacha20).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_chacha20 callbacks
-export([
	chacha20_exor/4,
	chacha20_stream_init/3,
	chacha20_stream_exor/2,
	chacha20_stream_final/1
]).

%% Records
-record(jose_chacha20_crypto, {
	crypto_state = undefined :: undefined | crypto:crypto_state()
}).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_chacha20,
		priority => high,
		requirements => [
			{app, crypto},
			crypto
		]
	}.

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
	IV = make_iv(Count, Nonce),
	crypto:crypto_one_time(chacha20, Key, IV, Input, true).

-spec chacha20_stream_init(Count, Nonce, Key) -> ChaCha20State when
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	Key :: jose_chacha20:chacha20_key(),
	ChaCha20State :: jose_chacha20:chacha20_state().
chacha20_stream_init(Count, Nonce, Key)
		when bit_size(Count) =:= 32
		andalso bit_size(Nonce) =:= 96
		andalso bit_size(Key) =:= 256 ->
	IV = make_iv(Count, Nonce),
	#jose_chacha20_crypto{crypto_state = crypto:crypto_init(chacha20, Key, IV, true)}.

-spec chacha20_stream_exor(ChaCha20State, Input) -> {NewChaCha20State, Output} when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Input :: jose_chacha20:input(),
	NewChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
chacha20_stream_exor(State = #jose_chacha20_crypto{}, Input = <<>>) ->
	{State, Input};
chacha20_stream_exor(State = #jose_chacha20_crypto{crypto_state = CryptoState}, Input) when byte_size(Input) > 0 ->
	Output = crypto:crypto_update(CryptoState, Input),
	{State, Output}.

-spec chacha20_stream_final(ChaCha20State) -> Output when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
chacha20_stream_final(_State = #jose_chacha20_crypto{crypto_state = CryptoState}) ->
	crypto:crypto_final(CryptoState).

%%%-------------------------------------------------------------------
%%% Internal ChaCha20 functions
%%%-------------------------------------------------------------------

%% @private
-spec make_iv(Count, Nonce) -> IV when
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	IV :: <<_:128>>.
make_iv(Count, Nonce)
		when bit_size(Count) =:= 32
		andalso bit_size(Nonce) =:= 96 ->
	<<Count:32/bits, Nonce:96/bits>>.
