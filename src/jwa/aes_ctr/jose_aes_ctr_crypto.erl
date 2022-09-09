%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_aes_ctr_crypto).

-behaviour(jose_provider).
-behaviour(jose_aes_ctr).

%% jose_provider callbacks
-export([provider_info/0]).
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

%% Records
-record(jose_aes_128_ctr_crypto, {
	crypto_state = undefined :: undefined | crypto:crypto_state()
}).
-record(jose_aes_192_ctr_crypto, {
	crypto_state = undefined :: undefined | crypto:crypto_state()
}).
-record(jose_aes_256_ctr_crypto, {
	crypto_state = undefined :: undefined | crypto:crypto_state()
}).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_aes_ctr,
		priority => high,
		requirements => [
			{app, crypto},
			crypto
		]
	}.

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
	crypto:crypto_one_time(aes_128_ctr, Key, IV, Input, true).

-spec aes_128_ctr_stream_init(IV, Key) -> Aes128CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_128_key(),
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state().
aes_128_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 128 ->
	#jose_aes_128_ctr_crypto{crypto_state = crypto:crypto_init(aes_128_ctr, Key, IV, true)}.

-spec aes_128_ctr_stream_exor(Aes128CtrState, Input) -> {NewAes128CtrState, Output} when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_stream_exor(State = #jose_aes_128_ctr_crypto{}, Input = <<>>) ->
	{State, Input};
aes_128_ctr_stream_exor(State = #jose_aes_128_ctr_crypto{crypto_state = CryptoState}, Input) when byte_size(Input) > 0 ->
	Output = crypto:crypto_update(CryptoState, Input),
	{State, Output}.

-spec aes_128_ctr_stream_final(Aes128CtrState) -> Output when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_stream_final(_State = #jose_aes_128_ctr_crypto{crypto_state = CryptoState}) ->
	crypto:crypto_final(CryptoState).

-spec aes_192_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 192 ->
	crypto:crypto_one_time(aes_192_ctr, Key, IV, Input, true).

-spec aes_192_ctr_stream_init(IV, Key) -> Aes192CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state().
aes_192_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 192 ->
	#jose_aes_192_ctr_crypto{crypto_state = crypto:crypto_init(aes_192_ctr, Key, IV, true)}.

-spec aes_192_ctr_stream_exor(Aes192CtrState, Input) -> {NewAes192CtrState, Output} when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_stream_exor(State = #jose_aes_192_ctr_crypto{}, Input = <<>>) ->
	{State, Input};
aes_192_ctr_stream_exor(State = #jose_aes_192_ctr_crypto{crypto_state = CryptoState}, Input) when byte_size(Input) > 0 ->
	Output = crypto:crypto_update(CryptoState, Input),
	{State, Output}.

-spec aes_192_ctr_stream_final(Aes192CtrState) -> Output when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_stream_final(_State = #jose_aes_192_ctr_crypto{crypto_state = CryptoState}) ->
	crypto:crypto_final(CryptoState).

-spec aes_256_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 256 ->
	crypto:crypto_one_time(aes_256_ctr, Key, IV, Input, true).

-spec aes_256_ctr_stream_init(IV, Key) -> Aes256CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state().
aes_256_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 256 ->
	#jose_aes_256_ctr_crypto{crypto_state = crypto:crypto_init(aes_256_ctr, Key, IV, true)}.

-spec aes_256_ctr_stream_exor(Aes256CtrState, Input) -> {NewAes256CtrState, Output} when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_stream_exor(State = #jose_aes_256_ctr_crypto{}, Input = <<>>) ->
	{State, Input};
aes_256_ctr_stream_exor(State = #jose_aes_256_ctr_crypto{crypto_state = CryptoState}, Input) when byte_size(Input) > 0 ->
	Output = crypto:crypto_update(CryptoState, Input),
	{State, Output}.

-spec aes_256_ctr_stream_final(Aes256CtrState) -> Output when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_stream_final(_State = #jose_aes_256_ctr_crypto{crypto_state = CryptoState}) ->
	crypto:crypto_final(CryptoState).

%%%-------------------------------------------------------------------
%%% Internal AES-CTR functions
%%%-------------------------------------------------------------------
