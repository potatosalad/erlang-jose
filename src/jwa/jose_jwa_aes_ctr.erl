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
-module(jose_jwa_aes_ctr).

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
-record(jose_jwa_aes_128_ctr, {
	key = <<0:128>> :: jose_aes_ctr:aes_128_key(),
	iv = <<0:128>> :: jose_aes_ctr:aes_ctr_iv(),
	block = <<>> :: binary()
}).
-record(jose_jwa_aes_192_ctr, {
	key = <<0:192>> :: jose_aes_ctr:aes_192_key(),
	iv = <<0:128>> :: jose_aes_ctr:aes_ctr_iv(),
	block = <<>> :: binary()
}).
-record(jose_jwa_aes_256_ctr, {
	key = <<0:256>> :: jose_aes_ctr:aes_256_key(),
	iv = <<0:128>> :: jose_aes_ctr:aes_ctr_iv(),
	block = <<>> :: binary()
}).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_aes_ctr,
		priority => low,
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
	State0 = jose_aes_ctr:aes_128_ctr_stream_init(IV, Key),
	{State1, Output} = jose_aes_ctr:aes_128_ctr_stream_exor(State0, Input),
	<<>> = jose_aes_ctr:aes_128_ctr_stream_final(State1),
	Output.

-spec aes_128_ctr_stream_init(IV, Key) -> Aes128CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_128_key(),
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state().
aes_128_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 128 ->
	#jose_jwa_aes_128_ctr{key = Key, iv = IV, block = <<>>}.

-spec aes_128_ctr_stream_exor(Aes128CtrState, Input) -> {NewAes128CtrState, Output} when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_stream_exor(State = #jose_jwa_aes_128_ctr{}, Input = <<>>) ->
	{State, Input};
aes_128_ctr_stream_exor(#jose_jwa_aes_128_ctr{key = Key, iv = IV, block = Block}, Input) when byte_size(Input) > 0 ->
	aes_ctr_stream_exor(fun jose_aes_ecb:aes_128_ecb_encrypt/2, fun make_aes_128_ctr/3, IV, Key, Block, Input, <<>>).

-spec aes_128_ctr_stream_final(Aes128CtrState) -> Output when
	Aes128CtrState :: jose_aes_ctr:aes_128_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_128_ctr_stream_final(_State = #jose_jwa_aes_128_ctr{}) ->
	<<>>.

-spec aes_192_ctr_stream_init(IV, Key) -> Aes192CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state().
aes_192_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 192 ->
	#jose_jwa_aes_192_ctr{key = Key, iv = IV, block = <<>>}.

-spec aes_192_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_192_key(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 192 ->
	State0 = jose_aes_ctr:aes_192_ctr_stream_init(IV, Key),
	{State1, Output} = jose_aes_ctr:aes_192_ctr_stream_exor(State0, Input),
	<<>> = jose_aes_ctr:aes_192_ctr_stream_final(State1),
	Output.

-spec aes_192_ctr_stream_exor(Aes192CtrState, Input) -> {NewAes192CtrState, Output} when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_stream_exor(State = #jose_jwa_aes_192_ctr{}, Input = <<>>) ->
	{State, Input};
aes_192_ctr_stream_exor(#jose_jwa_aes_192_ctr{key = Key, iv = IV, block = Block}, Input) when byte_size(Input) > 0 ->
	aes_ctr_stream_exor(fun jose_aes_ecb:aes_192_ecb_encrypt/2, fun make_aes_192_ctr/3, IV, Key, Block, Input, <<>>).

-spec aes_192_ctr_stream_final(Aes192CtrState) -> Output when
	Aes192CtrState :: jose_aes_ctr:aes_192_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_192_ctr_stream_final(_State = #jose_jwa_aes_192_ctr{}) ->
	<<>>.

-spec aes_256_ctr_exor(Input, IV, Key) -> Output when
	Input :: jose_aes_ctr:input(),
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_exor(Input, IV, Key)
		when is_binary(Input)
		andalso bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 256 ->
	State0 = jose_aes_ctr:aes_256_ctr_stream_init(IV, Key),
	{State1, Output} = jose_aes_ctr:aes_256_ctr_stream_exor(State0, Input),
	<<>> = jose_aes_ctr:aes_256_ctr_stream_final(State1),
	Output.

-spec aes_256_ctr_stream_init(IV, Key) -> Aes256CtrState when
	IV :: jose_aes_ctr:aes_ctr_iv(),
	Key :: jose_aes_ctr:aes_256_key(),
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state().
aes_256_ctr_stream_init(IV, Key)
		when bit_size(IV) =:= 128
		andalso bit_size(Key) =:= 256 ->
	#jose_jwa_aes_256_ctr{key = Key, iv = IV, block = <<>>}.

-spec aes_256_ctr_stream_exor(Aes256CtrState, Input) -> {NewAes256CtrState, Output} when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Input :: jose_aes_ctr:input(),
	NewAes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_stream_exor(State = #jose_jwa_aes_256_ctr{}, Input = <<>>) ->
	{State, Input};
aes_256_ctr_stream_exor(#jose_jwa_aes_256_ctr{key = Key, iv = IV, block = Block}, Input) when byte_size(Input) > 0 ->
	aes_ctr_stream_exor(fun jose_aes_ecb:aes_256_ecb_encrypt/2, fun make_aes_256_ctr/3, IV, Key, Block, Input, <<>>).

-spec aes_256_ctr_stream_final(Aes256CtrState) -> Output when
	Aes256CtrState :: jose_aes_ctr:aes_256_ctr_state(),
	Output :: jose_aes_ctr:output().
aes_256_ctr_stream_final(_State = #jose_jwa_aes_256_ctr{}) ->
	<<>>.

%%%-------------------------------------------------------------------
%%% Internal AES-CTR functions
%%%-------------------------------------------------------------------

%% @private
aes_ctr_stream_exor(_BlockFun, StateFun, IV, Key, Block, <<>>, Output) ->
	State = StateFun(Key, IV, Block),
	{State, Output};
aes_ctr_stream_exor(BlockFun, StateFun, IV0 = <<Counter:1/unsigned-big-integer-unit:128>>, Key, <<>>, Input, Output) ->
	Block = BlockFun(IV0, Key),
	IV1 = <<(Counter + 1):1/unsigned-big-integer-unit:128>>,
	aes_ctr_stream_exor(BlockFun, StateFun, IV1, Key, Block, Input, Output);
aes_ctr_stream_exor(BlockFun, StateFun, IV, Key, Block, Input, Output) ->
	BlockSize = byte_size(Block),
	InputSize = byte_size(Input),
	case Input of
		<<InputNext:BlockSize/binary, InputRest/binary>> ->
			OutputNext = crypto:exor(Block, InputNext),
			aes_ctr_stream_exor(BlockFun, StateFun, IV, Key, <<>>, InputRest, <<Output/binary, OutputNext/binary>>);
		_ ->
			<<BlockNext:InputSize/binary, BlockRest/binary>> = Block,
			OutputNext = crypto:exor(BlockNext, Input),
			aes_ctr_stream_exor(BlockFun, StateFun, IV, Key, BlockRest, <<>>, <<Output/binary, OutputNext/binary>>)
	end.

%% @private
make_aes_128_ctr(Key, IV, Block) ->
	#jose_jwa_aes_128_ctr{key = Key, iv = IV, block = Block}.

%% @private
make_aes_192_ctr(Key, IV, Block) ->
	#jose_jwa_aes_192_ctr{key = Key, iv = IV, block = Block}.

%% @private
make_aes_256_ctr(Key, IV, Block) ->
	#jose_jwa_aes_256_ctr{key = Key, iv = IV, block = Block}.
