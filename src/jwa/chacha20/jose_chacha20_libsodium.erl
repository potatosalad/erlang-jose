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
-module(jose_chacha20_libsodium).

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
-record(jose_chacha20_libsodium, {
	key = <<0:256>> :: jose_chacha20:chacha20_key(),
	nonce = <<0:96>> :: jose_chacha20:chacha20_nonce(),
	count = 0 :: non_neg_integer(),
    block = <<>> :: binary()
}).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_chacha20,
		priority => normal,
		requirements => [
			{app, libsodium},
			libsodium_crypto_stream_chacha20
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
    IC = binary:decode_unsigned(Count, little),
    libsodium_crypto_stream_chacha20:ietf_xor_ic(Input, Nonce, IC, Key).

-spec chacha20_stream_init(Count, Nonce, Key) -> ChaCha20State when
	Count :: jose_chacha20:chacha20_count(),
	Nonce :: jose_chacha20:chacha20_nonce(),
	Key :: jose_chacha20:chacha20_key(),
	ChaCha20State :: jose_chacha20:chacha20_state().
chacha20_stream_init(Count, Nonce, Key)
		when bit_size(Count) =:= 32
		andalso bit_size(Nonce) =:= 96
		andalso bit_size(Key) =:= 256 ->
    IC = binary:decode_unsigned(Count, little),
    #jose_chacha20_libsodium{key = Key, nonce = Nonce, count = IC, block = <<>>}.

-spec chacha20_stream_exor(ChaCha20State, Input) -> {NewChaCha20State, Output} when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Input :: jose_chacha20:input(),
	NewChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
chacha20_stream_exor(State = #jose_chacha20_libsodium{}, Input = <<>>) ->
	{State, Input};
chacha20_stream_exor(_State = #jose_chacha20_libsodium{key = Key, nonce = Nonce, count = Count, block = Block}, Input) ->
	chacha20_stream_exor(Count, Nonce, Key, Block, Input, <<>>).

-spec chacha20_stream_final(ChaCha20State) -> Output when
	ChaCha20State :: jose_chacha20:chacha20_state(),
	Output :: jose_chacha20:output().
chacha20_stream_final(_State = #jose_chacha20_libsodium{}) ->
	<<>>.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
pad64(X) when (byte_size(X) rem 64) == 0 ->
	<<>>;
pad64(X) ->
	binary:copy(<< 0 >>, 64 - (byte_size(X) rem 64)).

%% @private
chacha20_stream_exor(Count, Nonce, Key, Block, <<>>, Output) ->
	State = #jose_chacha20_libsodium{key = Key, count = Count, nonce = Nonce, block = Block},
	{State, Output};
chacha20_stream_exor(Count0, Nonce, Key, <<>>, Input, Output) ->
	InputSize = byte_size(Input),
	Pad = pad64(Input),
	PadSize = byte_size(Pad),
	PadInput = <<Input/binary, Pad/binary>>,
	PadInputSize = byte_size(PadInput),
	<<OutputNext:InputSize/binary, Block:PadSize/binary>> = libsodium_crypto_stream_chacha20:ietf_xor_ic(PadInput, Nonce, Count0, Key),
	Count1 = Count0 + (PadInputSize div 64),
	chacha20_stream_exor(Count1, Nonce, Key, Block, <<>>, <<Output/binary, OutputNext/binary>>);
chacha20_stream_exor(Count, Nonce, Key, Block, Input, Output) ->
	BlockSize = byte_size(Block),
	InputSize = byte_size(Input),
	case Input of
		<<InputNext:BlockSize/binary, InputRest/binary>> ->
			OutputNext = crypto:exor(Block, InputNext),
			chacha20_stream_exor(Count, Nonce, Key, <<>>, InputRest, <<Output/binary, OutputNext/binary>>);
		_ ->
			<<BlockNext:InputSize/binary, BlockRest/binary>> = Block,
			OutputNext = crypto:exor(BlockNext, Input),
			chacha20_stream_exor(Count, Nonce, Key, BlockRest, <<>>, <<Output/binary, OutputNext/binary>>)
	end.
