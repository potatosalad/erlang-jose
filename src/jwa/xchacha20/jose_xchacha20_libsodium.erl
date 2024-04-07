%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_xchacha20_libsodium).

-behaviour(jose_provider).
-behaviour(jose_xchacha20).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_xchacha20 callbacks
-export([
    xchacha20_exor/4,
    xchacha20_stream_init/3,
    xchacha20_stream_exor/2,
    xchacha20_stream_final/1
]).

%% Records
-record(jose_xchacha20_libsodium, {
    key = <<0:256>> :: jose_xchacha20:xchacha20_key(),
    nonce = <<0:192>> :: jose_xchacha20:xchacha20_nonce(),
    count = 0 :: non_neg_integer(),
    block = <<>> :: binary()
}).

%%%=============================================================================
%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_xchacha20,
        priority => normal,
        requirements => [
            {app, libsodium},
            libsodium_crypto_stream_xchacha20
        ]
    }.

%%%=============================================================================
%% jose_xchacha20 callbacks
%%%=============================================================================

-spec xchacha20_exor(Input, Count, Nonce, Key) -> Output when
    Input :: jose_xchacha20:input(),
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Output :: jose_xchacha20:output().
xchacha20_exor(Input, Count, Nonce, Key) when
    is_binary(Input) andalso
        bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    IC = binary:decode_unsigned(Count, little),
    libsodium_crypto_stream_xchacha20:xor_ic(Input, Nonce, IC, Key).

-spec xchacha20_stream_init(Count, Nonce, Key) -> Xchacha20State when
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Xchacha20State :: jose_xchacha20:xchacha20_state().
xchacha20_stream_init(Count, Nonce, Key) when
    bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    IC = binary:decode_unsigned(Count, little),
    #jose_xchacha20_libsodium{key = Key, nonce = Nonce, count = IC, block = <<>>}.

-spec xchacha20_stream_exor(Xchacha20State, Input) -> {NewXchacha20State, Output} when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Input :: jose_xchacha20:input(),
    NewXchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_exor(State = #jose_xchacha20_libsodium{}, Input = <<>>) ->
    {State, Input};
xchacha20_stream_exor(
    _State = #jose_xchacha20_libsodium{key = Key, nonce = Nonce, count = Count, block = Block}, Input
) ->
    xchacha20_stream_exor(Count, Nonce, Key, Block, Input, <<>>).

-spec xchacha20_stream_final(Xchacha20State) -> Output when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_final(_State = #jose_xchacha20_libsodium{}) ->
    <<>>.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
pad64(X) when (byte_size(X) rem 64) == 0 ->
    <<>>;
pad64(X) ->
    binary:copy(<<0>>, 64 - (byte_size(X) rem 64)).

%% @private
xchacha20_stream_exor(Count, Nonce, Key, Block, <<>>, Output) ->
    State = #jose_xchacha20_libsodium{key = Key, count = Count, nonce = Nonce, block = Block},
    {State, Output};
xchacha20_stream_exor(Count0, Nonce, Key, <<>>, Input, Output) ->
    InputSize = byte_size(Input),
    Pad = pad64(Input),
    PadSize = byte_size(Pad),
    PadInput = <<Input/binary, Pad/binary>>,
    PadInputSize = byte_size(PadInput),
    <<OutputNext:InputSize/binary, Block:PadSize/binary>> = libsodium_crypto_stream_xchacha20:xor_ic(
        PadInput, Nonce, Count0, Key
    ),
    Count1 = Count0 + (PadInputSize div 64),
    xchacha20_stream_exor(Count1, Nonce, Key, Block, <<>>, <<Output/binary, OutputNext/binary>>);
xchacha20_stream_exor(Count, Nonce, Key, Block, Input, Output) ->
    BlockSize = byte_size(Block),
    InputSize = byte_size(Input),
    case Input of
        <<InputNext:BlockSize/binary, InputRest/binary>> ->
            OutputNext = crypto:exor(Block, InputNext),
            xchacha20_stream_exor(Count, Nonce, Key, <<>>, InputRest, <<Output/binary, OutputNext/binary>>);
        _ ->
            <<BlockNext:InputSize/binary, BlockRest/binary>> = Block,
            OutputNext = crypto:exor(BlockNext, Input),
            xchacha20_stream_exor(Count, Nonce, Key, BlockRest, <<>>, <<Output/binary, OutputNext/binary>>)
    end.
