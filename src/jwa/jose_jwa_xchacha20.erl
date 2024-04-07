%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305
%%% See https://tools.ietf.org/html/draft-irtf-cfrg-xchacha
%%% @end
%%% Created :  14 Sep 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_xchacha20).

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
%% Internal API
-export([
    encrypt/4,
    subkey_and_nonce/2
]).

%% Records
-record(jose_jwa_xchacha20, {
    key = <<0:256>> :: jose_xchacha20:xchacha20_key(),
    count = <<0:32>> :: jose_xchacha20:xchacha20_count(),
    nonce = <<0:192>> :: jose_xchacha20:xchacha20_nonce(),
    block = <<>> :: binary()
}).

%%%=============================================================================
%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_xchacha20,
        priority => low,
        requirements => [
            {app, crypto},
            crypto
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
    State0 = jose_xchacha20:xchacha20_stream_init(Count, Nonce, Key),
    {State1, Output} = jose_xchacha20:xchacha20_stream_exor(State0, Input),
    <<>> = jose_xchacha20:xchacha20_stream_final(State1),
    Output.

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
    #jose_jwa_xchacha20{key = Key, count = Count, nonce = Nonce, block = <<>>}.

-spec xchacha20_stream_exor(Xchacha20State, Input) -> {NewXchacha20State, Output} when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Input :: jose_xchacha20:input(),
    NewXchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_exor(State = #jose_jwa_xchacha20{}, Input = <<>>) ->
    {State, Input};
xchacha20_stream_exor(_State = #jose_jwa_xchacha20{key = Key, nonce = Nonce, count = Count, block = Block}, Input) ->
    xchacha20_stream_exor(Count, Nonce, Key, Block, Input, <<>>).

-spec xchacha20_stream_final(Xchacha20State) -> Output when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_final(_State = #jose_jwa_xchacha20{}) ->
    <<>>.

%%%=============================================================================
%% Internal API functions
%%%=============================================================================

encrypt(Key, Counter, Nonce0, Plaintext) ->
    {Subkey, Nonce} = subkey_and_nonce(Key, Nonce0),
    jose_jwa_chacha20:encrypt(Subkey, Counter, Nonce, Plaintext).

subkey_and_nonce(Key, <<Nonce0:128/bitstring, Nonce1:64/bitstring>>) ->
    Subkey = jose_hchacha20:hchacha20_subkey(Nonce0, Key),
    Nonce = <<0:32, Nonce1:64/bitstring>>,
    {Subkey, Nonce}.

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
    State = #jose_jwa_xchacha20{key = Key, count = Count, nonce = Nonce, block = Block},
    {State, Output};
xchacha20_stream_exor(Count0 = <<Counter:32/unsigned-little-integer-unit:1>>, Nonce, Key, <<>>, Input, Output) ->
    InputSize = byte_size(Input),
    Pad = pad64(Input),
    PadSize = byte_size(Pad),
    PadInput = <<Input/binary, Pad/binary>>,
    PadInputSize = byte_size(PadInput),
    {ChaCha20Key, ChaCha20Nonce} = subkey_and_nonce(Key, Nonce),
    <<OutputNext:InputSize/binary, Block:PadSize/binary>> = jose_chacha20:chacha20_exor(
        PadInput, Count0, ChaCha20Nonce, ChaCha20Key
    ),
    Count1 = <<(Counter + (PadInputSize div 64)):32/unsigned-little-integer-unit:1>>,
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
