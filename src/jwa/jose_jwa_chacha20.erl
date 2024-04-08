%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc ChaCha20 and Poly1305 for IETF Protocols
%%% See https://tools.ietf.org/html/rfc7539
%%% @end
%%% Created :  31 May 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_chacha20).

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
%% API
-export([quarter_round/1]).
-export([column_round/1]).
-export([diagonal_round/1]).
-export([block/3]).
-export([encrypt/4]).

%% Macros
-define(math, jose_jwa_math).
-define(p, 16#100000000).
-define(rotl(X, R), ?math:mod((X bsl R) bor (X bsr (32 - R)), ?p)).

%% Records
-record(jose_jwa_chacha20, {
    key = <<0:256>> :: jose_chacha20:chacha20_key(),
    count = <<0:32>> :: jose_chacha20:chacha20_count(),
    nonce = <<0:96>> :: jose_chacha20:chacha20_nonce(),
    block = <<>> :: binary()
}).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_chacha20,
        priority => low,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%%=============================================================================
%%% jose_chacha20 callbacks
%%%=============================================================================

-spec chacha20_exor(Input, Count, Nonce, Key) -> Output when
    Input :: jose_chacha20:input(),
    Count :: jose_chacha20:chacha20_count(),
    Nonce :: jose_chacha20:chacha20_nonce(),
    Key :: jose_chacha20:chacha20_key(),
    Output :: jose_chacha20:output().
chacha20_exor(Input, Count, Nonce, Key) when
    is_binary(Input) andalso
        bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    State0 = jose_chacha20:chacha20_stream_init(Count, Nonce, Key),
    {State1, Output} = jose_chacha20:chacha20_stream_exor(State0, Input),
    <<>> = jose_chacha20:chacha20_stream_final(State1),
    Output.

-spec chacha20_stream_init(Count, Nonce, Key) -> ChaCha20State when
    Count :: jose_chacha20:chacha20_count(),
    Nonce :: jose_chacha20:chacha20_nonce(),
    Key :: jose_chacha20:chacha20_key(),
    ChaCha20State :: jose_chacha20:chacha20_state().
chacha20_stream_init(Count, Nonce, Key) when
    bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    #jose_jwa_chacha20{key = Key, count = Count, nonce = Nonce, block = <<>>}.

-spec chacha20_stream_exor(ChaCha20State, Input) -> {NewChaCha20State, Output} when
    ChaCha20State :: jose_chacha20:chacha20_state(),
    Input :: jose_chacha20:input(),
    NewChaCha20State :: jose_chacha20:chacha20_state(),
    Output :: jose_chacha20:output().
chacha20_stream_exor(State = #jose_jwa_chacha20{}, Input = <<>>) ->
    {State, Input};
chacha20_stream_exor(#jose_jwa_chacha20{key = Key, count = Count, nonce = Nonce, block = Block}, Input) when
    byte_size(Input) > 0
->
    chacha20_stream_exor(Count, Nonce, Key, Block, Input, <<>>).

-spec chacha20_stream_final(ChaCha20State) -> Output when
    ChaCha20State :: jose_chacha20:chacha20_state(),
    Output :: jose_chacha20:output().
chacha20_stream_final(_State = #jose_jwa_chacha20{}) ->
    <<>>.

%%%=============================================================================
%%% API functions
%%%=============================================================================

quarter_round({A0, B0, C0, D0}) ->
    A1 = ?math:mod(A0 + B0, ?p),
    D1 = ?rotl(D0 bxor A1, 16),
    C1 = ?math:mod(C0 + D1, ?p),
    B1 = ?rotl(B0 bxor C1, 12),
    A = ?math:mod(A1 + B1, ?p),
    D = ?rotl(D1 bxor A, 8),
    C = ?math:mod(C1 + D, ?p),
    B = ?rotl(B1 bxor C, 7),
    {A, B, C, D}.

column_round({X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12, X13, X14, X15}) ->
    {Y00, Y04, Y08, Y12} = quarter_round({X00, X04, X08, X12}),
    {Y01, Y05, Y09, Y13} = quarter_round({X01, X05, X09, X13}),
    {Y02, Y06, Y10, Y14} = quarter_round({X02, X06, X10, X14}),
    {Y03, Y07, Y11, Y15} = quarter_round({X03, X07, X11, X15}),
    {Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11, Y12, Y13, Y14, Y15}.

diagonal_round({Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11, Y12, Y13, Y14, Y15}) ->
    {Z00, Z05, Z10, Z15} = quarter_round({Y00, Y05, Y10, Y15}),
    {Z01, Z06, Z11, Z12} = quarter_round({Y01, Y06, Y11, Y12}),
    {Z02, Z07, Z08, Z13} = quarter_round({Y02, Y07, Y08, Y13}),
    {Z03, Z04, Z09, Z14} = quarter_round({Y03, Y04, Y09, Y14}),
    {Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, Z12, Z13, Z14, Z15}.

block(Key, Counter, Nonce) when
    is_binary(Key) andalso
        bit_size(Key) =:= 256 andalso
        is_integer(Counter) andalso
        Counter >= 0 andalso
        is_binary(Nonce) andalso
        bit_size(Nonce) =:= 96
->
    State = <<
        "expand 32-byte k",
        Key:256/bitstring,
        Counter:32/unsigned-little-integer-unit:1,
        Nonce:96/bitstring
    >>,
    WS0 = list_to_tuple([Word || <<Word:32/unsigned-little-integer-unit:1>> <= State]),
    WS1 = rounds(WS0, 10),
    WS2 = add(WS1, WS0),
    serialize(WS2).

encrypt(Key, Counter, Nonce, Plaintext) ->
    encrypt(Key, Counter, Nonce, Plaintext, 0, <<>>).

encrypt(_Key, _Counter, _Nonce, <<>>, _J, EncryptedMessage) ->
    EncryptedMessage;
encrypt(Key, Counter, Nonce, <<Block:64/binary, Rest/binary>>, J, EncryptedMessage) ->
    KeyStream = block(Key, Counter + J, Nonce),
    encrypt(Key, Counter, Nonce, Rest, J + 1, <<EncryptedMessage/binary, (crypto:exor(Block, KeyStream))/binary>>);
encrypt(Key, Counter, Nonce, Block, J, EncryptedMessage) ->
    BlockBytes = byte_size(Block),
    <<KeyStream:BlockBytes/binary, _/binary>> = block(Key, Counter + J, Nonce),
    <<EncryptedMessage/binary, (crypto:exor(Block, KeyStream))/binary>>.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
inner_block(State0) when
    is_tuple(State0) andalso
        tuple_size(State0) =:= 16
->
    State1 = column_round(State0),
    State2 = diagonal_round(State1),
    State2.

%% @private
rounds(S, 0) ->
    S;
rounds(S, N) when
    is_integer(N) andalso
        N > 0
->
    rounds(inner_block(S), N - 1).

%% @private
add(
    {X00, X01, X02, X03, X04, X05, X06, X07, X08, X09, X10, X11, X12, X13, X14, X15},
    {Y00, Y01, Y02, Y03, Y04, Y05, Y06, Y07, Y08, Y09, Y10, Y11, Y12, Y13, Y14, Y15}
) ->
    {
        X00 + Y00,
        X01 + Y01,
        X02 + Y02,
        X03 + Y03,
        X04 + Y04,
        X05 + Y05,
        X06 + Y06,
        X07 + Y07,
        X08 + Y08,
        X09 + Y09,
        X10 + Y10,
        X11 + Y11,
        X12 + Y12,
        X13 + Y13,
        X14 + Y14,
        X15 + Y15
    }.

%% @private
serialize({Z00, Z01, Z02, Z03, Z04, Z05, Z06, Z07, Z08, Z09, Z10, Z11, Z12, Z13, Z14, Z15}) ->
    <<
        Z00:32/unsigned-little-integer-unit:1,
        Z01:32/unsigned-little-integer-unit:1,
        Z02:32/unsigned-little-integer-unit:1,
        Z03:32/unsigned-little-integer-unit:1,
        Z04:32/unsigned-little-integer-unit:1,
        Z05:32/unsigned-little-integer-unit:1,
        Z06:32/unsigned-little-integer-unit:1,
        Z07:32/unsigned-little-integer-unit:1,
        Z08:32/unsigned-little-integer-unit:1,
        Z09:32/unsigned-little-integer-unit:1,
        Z10:32/unsigned-little-integer-unit:1,
        Z11:32/unsigned-little-integer-unit:1,
        Z12:32/unsigned-little-integer-unit:1,
        Z13:32/unsigned-little-integer-unit:1,
        Z14:32/unsigned-little-integer-unit:1,
        Z15:32/unsigned-little-integer-unit:1
    >>.

%% @private
chacha20_stream_exor(Count, Nonce, Key, Block, <<>>, Output) ->
    State = #jose_jwa_chacha20{key = Key, count = Count, nonce = Nonce, block = Block},
    {State, Output};
chacha20_stream_exor(<<Counter:1/unsigned-little-integer-unit:32>>, Nonce, Key, <<>>, Input, Output) ->
    Block = block(Key, Counter, Nonce),
    Count1 = <<(Counter + 1):1/unsigned-little-integer-unit:32>>,
    chacha20_stream_exor(Count1, Nonce, Key, Block, Input, Output);
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
