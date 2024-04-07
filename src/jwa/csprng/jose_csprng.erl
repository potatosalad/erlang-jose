%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 0; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc Cryptographically secure pseudorandom number generator (CSPRNG)
%%% See [https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator]
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_csprng).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type bit_size() :: non_neg_integer().
-type bit_output() :: bitstring().
-type byte_size() :: non_neg_integer().
-type byte_output() :: binary().
-type seed() :: binary().

-export_type([
    bit_size/0,
    bit_output/0,
    byte_size/0,
    byte_output/0,
    seed/0
]).

%% Callbacks
-callback init() -> ok.
-callback random_bits(BitSize) -> BitOutput when
    BitSize :: jose_csprng:bit_size(),
    BitOutput :: jose_csprng:bit_output().
-callback random_bytes(ByteSize) -> ByteOutput when
    ByteSize :: jose_csprng:byte_size(),
    ByteOutput :: jose_csprng:byte_output().
-callback stir(Seed) -> ok when
    Seed :: jose_csprng:seed().
-callback uniform(Lo, Hi) -> N when
    Lo :: integer(),
    Hi :: integer(),
    N :: integer().

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_csprng callbacks
-export([
    init/0,
    random_bits/1,
    random_bytes/1,
    stir/1,
    uniform/2
]).

%% Macros
-define(TV_RandomBits(), <<0:173>>).
-define(TV_RandomBytes(), <<0:192>>).
-define(TV_Seed(), ?b16d("00000000000000000000000000000000")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [
            [
                {init, 0},
                {random_bits, 1},
                {random_bytes, 1},
                {stir, 1}
            ]
        ],
        callbacks => [
            {{init, 0}, []},
            {{random_bits, 1}, []},
            {{random_bytes, 1}, []},
            {{stir, 1}, []},
            {{uniform, 2}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, init, 0) ->
    ?expect(ok, Module, init, []);
support_check(Module, random_bits, 1) ->
    BitOutput = ?TV_RandomBits(),
    BitSize = bit_size(BitOutput),
    ok = Module:init(),
    case Module:random_bits(BitSize) of
        <<ActualBitOutput:BitSize/bits>> when ActualBitOutput =/= BitOutput ->
            ok;
        BitOutput ->
            {error,
                ?expect_report(
                    Module, random_bits, [BitSize], BitOutput, {badmatch, "BitOutput must not be all zeroes"}
                )};
        ActualBitOutput ->
            {error,
                ?expect_report(
                    Module,
                    random_bits,
                    [BitSize],
                    ActualBitOutput,
                    {badmatch,
                        ?format("BitOutput should have been ~w-bits, but was ~w-bits instead", [
                            BitSize, bit_size(ActualBitOutput)
                        ])}
                )}
    end;
support_check(Module, random_bytes, 1) ->
    ByteOutput = ?TV_RandomBytes(),
    ByteSize = byte_size(ByteOutput),
    ok = Module:init(),
    case Module:random_bytes(ByteSize) of
        <<ActualByteOutput:ByteSize/binary>> when ActualByteOutput =/= ByteOutput ->
            ok;
        ByteOutput ->
            {error,
                ?expect_report(
                    Module, random_bytes, [ByteSize], ByteOutput, {badmatch, "ByteOutput must not be all zeroes"}
                )};
        ActualByteOutput ->
            {error,
                ?expect_report(
                    Module,
                    random_bytes,
                    [ByteSize],
                    ActualByteOutput,
                    {badmatch,
                        ?format("ByteOutput should have been ~w-bytes, but was ~w-bytes instead", [
                            ByteSize, byte_size(ActualByteOutput)
                        ])}
                )}
    end;
support_check(Module, stir, 1) ->
    Seed = ?TV_Seed(),
    ok = Module:init(),
    ?expect(ok, Module, stir, [Seed]);
support_check(Module, uniform, 2) ->
    Lo = 0,
    Hi = 1,
    N = 0,
    ?expect(N, Module, uniform, [Lo, Hi]).

%%====================================================================
%% jose_sha1 callbacks
%%====================================================================

-spec init() -> ok.
init() ->
    ?resolve([]).

-spec random_bits(BitSize) -> BitOutput when
    BitSize :: jose_csprng:bit_size(),
    BitOutput :: jose_csprng:bit_output().
random_bits(BitSize) when (is_integer(BitSize) andalso BitSize >= 0) ->
    ?resolve([BitSize]).

-spec random_bytes(ByteSize) -> ByteOutput when
    ByteSize :: jose_csprng:byte_size(),
    ByteOutput :: jose_csprng:byte_output().
random_bytes(ByteSize) when (is_integer(ByteSize) andalso ByteSize >= 0) ->
    ?resolve([ByteSize]).

-spec stir(Seed) -> ok when
    Seed :: jose_csprng:seed().
stir(Seed) when is_binary(Seed) ->
    ?resolve([Seed]).

-spec uniform(Lo, Hi) -> N when
    Lo :: integer(),
    Hi :: integer(),
    N :: integer().
uniform(Lo, Hi) when is_integer(Lo) andalso is_integer(Hi) andalso Lo < Hi ->
    ?resolve([Lo, Hi]).
