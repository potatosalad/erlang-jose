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
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_csprng_libsodium).

-behaviour(jose_provider).
-behaviour(jose_csprng).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_csprng callbacks
-export([
    init/0,
    random_bits/1,
    random_bytes/1,
    stir/1,
    uniform/2
]).

%%%=============================================================================
%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_csprng,
        priority => normal,
        requirements => [
            {app, libsodium},
            libsodium_randombytes
        ]
    }.

%%%=============================================================================
%% jose_csprng callbacks
%%%=============================================================================

-spec init() -> ok.
init() ->
    ok.

-spec random_bits(BitSize) -> BitOutput when
    BitSize :: jose_csprng:bit_size(),
    BitOutput :: jose_csprng:bit_output().
random_bits(BitSize) when BitSize rem 8 =:= 0 ->
    random_bytes(BitSize div 8);
random_bits(BitSize) when (is_integer(BitSize) andalso BitSize >= 0) ->
    ByteSize = ((BitSize + 7) div 8),
    <<BitOutput:BitSize/bits, _/bits>> = random_bytes(ByteSize),
    BitOutput.

-spec random_bytes(ByteSize) -> ByteOutput when
    ByteSize :: jose_csprng:byte_size(),
    ByteOutput :: jose_csprng:byte_output().
random_bytes(ByteSize) when (is_integer(ByteSize) andalso ByteSize >= 0) ->
    libsodium_randombytes:buf(ByteSize).

-spec stir(Seed) -> ok when
    Seed :: jose_csprng:seed().
stir(Seed) when is_binary(Seed) ->
    libsodium_randombytes:stir().

-spec uniform(Lo, Hi) -> N when
    Lo :: integer(),
    Hi :: integer(),
    N :: integer().
uniform(Lo, Hi) when is_integer(Lo) andalso is_integer(Hi) andalso Lo < Hi ->
    libsodium_randombytes:uniform(Hi - Lo) + Lo.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
