%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  01 Mar 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_sha3_libdecaf).

-behaviour(jose_provider).
-behaviour(jose_sha3).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_sha3 callbacks
-export([
    sha3_224/1,
    sha3_256/1,
    sha3_384/1,
    sha3_512/1,
    shake128/2,
    shake256/2
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_sha3,
        priority => normal,
        requirements => [
            {app, libdecaf},
            libdecaf_sha3
        ]
    }.

%%====================================================================
%% jose_sha3 callbacks
%%====================================================================

-spec sha3_224(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_224_output().
sha3_224(Input) ->
    libdecaf_sha3:hash(sha3_224, Input).

-spec sha3_256(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_256_output().
sha3_256(Input) ->
    libdecaf_sha3:hash(sha3_256, Input).

-spec sha3_384(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_384_output().
sha3_384(Input) ->
    libdecaf_sha3:hash(sha3_384, Input).

-spec sha3_512(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_512_output().
sha3_512(Input) ->
    libdecaf_sha3:hash(sha3_512, Input).

-spec shake128(Input, OutputSize) -> Output when
    Input :: jose_sha3:input(), OutputSize :: jose_sha3:shake128_output_size(), Output :: jose_sha3:shake128_output().
shake128(Input, OutputSize) ->
    libdecaf_sha3:xof(shake128, Input, OutputSize).

-spec shake256(Input, OutputSize) -> Output when
    Input :: jose_sha3:input(), OutputSize :: jose_sha3:shake256_output_size(), Output :: jose_sha3:shake256_output().
shake256(Input, OutputSize) ->
    libdecaf_sha3:xof(shake256, Input, OutputSize).
