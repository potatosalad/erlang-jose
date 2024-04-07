%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_sha3_crypto).

-behaviour(jose_provider).
-behaviour(jose_sha3).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_sha3 callbacks
-export([
    sha3_224/1,
    sha3_256/1,
    sha3_384/1,
    sha3_512/1
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_sha3,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%====================================================================
%% jose_sha3 callbacks
%%====================================================================

-spec sha3_224(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_224_output().
sha3_224(Input) ->
    crypto:hash(sha3_224, Input).

-spec sha3_256(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_256_output().
sha3_256(Input) ->
    crypto:hash(sha3_256, Input).

-spec sha3_384(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_384_output().
sha3_384(Input) ->
    crypto:hash(sha3_384, Input).

-spec sha3_512(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_512_output().
sha3_512(Input) ->
    crypto:hash(sha3_512, Input).
