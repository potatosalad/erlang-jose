%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_sha1_crypto).

-behaviour(jose_provider).
-behaviour(jose_sha1).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_sha1 callbacks
-export([
	sha1/1
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_sha1,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%====================================================================
%% jose_sha1 callbacks
%%====================================================================

-spec sha1(Input) -> Output when
	Input :: jose_sha1:input(), Output :: jose_sha1:sha1_output().
sha1(Input) ->
	crypto:hash(sha, Input).
