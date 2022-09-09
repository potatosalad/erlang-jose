%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  14 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_json_poison).
-behaviour(jose_provider).
-behaviour(jose_json).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_json callbacks
-export([
    decode/1,
    encode/1
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_json,
        priority => normal,
        requirements => [
            {app, poison},
            'Elixir.Poison'
        ]
    }.

%%====================================================================
%% jose_json callbacks
%%====================================================================

-spec decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
decode(JSON) when is_binary(JSON) ->
    'Elixir.Poison':'decode!'(JSON).

-spec encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().
encode(Term) ->
    'Elixir.Poison':'encode!'(Term).
