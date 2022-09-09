%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Michael Klishin <michael@clojurewerkz.org>
%%% @copyright 2022, Michael Klishin
%%% @doc
%%%
%%% @end
%%% Created :  30 Jul 2022 by Michael Klishin <michael@clojurewerkz.org>
%%%-------------------------------------------------------------------
-module(jose_json_thoas).
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
            {app, thoas},
            thoas
        ]
    }.

%%====================================================================
%% jose_json callbacks
%%====================================================================

-spec decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
decode(JSON) when is_binary(JSON) ->
    case thoas:decode(JSON) of
        {ok, Value} ->
            Value;
        Error = {error, _Reason} ->
            error(Error)
    end.

-spec encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().
encode(Term) ->
    thoas:encode(Term).
