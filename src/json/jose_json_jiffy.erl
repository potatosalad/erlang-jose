%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_json_jiffy).
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
            {app, jiffy},
            jiffy
        ]
    }.

%%====================================================================
%% jose_json callbacks
%%====================================================================

-spec decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
decode(JSON) when is_binary(JSON) ->
    jiffy:decode(JSON, [return_maps]).

-spec encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().
encode(Map) when is_map(Map) ->
    jiffy:encode(sort(Map));
encode(List) when is_list(List) ->
    jiffy:encode(sort(List));
encode(Term) ->
    jiffy:encode(Term).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
sort(Map) when is_map(Map) ->
    {[{sort(Key), sort(Val)} || {Key, Val} <- maps:to_list(Map)]};
sort(List) when is_list(List) ->
    [sort(Term) || Term <- List];
sort(Term) ->
    Term.
