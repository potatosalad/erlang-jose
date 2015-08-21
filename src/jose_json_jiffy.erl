%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_json_jiffy).
-behaviour(jose_json).

%% jose_json callbacks
-export([decode/1]).
-export([encode/1]).

%%====================================================================
%% jose_json callbacks
%%====================================================================

decode(Binary) ->
	jiffy:decode(Binary, [return_maps]).

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
