%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose).

%% API
-export([require/1]).
-export([start/0]).

%%====================================================================
%% API functions
%%====================================================================

require([]) ->
	ok;
require([App | Apps]) ->
	case application:ensure_started(App) of
		ok ->
			require(Apps);
		StartError ->
			StartError
	end.

start() ->
	_ = application:load(?MODULE),
	{ok, Apps} = application:get_key(?MODULE, applications),
	case require(Apps) of
		ok ->
			application:ensure_started(?MODULE);
		StartError ->
			StartError
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
