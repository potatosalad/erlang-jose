%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_app).
-behaviour(application).

%% Application callbacks
-export([start/2]).
-export([stop/1]).
-export([config_change/3]).

%%====================================================================
%%% Application callbacks
%%%===================================================================

-spec start(StartType, StartArgs) -> {ok, Pid} | {ok, Pid, State} | {error, Reason} when
	StartType :: application:start_type(), StartArgs :: term(), Pid :: pid(), State :: term(), Reason :: term().
start(_StartType, _StartArgs) ->
	jose_sup:start_link().

-spec stop(State) -> Ignored when State :: term(), Ignored :: any().
stop(_State) ->
	ok.

-spec config_change(Changed, New, Removed) -> ok when
	Changed :: [{Par, Val}], New :: [{Par, Val}], Removed :: [Par], Par :: atom(), Val :: term().
config_change(_Changed, _New, _Removed) ->
	jose_server:config_change().
