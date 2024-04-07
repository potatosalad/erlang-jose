%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_app).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-behaviour(application).

%% application callbacks
-export([
    start/2,
    stop/1,
    config_change/3
]).

%%%=============================================================================
%%% application callbacks
%%%=============================================================================

-spec start(StartType, StartArgs) -> {ok, Pid} | {ok, Pid, State} | {error, Reason} when
    StartType :: application:start_type(),
    StartArgs :: term(),
    Pid :: pid(),
    State :: term(),
    Reason :: term().
start(_StartType, _StartArgs) ->
    {ok, SupPid} = jose_sup:start_link(),
    {ok, SupPid}.

-spec stop(State) -> Ignored when
    State :: term(),
    Ignored :: term().
stop(_State) ->
    ok.

-spec config_change(Changed, New, Removed) -> ok when
    Changed :: [{Par, Val}], New :: [{Par, Val}], Removed :: [Par], Par :: atom(), Val :: term().
config_change(_Changed, _New, _Removed) ->
    jose_server:config_change().

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
