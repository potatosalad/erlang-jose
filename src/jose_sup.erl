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
-module(jose_sup).
-behaviour(supervisor).

-define(SUPERVISOR, ?MODULE).

%% OTP API
-export([start_link/0]).
%% supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% OTP API functions
%%%===================================================================

-spec start_link() -> {ok, pid()} | ignore | {error, supervisor:startlink_err()}.
start_link() ->
	supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

-spec init([]) -> {ok, {SupFlags, [ChildSpec]}} | ignore
	when SupFlags :: supervisor:sup_flags(), ChildSpec :: supervisor:child_spec().
init([]) ->
	ChildSpecs = [
		jose_support_check_sup:child_spec(),
		jose_support_resolve_sup:child_spec(),
		jose_support_statem:child_spec()
	],
	SupFlags = #{
		strategy => rest_for_one,
		intensity => 5,
		period => 10
	},
	{ok, {SupFlags, ChildSpecs}}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
