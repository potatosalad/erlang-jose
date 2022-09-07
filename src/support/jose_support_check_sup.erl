%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  05 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_support_check_sup).
-behaviour(supervisor).

-define(SUPERVISOR, ?MODULE).

%% OTP API
-export([
    child_spec/0,
    start_link/0,
    start_child/3
]).
%% supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% OTP API functions
%%%===================================================================

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
	#{
		id => ?SUPERVISOR,
		start => {?MODULE, start_link, []},
		restart => permanent,
		shutdown => 5000,
		type => supervisor
	}.

-spec start_link() -> {ok, pid()} | ignore | {error, supervisor:startlink_err()}.
start_link() ->
	supervisor:start_link({local, ?SUPERVISOR}, ?MODULE, []).

-spec start_child(ReplyTo, Key, Module) -> supervisor:startchild_ret()
    when ReplyTo :: pid(), Key :: jose_support:key(), Module :: module().
start_child(ReplyTo, Key = {Behaviour, {FunctionName, Arity}}, ProviderKey = {Priority, ProviderModule})
        when is_pid(ReplyTo)
        andalso is_atom(Behaviour)
        andalso is_atom(FunctionName)
        andalso (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255)
        andalso is_integer(Priority)
        andalso is_atom(ProviderModule) ->
    supervisor:start_child(?SUPERVISOR, [ReplyTo, Key, ProviderKey]).

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

-spec init([]) -> {ok, {SupFlags, [ChildSpec]}} | ignore
	when SupFlags :: supervisor:sup_flags(), ChildSpec :: supervisor:child_spec().
init([]) ->
	ChildSpecs = [
		jose_support_check:child_spec()
	],
	SupFlags = #{
		strategy => simple_one_for_one,
		intensity => 0,
		period => 1
	},
	{ok, {SupFlags, ChildSpecs}}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
