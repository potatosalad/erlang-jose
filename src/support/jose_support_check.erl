%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  05 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_support_check).

%% OTP API
-export([
	child_spec/0,
	start_link/3
]).
%% Internal API
-export([
	init/4
]).
%% sys callbacks
-export([
	system_code_change/4,
	system_continue/3,
	system_get_state/1,
	system_replace_state/2,
	system_terminate/4
]).

%%%===================================================================
%%% OTP API functions
%%%===================================================================

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
	#{
		id => undefined,
		start => {?MODULE, start_link, []},
		restart => temporary,
		shutdown => brutal_kill,
		type => worker
	}.

-spec start_link(ReplyTo, Key, ProviderKey) -> {ok, pid()} | {error, Reason}
	when ReplyTo :: pid(), Key :: jose_support:key(), ProviderKey :: {integer(), module()}, Reason :: term().
start_link(ReplyTo, Key = {Behaviour, {FunctionName, Arity}}, ProviderKey = {Priority, ProviderModule})
		when is_pid(ReplyTo)
		andalso is_atom(Behaviour)
		andalso is_atom(FunctionName)
		andalso (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255)
		andalso is_integer(Priority)
        andalso is_atom(ProviderModule) ->
	proc_lib:start_link(?MODULE, init, [self(), ReplyTo, Key, ProviderKey]).

%%%===================================================================
%%% Internal API functions
%%%===================================================================

%% @private
init(Parent, ReplyTo, Key = {_Behaviour, {_FunctionName, _Arity}}, ProviderKey) ->
	Debug0 = sys:debug_options([]),
	ok = proc_lib:init_ack(Parent, {ok, self()}),
	Debug1 = sys_debug(Debug0, {in, {Key, ProviderKey}, ReplyTo}),
	exec(Parent, Debug1, ReplyTo, Key, ProviderKey).

%% @private
exec(Parent, Debug0, ReplyTo, Key = {Behaviour, {FunctionName, Arity}}, ProviderKey = {_Priority, ProviderModule}) ->
	_ = code:ensure_loaded(Behaviour),
	_ = code:ensure_loaded(ProviderModule),
	Reply =
		case erlang:function_exported(Behaviour, support_check, 3) of
			true ->
				try Behaviour:support_check(ProviderModule, FunctionName, Arity) of
					ok ->
						{Key, ProviderKey, ok};
					{error, ExpectReport} ->
						{Key, ProviderKey, {error, ExpectReport}}
				catch
					Class:Reason:Stacktrace ->
						{Key, ProviderKey, {exception, {Class, Reason, Stacktrace}}}
				end;
			false ->
				{Key, ProviderKey, {function_not_exported, {Behaviour, support_check, 3}}}
		end,
	_ = ReplyTo ! Reply,
	Debug1 = sys_debug(Debug0, {out, Reply, ReplyTo}),
	before_terminate_loop(Parent, Debug1, ReplyTo, Key, ProviderKey).

%% @private
before_terminate_loop(Parent, Debug, ReplyTo, Key, ProviderKey) ->
	receive
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, Debug, {ReplyTo, Key, ProviderKey})
	after
		0 ->
			terminate(normal, Parent, Debug, ReplyTo, Key, ProviderKey)
	end.

%% @private
terminate(Reason, _Parent, Debug0, ReplyTo, Key, ProviderKey) ->
	_Debug1 = sys_debug(Debug0, {terminate, Reason, {ReplyTo, Key, ProviderKey}}),
	erlang:exit(Reason).

%%%===================================================================
%%% sys callbacks
%%%===================================================================

system_code_change(Misc, _Module, _OldVsn, _Extra) ->
	{ok, Misc}.

system_continue(Parent, Debug, {ReplyTo, Key, ProviderKey}) ->
	before_terminate_loop(Parent, Debug, ReplyTo, Key, ProviderKey).

system_get_state(Misc) ->
	{ok, Misc}.

system_replace_state(StateFun, Misc) ->
	NMisc = StateFun(Misc),
	{ok, NMisc, NMisc}.

system_terminate(Reason, Parent, Debug, {ReplyTo, Key, ProviderKey}) ->
	terminate(Reason, Parent, Debug, ReplyTo, Key, ProviderKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%%--------------------------------------------------------------------
%% Format debug messages.
%%--------------------------------------------------------------------

%% @private
sys_debug(Debug, Event) ->
  sys:handle_debug(Debug, fun print_debug/3, {?MODULE, self()}, Event).

%% @private
print_debug(Dev, SystemEvent, Name) ->
	case SystemEvent of
		{in, Event, ReplyTo} ->
			io:format(Dev, "*DBG* ~tp receive ~tp from ~tp~n", [Name, Event, ReplyTo]);
		{out, Event, ReplyTo} ->
			io:format(Dev, "*DBG* ~tp send ~tp to ~tw~n", [Name, Event, ReplyTo]);
		{terminate, Reason, State} ->
			io:format(Dev, "*DBG* ~tp terminate ~tp in state ~tp~n", [Name, Reason, State])
	end.
