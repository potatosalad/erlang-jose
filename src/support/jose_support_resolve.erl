-module(jose_support_resolve).
-behaviour(gen_statem).

%% OTP API
-export([
	child_spec/0,
	start_link/4
]).
%% gen_statem callbacks
-export([
	callback_mode/0,
	init/1,
	handle_event/4
]).

%% Records
-record(data, {
	reply_to = undefined :: undefined | pid(),
	reply_tag = undefined :: undefined | reference(),
	key = undefined :: undefined | jose_support:key(),
	modules = [] :: [{integer(), module()}],
	monitors = #{} :: #{reference() => {pid(), {integer(), module()}}},
	mods = #{} :: #{module() => reference()}
}).

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

-spec start_link(ReplyTo, ReplyTag, Key, ProviderModules) -> {ok, pid()} | {error, Reason}
	when ReplyTo :: pid(), ReplyTag :: reference(), Key :: jose_support:key(), ProviderModules :: [{integer(), module()}], Reason :: term().
start_link(ReplyTo, ReplyTag, Key = {Behaviour, {FunctionName, Arity}}, ProviderModules)
		when is_pid(ReplyTo)
		andalso is_reference(ReplyTag)
		andalso is_atom(Behaviour)
		andalso is_atom(FunctionName)
		andalso (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255)
		andalso is_list(ProviderModules) ->
	gen_statem:start_link(?MODULE, [ReplyTo, ReplyTag, Key, ProviderModules], []).

%%====================================================================
%% gen_statem callbacks
%%====================================================================

-spec callback_mode() -> gen_statem:callback_mode() | [gen_statem:callback_mode() | gen_statem:state_enter()].
callback_mode() ->
	[handle_event_function, state_enter].

-spec init([]) -> {ok, State :: init, Data :: #data{}}.
init([ReplyTo, ReplyTag, Key, ProviderModules]) ->
	State = init,
	Data = #data{
		reply_to = ReplyTo,
		reply_tag = ReplyTag,
		key = Key,
		modules = ProviderModules
	},
	{ok, State, Data}.

%% State Enter Events
handle_event(enter, init, init, _Data) ->
	Actions = [{state_timeout, 0, init}],
	{keep_state_and_data, Actions};
handle_event(enter, init, resolving, _Data) ->
	%% 15 seconds should be plenty, otherwise something is very, very wrong.
	Actions = [{state_timeout, 15000, fail}],
	{keep_state_and_data, Actions};
handle_event(enter, resolving, resolved, _Data) ->
	{stop, normal};
%% State Timeout Events
handle_event(state_timeout, init, init, Data0 = #data{key = Key, modules = ProviderModules}) ->
	{Monitors, Mods} = start_checks(maps:new(), maps:new(), Key, ProviderModules),
	Data1 = Data0#data{monitors = Monitors, mods = Mods},
	{next_state, resolving, Data1};
handle_event(state_timeout, fail, resolving, _Data = #data{reply_to = ReplyTo, reply_tag = ReplyTag, key = Key, mods = Mods}) ->
	ProviderModules = maps:keys(Mods),
	_ = [begin
		Reply = {Key, ProviderKey, {exit, timeout}},
		_ = ReplyTo ! {ReplyTag, Reply},
		ok
	end || ProviderKey <- ProviderModules],
	{stop, timeout};
%% Internal Events
handle_event(internal, maybe_resolved, resolving, Data = #data{monitors = Monitors, mods = Mods}) ->
	case map_size(Monitors) =:= 0 andalso map_size(Mods) =:= 0 of
		true ->
			{next_state, resolved, Data};
		false ->
			keep_state_and_data
	end;
%% Info Events
handle_event(info, Reply = {Key, ProviderKey, _Result}, resolving, Data0 = #data{reply_to = ReplyTo, reply_tag = ReplyTag, key = Key, monitors = Monitors0, mods = Mods0}) ->
	case maps:take(ProviderKey, Mods0) of
		{Mon, Mods1} ->
			case maps:take(Mon, Monitors0) of
				{{_Pid, ProviderKey}, Monitors1} ->
					true = erlang:demonitor(Mon, [flush]),
					_ = ReplyTo ! {ReplyTag, Reply},
					Data1 = Data0#data{monitors = Monitors1, mods = Mods1},
					Actions = [{next_event, internal, maybe_resolved}],
					{keep_state, Data1, Actions};
				_ ->
					%% Possibly old message: ignore.
					keep_state_and_data
			end;
		error ->
			%% Possibly old message: ignore.
			keep_state_and_data
	end;
handle_event(info, {'DOWN', Mon, process, Pid, Reason}, resolving, Data0 = #data{reply_to = ReplyTo, reply_tag = ReplyTag, key = Key, monitors = Monitors0, mods = Mods0}) ->
	case maps:take(Mon, Monitors0) of
		{{Pid, ProviderKey}, Monitors1} ->
			case maps:take(ProviderKey, Mods0) of
				{Mon, Mods1} ->
					Reply = {Key, ProviderKey, {exit, Reason}},
					_ = ReplyTo ! {ReplyTag, Reply},
					Data1 = Data0#data{monitors = Monitors1, mods = Mods1},
					Actions = [{next_event, internal, maybe_resolved}],
					{keep_state, Data1, Actions};
				_ ->
					%% Possibly old message: ignore.
					keep_state_and_data
			end;
		error ->
			%% Possibly old message: ignore.
			keep_state_and_data
	end.

%% @private
start_checks(Monitors0, Mods0, Key, [ProviderKey = {_Priority, _ProviderModule} | ProviderModules]) ->
	{ok, Pid} = jose_support_check_sup:start_child(self(), Key, ProviderKey),
	Mon = erlang:monitor(process, Pid),
	Monitors1 = maps:put(Mon, {Pid, ProviderKey}, Monitors0),
	Mods1 = maps:put(ProviderKey, Mon, Mods0),
	start_checks(Monitors1, Mods1, Key, ProviderModules);
start_checks(Monitors, Mods, _Key, []) ->
	{Monitors, Mods}.
