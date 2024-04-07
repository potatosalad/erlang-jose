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
%%% Created :  05 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_support_resolve).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

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
    reply_to :: pid(),
    reply_tag :: reference(),
    key :: jose_support:key(),
    modules = [] :: [jose_support_check:provider_key()],
    monitors = #{} :: monitors(),
    mods = #{} :: mods()
}).

%% Types
-type data() :: #data{}.
-type mods() :: #{jose_support_check:provider_key() => reference()}.
-type monitors() :: #{reference() => {pid(), jose_support_check:provider_key()}}.
-type state() :: init | resolving | resolved.

-export_type([
    state/0,
    data/0
]).

%%%=============================================================================
%%% OTP API functions
%%%=============================================================================

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    #{
        id => undefined,
        start => {?MODULE, start_link, []},
        restart => temporary,
        shutdown => brutal_kill,
        type => worker
    }.

-spec start_link(ReplyTo, ReplyTag, Key, ProviderModules) -> gen_statem:start_ret() when
    ReplyTo :: pid(),
    ReplyTag :: reference(),
    Key :: jose_support:key(),
    ProviderModules :: [{integer(), module()}].
start_link(ReplyTo, ReplyTag, Key = {Behaviour, {FunctionName, Arity}}, ProviderModules) when
    is_pid(ReplyTo) andalso
        is_reference(ReplyTag) andalso
        is_atom(Behaviour) andalso
        is_atom(FunctionName) andalso
        (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255) andalso
        is_list(ProviderModules)
->
    gen_statem:start_link(?MODULE, [ReplyTo, ReplyTag, Key, ProviderModules], []).

%%%=============================================================================
%%% gen_statem callbacks
%%%=============================================================================

%% @private
-spec callback_mode() -> gen_statem:callback_mode_result().
callback_mode() ->
    [handle_event_function, state_enter].

%% @private
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

%% @private
-spec handle_event
    ('enter', OldState, CurrentState, Data) -> gen_statem:state_enter_result(CurrentState, Data) when
        OldState :: state(), CurrentState :: state(), Data :: data();
    (EventType, EventContent, CurrentState, Data) -> gen_statem:event_handler_result(NextState, Data) when
        EventType :: gen_statem:event_type(),
        EventContent :: term(),
        CurrentState :: state(),
        Data :: data(),
        NextState :: state().
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
handle_event(
    state_timeout, fail, resolving, _Data = #data{reply_to = ReplyTo, reply_tag = ReplyTag, key = Key, mods = Mods}
) ->
    ProviderModules = maps:keys(Mods),
    _ = [
        begin
            Reply = {Key, ProviderKey, {exit, timeout}},
            _ = ReplyTo ! {ReplyTag, Reply},
            ok
        end
     || ProviderKey <- ProviderModules
    ],
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
handle_event(
    info,
    Reply = {Key, ProviderKey, _Result},
    resolving,
    Data0 = #data{reply_to = ReplyTo, reply_tag = ReplyTag, key = Key, monitors = Monitors0, mods = Mods0}
) ->
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
handle_event(
    info,
    {'DOWN', Mon, process, Pid, Reason},
    resolving,
    Data0 = #data{reply_to = ReplyTo, reply_tag = ReplyTag, key = Key, monitors = Monitors0, mods = Mods0}
) ->
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

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
-spec start_checks(Monitors, Mods, Key, ProviderModules) -> {Monitors, Mods} when
    Monitors :: monitors(),
    Mods :: mods(),
    Key :: jose_support:key(),
    ProviderModules :: [jose_support_check:provider_key()].
start_checks(Monitors0, Mods0, Key, [ProviderKey = {_Priority, _ProviderModule} | ProviderModules]) ->
    {ok, Pid} = jose_support_check_sup:start_child(self(), Key, ProviderKey),
    Mon = erlang:monitor(process, Pid),
    Monitors1 = maps:put(Mon, {Pid, ProviderKey}, Monitors0),
    Mods1 = maps:put(ProviderKey, Mon, Mods0),
    start_checks(Monitors1, Mods1, Key, ProviderModules);
start_checks(Monitors, Mods, _Key, []) ->
    {Monitors, Mods}.
