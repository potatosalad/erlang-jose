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
-module(jose_support_check).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-include_lib("kernel/include/file.hrl").

-behaviour(sys).

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

%% Records
-record(state, {
    parent :: pid(),
    reply_to :: pid(),
    key :: jose_support:key(),
    provider_key :: provider_key(),
    debug :: [sys:dbg_opt()]
}).

%% Types
-type provider_key() :: {integer(), module()}.
-type state() :: #state{}.

-export_type([
    provider_key/0
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

-spec start_link(ReplyTo, Key, ProviderKey) -> {ok, pid()} | {error, Reason} when
    ReplyTo :: pid(), Key :: jose_support:key(), ProviderKey :: provider_key(), Reason :: term().
start_link(ReplyTo, Key = {Behaviour, {FunctionName, Arity}}, ProviderKey = {Priority, ProviderModule}) when
    is_pid(ReplyTo) andalso
        is_atom(Behaviour) andalso
        is_atom(FunctionName) andalso
        (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255) andalso
        is_integer(Priority) andalso
        is_atom(ProviderModule)
->
    proc_lib:start_link(?MODULE, init, [self(), ReplyTo, Key, ProviderKey]).

%%%=============================================================================
%%% Internal API functions
%%%=============================================================================

%% @private
-spec init(Parent, ReplyTo, Key, ProviderKey) -> no_return() when
    Parent :: pid(), ReplyTo :: pid(), Key :: jose_support:key(), ProviderKey :: provider_key().
init(Parent, ReplyTo, Key = {_Behaviour, {_FunctionName, _Arity}}, ProviderKey) ->
    Debug1 = sys:debug_options([]),
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    State1 = #state{
        parent = Parent,
        reply_to = ReplyTo,
        key = Key,
        provider_key = ProviderKey,
        debug = Debug1
    },
    State2 = sys_debug(State1, {in, {Key, ProviderKey}, ReplyTo}),
    exec(State2).

%% @private
-spec exec(State) -> no_return() when State :: state().
exec(
    State1 = #state{
        reply_to = ReplyTo,
        key = Key = {Behaviour, {FunctionName, Arity}},
        provider_key = ProviderKey = {_Priority, ProviderModule}
    }
) ->
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
    State2 = sys_debug(State1, {out, Reply, ReplyTo}),
    before_terminate_loop(State2).

%% @private
-spec before_terminate_loop(State) -> no_return() when State :: state().
before_terminate_loop(State1 = #state{parent = Parent, debug = Debug1}) ->
    receive
        {system, From, Request} ->
            sys:handle_system_msg(Request, From, Parent, ?MODULE, Debug1, State1)
    after 0 ->
        terminate(normal, State1)
    end.

%% @private
-spec terminate(Reason, State) -> no_return() when Reason :: term(), State :: state().
terminate(Reason, State1 = #state{reply_to = ReplyTo, key = Key, provider_key = ProviderKey}) ->
    _State2 = sys_debug(State1, {terminate, Reason, {ReplyTo, Key, ProviderKey}}),
    erlang:exit(Reason).

%%%=============================================================================
%%% sys callbacks
%%%=============================================================================

%% @private
-spec system_code_change(Misc, Module, OldVsn, Extra) -> {ok, NMisc} when
    Misc :: state(),
    OldVsn :: undefined | term(),
    Module :: atom(),
    Extra :: term(),
    NMisc :: state().
system_code_change(Misc, _Module, _OldVsn, _Extra) ->
    {ok, Misc}.

%% @private
-spec system_continue(Parent, Debug, Misc) -> no_return() when
    Parent :: pid(),
    Debug :: [sys:dbg_opt()],
    Misc :: state().
system_continue(Parent, Debug2, State1 = #state{parent = Parent}) ->
    State2 = State1#state{debug = Debug2},
    before_terminate_loop(State2).

%% @private
-spec system_get_state(Misc) -> {ok, State} when
    Misc :: state(), State :: state().
system_get_state(Misc) ->
    {ok, Misc}.

%% @private
-spec system_replace_state(StateFun, Misc) -> {ok, NState, NMisc} when
    Misc :: state(),
    NState :: state(),
    NMisc :: state(),
    StateFun :: fun((State :: state()) -> NState).
system_replace_state(StateFun, Misc) ->
    NMisc = StateFun(Misc),
    {ok, NMisc, NMisc}.

%% @private
-spec system_terminate(Reason, Parent, Debug, Misc) -> no_return() when
    Reason :: term(),
    Parent :: pid(),
    Debug :: [sys:dbg_opt()],
    Misc :: state().
system_terminate(Reason, Parent, Debug2, State1 = #state{parent = Parent}) ->
    State2 = State1#state{debug = Debug2},
    terminate(Reason, State2).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%%%-----------------------------------------------------------------------------
%%% Format debug messages.
%%%-----------------------------------------------------------------------------

%% @private
-spec sys_debug(State, SystemEvent) -> State when State :: state(), SystemEvent :: sys:system_event().
sys_debug(State1 = #state{debug = Debug1}, SystemEvent) ->
    Debug2 = sys:handle_debug(Debug1, fun print_debug/3, {?MODULE, self()}, SystemEvent),
    State2 = State1#state{debug = Debug2},
    State2.

%% @private
-spec print_debug(Device, SystemEvent, Extra) -> any() when
    Device :: io:device() | file:io_device(), SystemEvent :: sys:system_event(), Extra :: term().
print_debug(Device, SystemEvent, Name) ->
    case SystemEvent of
        {in, Event, ReplyTo} ->
            write_debug(Device, "*DBG* ~tp receive ~tp from ~tp~n", [Name, Event, ReplyTo]);
        {out, Event, ReplyTo} ->
            write_debug(Device, "*DBG* ~tp send ~tp to ~tw~n", [Name, Event, ReplyTo]);
        {terminate, Reason, State} ->
            write_debug(Device, "*DBG* ~tp terminate ~tp in state ~tp~n", [Name, Reason, State])
    end.

%% @private
-spec write_debug(Device, Format, Data) -> any() when
    Device :: io:device() | file:io_device(), Format :: io:format(), Data :: [term()].
write_debug(Device = #file_descriptor{}, Format, Data) ->
    file:write(Device, io_lib:format(Format, Data));
write_debug(Device, Format, Data) ->
    io:format(Device, Format, Data).
