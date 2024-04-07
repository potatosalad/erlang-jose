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
%%% Created :  04 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_support_statem).
-behaviour(gen_statem).

%% OTP API
-export([
    child_spec/0,
    start_link/0
]).
%% API
-export([
    code_change/0,
    ensure_all_resolved/0,
    provider_module_add/1,
    resolve/1,
    support_module_add/1
]).
%% gen_statem callbacks
-export([
    callback_mode/0,
    init/1,
    handle_event/4
]).

%% Records
-record(data, {
    graph = undefined :: undefined | #{any() => any()},
    plan = [] :: [{serial | parallel, jose_support:key()}],
    resolved = maps:new() :: #{jose_support:key() => [{integer(), module()}]},
    resolving = {maps:new(), maps:new()} :: {#{reference() => {pid(), jose_support:key()}}, #{
        jose_support:key() => reference()
    }},
    resolving_tag = undefined :: undefined | reference()
}).

%% Macros
-define(ENSURE_JOSE_STARTED(F),
    case application:ensure_all_started(jose) of
        {ok, _} ->
            F;
        ApplicationStartError = {error, _} ->
            ApplicationStartError
    end
).
-define(SERVER, ?MODULE).
-define(SUPPORT_MODULES_TABLE, jose_support_modules).
-define(PROVIDER_MODULES_TABLE, jose_provider_modules).
-define(RESOLVED_TABLE, jose_jwa_resolved).

%%%=============================================================================
%%% OTP API functions
%%%=============================================================================

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    #{
        id => ?SERVER,
        start => {?MODULE, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => worker
    }.

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_statem:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%=============================================================================
%%% API functions
%%%=============================================================================

-spec code_change() -> ok.
code_change() ->
    ?ENSURE_JOSE_STARTED(gen_statem:call(?SERVER, code_change)).

-spec ensure_all_resolved() -> ok.
ensure_all_resolved() ->
    ?ENSURE_JOSE_STARTED(gen_statem:call(?SERVER, ensure_all_resolved)).

-spec provider_module_add({ProviderModule, SupportModule}) -> ok when
    ProviderModule :: module(), SupportModule :: module().
provider_module_add({ProviderModule, SupportModule}) when is_atom(ProviderModule) andalso is_atom(SupportModule) ->
    ?ENSURE_JOSE_STARTED(gen_statem:call(?SERVER, {provider_module_add, {ProviderModule, SupportModule}})).

-spec resolve(Key) -> {ok, ResolvedModule} | {error, Reason} when
    Key :: jose_support:key(), ResolvedModule :: module(), Reason :: term().
resolve(Key = {Behaviour, {FunctionName, Arity}}) when
    is_atom(Behaviour) andalso
        is_atom(FunctionName) andalso
        (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255)
->
    ?ENSURE_JOSE_STARTED(gen_statem:call(?SERVER, {resolve, Key})).

-spec support_module_add({SupportModule}) -> ok when SupportModule :: module().
support_module_add({SupportModule}) when is_atom(SupportModule) ->
    ?ENSURE_JOSE_STARTED(gen_statem:call(?SERVER, {support_module_add, {SupportModule}})).

%%%=============================================================================
%%% gen_statem callbacks
%%%=============================================================================

-spec callback_mode() -> gen_statem:callback_mode() | [gen_statem:callback_mode() | gen_statem:state_enter()].
callback_mode() ->
    [handle_event_function, state_enter].

-spec init([]) -> {ok, State :: init, Data :: #data{}}.
init([]) ->
    ?SUPPORT_MODULES_TABLE = ets:new(?SUPPORT_MODULES_TABLE, [
        named_table,
        protected,
        set,
        {read_concurrency, true}
    ]),
    ?PROVIDER_MODULES_TABLE = ets:new(?PROVIDER_MODULES_TABLE, [
        named_table,
        protected,
        set,
        {read_concurrency, true}
    ]),
    true = ets:insert(?SUPPORT_MODULES_TABLE, [
        jose_support:support_module_key(SupportModule)
     || SupportModule <- jose_support:support_module_list_static()
    ]),
    true = ets:insert(?PROVIDER_MODULES_TABLE, [
        jose_support:provider_module_key(ProviderModule)
     || ProviderModule <- jose_support:provider_module_list_static()
    ]),
    ?RESOLVED_TABLE = ets:new(?RESOLVED_TABLE, [
        named_table,
        protected,
        set,
        {read_concurrency, true}
    ]),
    State = init,
    Data = #data{},
    {ok, State, Data}.

%% State Enter Events
handle_event(enter, init, init, _Data) ->
    Actions = [{state_timeout, 0, init}],
    {keep_state_and_data, Actions};
handle_event(enter, _OldState, resolving, _Data) ->
    Actions = [{state_timeout, 0, resolve_next}],
    {keep_state_and_data, Actions};
handle_event(enter, _OldState, resolved, _Data) ->
    keep_state_and_data;
%% State Timeout Events
handle_event(state_timeout, init, init, Data0 = #data{}) ->
    {ok, Graph = #{plan := Plan}} = jose_support:deps(),
    Data1 = Data0#data{graph = Graph, plan = Plan, resolving_tag = erlang:make_ref()},
    {next_state, resolving, Data1};
handle_event(state_timeout, resolve_next, resolving, Data0 = #data{plan = Plan0}) ->
    case Plan0 of
        [{serial, []} | Plan1] ->
            Data1 = Data0#data{plan = Plan1},
            Actions = [{state_timeout, 0, resolve_next}],
            {keep_state, Data1, Actions};
        [{serial, [SerialNext | SerialRest]} | PlanRest] ->
            Plan1 = [{serial, SerialRest} | PlanRest],
            Data1 = start_resolve(SerialNext, Data0#data{plan = Plan1}),
            {keep_state, Data1};
        [{parallel, []} | Plan1] ->
            Data1 = Data0#data{plan = Plan1},
            Actions = [{state_timeout, 0, resolve_next}],
            {keep_state, Data1, Actions};
        [{parallel, Parallel} | PlanRest] ->
            Plan1 = [{parallel, []} | PlanRest],
            Data1 = start_parallel(Parallel, Data0#data{plan = Plan1}),
            {keep_state, Data1};
        [] ->
            {next_state, resolved, Data0}
    end;
%% Call Events
% handle_event({call, _From}, code_change, resolved, Data) ->
% 	Actions = [postpone],
% 	{next_state, init, }
handle_event({call, From}, ensure_all_resolved, resolved, _Data) ->
    Actions = [{reply, From, ok}],
    {keep_state_and_data, Actions};
handle_event({call, From}, {provider_module_add, {ProviderModule, SupportModule}}, _State, _Data) when
    is_atom(ProviderModule) andalso is_atom(SupportModule)
->
    true = ets:insert(?PROVIDER_MODULES_TABLE, {ProviderModule, SupportModule}),
    Actions = [{reply, From, ok}],
    {keep_state_and_data, Actions};
handle_event({call, From}, {resolve, Key}, _State, _Data) ->
    case ets:lookup(?RESOLVED_TABLE, Key) of
        [{_, {_, ResolvedModule}}] ->
            Actions = [{reply, From, {ok, ResolvedModule}}],
            {keep_state_and_data, Actions};
        [] ->
            Actions = [{reply, From, error}],
            {keep_state_and_data, Actions}
    end;
handle_event({call, From}, {support_module_add, {SupportModule}}, _State, _Data) when is_atom(SupportModule) ->
    true = ets:insert(?SUPPORT_MODULES_TABLE, {SupportModule}),
    Actions = [{reply, From, ok}],
    {keep_state_and_data, Actions};
handle_event(info, EventContent, State, Data0 = #data{resolved = Resolved0, resolving_tag = ResolvingTag}) ->
    case EventContent of
        {ResolvingTag, {Key, ProviderKey, ok}} ->
            ok =
                case ets:lookup(?RESOLVED_TABLE, Key) of
                    [{Key, OtherProviderKey}] when OtherProviderKey =< ProviderKey ->
                        ok;
                    _ ->
                        true = ets:insert(?RESOLVED_TABLE, {Key, ProviderKey}),
                        ok
                end,
            Resolved1 =
                case maps:find(Key, Resolved0) of
                    {ok, ExistingProviders} ->
                        maps:put(Key, ordsets:add_element(ProviderKey, ExistingProviders), Resolved0);
                    error ->
                        maps:put(Key, [ProviderKey], Resolved0)
                end,
            Data1 = Data0#data{resolved = Resolved1},
            {keep_state, Data1};
        {'DOWN', Mon, process, Pid, _Reason} ->
            maybe_reap(Mon, Pid, State, Data0);
        _ ->
            io:format("info =~n~p~n", [EventContent]),
            keep_state_and_data
    end.
% keep_state_and_data.

start_resolve(
    Key, Data0 = #data{graph = #{providers := Providers}, resolving = {M2K0, K2M0}, resolving_tag = ResolvingTag}
) ->
    ProviderModules = maps:get(Key, Providers),
    {ok, Pid} = jose_support_resolve_sup:start_child(self(), ResolvingTag, Key, ProviderModules),
    Mon = erlang:monitor(process, Pid),
    M2K1 = maps:put(Mon, {Pid, Key}, M2K0),
    K2M1 = maps:put(Key, Mon, K2M0),
    Data1 = Data0#data{resolving = {M2K1, K2M1}},
    Data1.

start_parallel([Key | Keys], Data0) ->
    Data1 = start_resolve(Key, Data0),
    start_parallel(Keys, Data1);
start_parallel([], Data) ->
    Data.

maybe_reap(Mon, Pid, resolving, Data0 = #data{resolving = {M2K0, K2M0}}) ->
    case maps:take(Mon, M2K0) of
        {{Pid, Key}, M2K1} ->
            {Mon, K2M1} = maps:take(Key, K2M0),
            Data1 = Data0#data{resolving = {M2K1, K2M1}},
            case map_size(M2K1) =:= 0 andalso map_size(K2M1) =:= 0 of
                true ->
                    Actions = [{state_timeout, 0, resolve_next}],
                    {keep_state, Data1, Actions};
                false ->
                    {keep_state, Data1}
            end;
        error ->
            keep_state_and_data
    end.
