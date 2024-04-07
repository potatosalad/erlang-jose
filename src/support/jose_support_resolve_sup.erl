%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  05 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_support_resolve_sup).
-behaviour(supervisor).

-define(SUPERVISOR, ?MODULE).

%% OTP API
-export([
    child_spec/0,
    start_link/0,
    start_child/4
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

-spec start_child(ReplyTo, ReplyTag, Key, ProviderModules) -> supervisor:startchild_ret() when
    ReplyTo :: pid(), ReplyTag :: reference(), Key :: jose_support:key(), ProviderModules :: [{integer(), module()}].
start_child(ReplyTo, ReplyTag, Key = {Behaviour, {FunctionName, Arity}}, ProviderModules) when
    is_pid(ReplyTo) andalso
        is_reference(ReplyTag) andalso
        is_atom(Behaviour) andalso
        is_atom(FunctionName) andalso
        (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255) andalso
        is_list(ProviderModules)
->
    supervisor:start_child(?SUPERVISOR, [ReplyTo, ReplyTag, Key, ProviderModules]).

%%%===================================================================
%%% supervisor callbacks
%%%===================================================================

-spec init([]) -> {ok, {SupFlags, [ChildSpec]}} | ignore when
    SupFlags :: supervisor:sup_flags(), ChildSpec :: supervisor:child_spec().
init([]) ->
    ChildSpecs = [
        jose_support_resolve:child_spec()
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
