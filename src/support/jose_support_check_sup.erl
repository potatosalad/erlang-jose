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
-module(jose_support_check_sup).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

%% OTP API
-export([
    child_spec/0,
    start_link/0,
    start_child/3
]).
%% supervisor callbacks
-export([init/1]).

%%%=============================================================================
%%% OTP API functions
%%%=============================================================================

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    #{
        id => ?MODULE,
        start => {?MODULE, start_link, []},
        restart => permanent,
        shutdown => 5000,
        type => supervisor
    }.

-spec start_link() -> {ok, pid()} | ignore | {error, supervisor:startlink_err()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec start_child(ReplyTo, Key, ProviderKey) -> supervisor:startchild_ret() when
    ReplyTo :: pid(), Key :: jose_support:key(), ProviderKey :: jose_support_check:provider_key().
start_child(ReplyTo, Key = {Behaviour, {FunctionName, Arity}}, ProviderKey = {Priority, ProviderModule}) when
    is_pid(ReplyTo) andalso
        is_atom(Behaviour) andalso
        is_atom(FunctionName) andalso
        (is_integer(Arity) andalso Arity >= 0 andalso Arity =< 255) andalso
        is_integer(Priority) andalso
        is_atom(ProviderModule)
->
    supervisor:start_child(?MODULE, [ReplyTo, Key, ProviderKey]).

%%%=============================================================================
%%% supervisor callbacks
%%%=============================================================================

-spec init([]) -> {ok, {SupFlags, [ChildSpec]}} | ignore when
    SupFlags :: supervisor:sup_flags(), ChildSpec :: supervisor:child_spec().
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

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
