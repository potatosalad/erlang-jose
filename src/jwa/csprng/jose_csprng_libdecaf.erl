%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_csprng_libdecaf).

-behaviour(jose_provider).
-behaviour(jose_csprng).
-behaviour(gen_server).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_csprng callbacks
-export([
    init/0,
    random_bits/1,
    random_bytes/1,
    stir/1,
    uniform/2
]).
%% OTP API
-export([
    child_spec/0,
    start_link/0
]).
%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2
]).

%% Types
-type state() :: {spongerng, erlang:nif_resource()}.

%% Macros
-define(PKEY, '$jose_csprng_libdecaf_state').

%%%=============================================================================
%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_csprng,
        priority => normal,
        requirements => [
            {app, libdecaf},
            libdecaf_spongerng,
            rand
        ]
    }.

%%%=============================================================================
%% jose_csprng callbacks
%%%=============================================================================

-spec init() -> ok.
init() ->
    ChildSpec = #{id := ChildId} = child_spec(),
    case supervisor:start_child(jose_sup, ChildSpec) of
        {ok, _Pid} ->
            ok;
        {error, already_present} ->
            _ = supervisor:restart_child(jose_sup, ChildId),
            ok;
        {error, {already_started, _Pid}} ->
            ok
    end.

-spec random_bits(BitSize) -> BitOutput when
    BitSize :: jose_csprng:bit_size(),
    BitOutput :: jose_csprng:bit_output().
random_bits(BitSize) when BitSize rem 8 =:= 0 ->
    random_bytes(BitSize div 8);
random_bits(BitSize) when (is_integer(BitSize) andalso BitSize >= 0) ->
    ByteSize = ((BitSize + 7) div 8),
    <<BitOutput:BitSize/bits, _/bits>> = random_bytes(ByteSize),
    BitOutput.

-spec random_bytes(ByteSize) -> ByteOutput when
    ByteSize :: jose_csprng:byte_size(),
    ByteOutput :: jose_csprng:byte_output().
random_bytes(ByteSize) when (is_integer(ByteSize) andalso ByteSize >= 0) ->
    case erlang:get(?PKEY) of
        undefined ->
            State0 = {spongerng, _} = gen_server:call(?MODULE, fork),
            {State1, ByteOutput} = libdecaf_spongerng:next(State0, ByteSize),
            _ = erlang:put(?PKEY, State1),
            ByteOutput;
        State0 = {spongerng, _} ->
            {State1, ByteOutput} = libdecaf_spongerng:next(State0, ByteSize),
            _ = erlang:put(?PKEY, State1),
            ByteOutput
    end.

-spec stir(Seed) -> ok when
    Seed :: jose_csprng:seed().
stir(Seed) when is_binary(Seed) ->
    ok = gen_server:call(?MODULE, {stir, Seed}),
    case erlang:get(?PKEY) of
        undefined ->
            ok;
        State0 = {spongerng, _} ->
            State1 = libdecaf_spongerng:stir(State0, Seed),
            _ = erlang:put(?PKEY, State1),
            ok
    end.

-spec uniform(Lo, Hi) -> N when
    Lo :: integer(),
    Hi :: integer(),
    N :: integer().
uniform(Lo, Hi) when is_integer(Lo) andalso is_integer(Hi) andalso Lo < Hi ->
    rand:uniform(Hi - Lo) + Lo - 1.

%%%=============================================================================
%%% OTP API functions
%%%=============================================================================

-spec child_spec() -> supervisor:child_spec().
child_spec() ->
    #{
        id => ?MODULE,
        start => {?MODULE, start_link, []},
        restart => transient,
        shutdown => 5000,
        type => worker
    }.

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%=============================================================================
%%% gen_server callbacks
%%%=============================================================================

-spec init([]) -> {ok, state()}.
init([]) ->
    State = libdecaf_spongerng:init_from_dev_urandom(),
    {ok, State}.

-spec handle_call
    (fork, From, State) -> {reply, ForkState, NewState} when
        From :: gen_server:from(), State :: state(), ForkState :: state(), NewState :: state();
    ({stir, Seed}, From, State) -> {reply, ok, NewState} when
        Seed :: jose_csprng:seed(), From :: gen_server:from(), State :: state(), NewState :: state().
handle_call(fork, From, State0) ->
    FromSeed = erlang:term_to_binary(From),
    {State1, ForkSeed} = libdecaf_spongerng:next(State0, 128),
    ForkState = libdecaf_spongerng:init_from_buffer(ForkSeed, false),
    State2 = libdecaf_spongerng:stir(State1, FromSeed),
    {reply, ForkState, State2};
handle_call({stir, Seed}, From, State0) ->
    FromSeed = erlang:term_to_binary(From),
    State1 = libdecaf_spongerng:stir(State0, Seed),
    State2 = libdecaf_spongerng:stir(State1, FromSeed),
    {reply, ok, State2}.

-spec handle_cast(Request, State) -> {noreply, State} when
    Request :: any(), State :: state().
handle_cast(_Request, State) ->
    {noreply, State}.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
