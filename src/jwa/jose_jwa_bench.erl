%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_bench).

%% API
-export([bench/2]).
-export([bench/3]).
-export([compare/3]).

%%====================================================================
%% API
%%====================================================================

bench(Function, Arguments) ->
	bench(Function, Arguments, 1).

bench(Function, Arguments, N)
		when is_function(Function)
		andalso (is_list(Arguments) orelse is_function(Arguments, 0))
		andalso (is_integer(N) andalso N > 0) ->
	{AccUSec, MinUSec, MaxUSec} = bench_loop(N, 0, 0, 0, Function, Arguments),
	{AccUSec, MinUSec, MaxUSec, AccUSec / N}.

compare(Groups, Arguments, N)
		when is_list(Groups)
		andalso (is_list(Arguments) orelse is_function(Arguments, 0))
		andalso (is_integer(N) andalso N > 0) ->
	ResolvedArguments = resolve(Arguments),
	[begin
		{Label, bench(Function, ResolvedArguments, N)}
	end || {Label, Function} <- Groups, is_atom(Label) andalso is_function(Function)].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
bench_loop(0, MinUSec, MaxUSec, AccUSec, _Function, _Arguments) ->
	{AccUSec, MinUSec, MaxUSec};
bench_loop(I, 0, MaxUSec, AccUSec, Function, Arguments) ->
	{USec, _} = timer:tc(Function, resolve(Arguments)),
	MinUSec = USec,
	NewMaxUSec = case USec > MaxUSec of
		true ->
			USec;
		false ->
			MaxUSec
	end,
	bench_loop(I - 1, MinUSec, NewMaxUSec, AccUSec + USec, Function, Arguments);
bench_loop(I, MinUSec, MaxUSec, AccUSec, Function, Arguments) ->
	{USec, _} = timer:tc(Function, resolve(Arguments)),
	NewMinUSec = case USec < MinUSec of
		true ->
			USec;
		false ->
			MinUSec
	end,
	NewMaxUSec = case USec > MaxUSec of
		true ->
			USec;
		false ->
			MaxUSec
	end,
	bench_loop(I - 1, NewMinUSec, NewMaxUSec, AccUSec + USec, Function, Arguments).

%% @private
resolve(Arguments) when is_function(Arguments, 0) ->
	resolve(Arguments());
resolve(Arguments) when is_list(Arguments) ->
	Arguments.
