%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Łukasz Jan Niemier <lukasz@niemier.pl>
%%% @copyright 2018, Łukasz Niemier
%%% @doc
%%%
%%% @end
%%% Created :  23 Oct 2018 by Łukasz Jan Niemier <lukasz@niemier.pl>
%%%-------------------------------------------------------------------
-module(jose_json_jason).
-behaviour(jose_json).

%% jose_json callbacks
-export([decode/1]).
-export([encode/1]).

%%====================================================================
%% jose_json callbacks
%%====================================================================

decode(Binary) ->
	'Elixir.Jason':'decode!'(Binary).

encode(Term) ->
	'Elixir.Jason':'encode!'(Term).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
