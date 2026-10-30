%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_json_elixir).

-behaviour(jose_json).

%% jose_json callbacks
-export([decode/1]).
-export([encode/1]).

%%====================================================================
%% jose_json callbacks
%%====================================================================

-spec decode(binary()) -> dynamic().
decode(Binary) ->
  'Elixir.JSON':'decode!'(Binary).

-spec encode(dynamic()) -> binary().
encode(Term) ->
  'Elixir.JSON':'encode!'(Term).
