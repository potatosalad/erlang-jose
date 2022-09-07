%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_provider).

%% Types
-type info() :: #{
	behaviour := jose_support:behaviour(),
    priority := jose_support:priority(),
	requirements := list(jose_support:requirement())
}.

-export_type([
    info/0
]).

%% Callbacks
-callback provider_info() -> jose_provider:info().
