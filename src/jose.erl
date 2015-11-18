%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose).

%% API
-export([crypto_fallback/0]).
-export([crypto_fallback/1]).
-export([decode/1]).
-export([encode/1]).
-export([json_module/0]).
-export([json_module/1]).
-export([unsecured_signing/0]).
-export([unsecured_signing/1]).
%% Private API
-export([start/0]).

-define(TAB, jose_jwa).

-define(MAYBE_START_JOSE(F), try
	F
catch
	_:_ ->
		_ = jose:start(),
		F
end).

%%====================================================================
%% API functions
%%====================================================================

crypto_fallback() ->
	jose_jwa:crypto_fallback().

crypto_fallback(Boolean) when is_boolean(Boolean) ->
	jose_jwa:crypto_fallback(Boolean).

decode(Binary) ->
	JSONModule = json_module(),
	JSONModule:decode(Binary).

encode(Term) ->
	JSONModule = json_module(),
	JSONModule:encode(Term).

json_module() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, json_module, 2)).

json_module(JSONModule) when is_atom(JSONModule) ->
	?MAYBE_START_JOSE(jose_server:json_module(JSONModule)).

unsecured_signing() ->
	jose_jwa:unsecured_signing().

unsecured_signing(Boolean) when is_boolean(Boolean) ->
	jose_jwa:unsecured_signing(Boolean).

%%====================================================================
%% Private API functions
%%====================================================================

start() ->
	case application:ensure_all_started(?MODULE) of
		{ok, _} ->
			ok;
		StartError ->
			StartError
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
