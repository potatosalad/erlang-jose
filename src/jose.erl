%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose).

%% API
-export([chacha20_poly1305_module/0]).
-export([chacha20_poly1305_module/1]).
-export([crypto_fallback/0]).
-export([crypto_fallback/1]).
-export([curve25519_module/0]).
-export([curve25519_module/1]).
-export([curve448_module/0]).
-export([curve448_module/1]).
-export([decode/1]).
-export([encode/1]).
-export([json_module/0]).
-export([json_module/1]).
-export([sha3_module/0]).
-export([sha3_module/1]).
-export([unsecured_signing/0]).
-export([unsecured_signing/1]).
-export([xchacha20_poly1305_module/0]).
-export([xchacha20_poly1305_module/1]).
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

chacha20_poly1305_module() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, chacha20_poly1305_module, 2)).

chacha20_poly1305_module(ChaCha20Poly1305Module) when is_atom(ChaCha20Poly1305Module) ->
	?MAYBE_START_JOSE(jose_server:chacha20_poly1305_module(ChaCha20Poly1305Module)).

crypto_fallback() ->
	jose_jwa:crypto_fallback().

crypto_fallback(Boolean) when is_boolean(Boolean) ->
	jose_jwa:crypto_fallback(Boolean).

curve25519_module() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, curve25519_module, 2)).

curve25519_module(Curve25519Module) when is_atom(Curve25519Module) ->
	?MAYBE_START_JOSE(jose_server:curve25519_module(Curve25519Module)).

curve448_module() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, curve448_module, 2)).

curve448_module(Curve448Module) when is_atom(Curve448Module) ->
	?MAYBE_START_JOSE(jose_server:curve448_module(Curve448Module)).

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

sha3_module() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, sha3_module, 2)).

sha3_module(SHA3Module) when is_atom(SHA3Module) ->
	?MAYBE_START_JOSE(jose_server:sha3_module(SHA3Module)).

unsecured_signing() ->
	jose_jwa:unsecured_signing().

unsecured_signing(Boolean) when is_boolean(Boolean) ->
	jose_jwa:unsecured_signing(Boolean).

xchacha20_poly1305_module() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, xchacha20_poly1305_module, 2)).

xchacha20_poly1305_module(XChaCha20Poly1305Module) when is_atom(XChaCha20Poly1305Module) ->
	?MAYBE_START_JOSE(jose_server:xchacha20_poly1305_module(XChaCha20Poly1305Module)).

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
