%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  21 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwt).

-include("jose_jwk.hrl").
-include("jose_jws.hrl").
-include("jose_jwt.hrl").

%% Decode API
-export([from/1]).
-export([from_binary/1]).
-export([from_file/1]).
-export([from_map/1]).
%% Encode API
-export([to_binary/1]).
-export([to_file/2]).
-export([to_map/1]).
%% API
-export([sign/2]).
-export([sign/3]).
-export([verify/2]).

%%====================================================================
%% Decode API functions
%%====================================================================

from({Modules, Map}) when is_map(Modules) andalso is_map(Map) ->
	from_map({Modules, Map});
from({Modules, Binary}) when is_map(Modules) andalso is_binary(Binary) ->
	from_binary({Modules, Binary});
from(JWT=#jose_jwt{}) ->
	JWT;
from(Other) when is_map(Other) orelse is_binary(Other) ->
	from({#{}, Other}).

from_binary({Modules, Binary}) when is_map(Modules) andalso is_binary(Binary) ->
	from_map({Modules, jsx:decode(Binary, [return_maps])});
from_binary(Binary) when is_binary(Binary) ->
	from_binary({#{}, Binary}).

from_file({Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_binary({Modules, Binary});
		ReadError ->
			ReadError
	end;
from_file(File) when is_binary(File) orelse is_list(File) ->
	from_file({#{}, File}).

from_map(Map) when is_map(Map) ->
	from_map({#{}, Map});
from_map({Modules, Map}) when is_map(Modules) andalso is_map(Map) ->
	from_map({#jose_jwt{}, Modules, Map});
from_map({JWT, _Modules, Fields}) ->
	JWT#jose_jwt{ fields = Fields }.

%%====================================================================
%% Encode API functions
%%====================================================================

to_binary(JWT=#jose_jwt{}) ->
	{Modules, Map} = to_map(JWT),
	{Modules, jsx:encode(Map)};
to_binary(Other) ->
	to_binary(from(Other)).

to_file(File, JWT=#jose_jwt{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_binary(JWT),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_file(File, from(Other)).

to_map(JWT=#jose_jwt{fields=Fields}) ->
	record_to_map(JWT, #{}, Fields);
to_map(Other) ->
	to_map(from(Other)).

%%====================================================================
%% API functions
%%====================================================================

sign(JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}, JWT=#jose_jwt{}) ->
	sign(JWK, Module:signer(KTY, Fields, JWT), JWT);
sign(JWKOther, JWTOther) ->
	sign(jose_jwk:from(JWKOther), from(JWTOther)).

sign(JWK=#jose_jwk{}, JWS=#jose_jws{}, JWT=#jose_jwt{}) ->
	{Modules0, JWTBinary} = to_binary(JWT),
	{Modules1, SignedMap} = jose_jwk:sign(JWTBinary, JWS, JWK),
	{maps:merge(Modules0, Modules1), SignedMap};
sign(JWKOther, {JWSModules, JWSMap=#{ <<"typ">> := _ }}, JWTOther) ->
	sign(JWKOther, jose_jws:from({JWSModules, JWSMap}), JWTOther);
sign(JWKOther, {JWSModules, JWSMap0}, JWTOther) when is_map(JWSMap0) ->
	Keys = [<<"typ">>] -- maps:keys(JWSMap0),
	JWSMap1 = normalize_signer(Keys, JWSMap0),
	sign(JWKOther, {JWSModules, JWSMap1}, JWTOther);
sign(JWKOther, JWSMap, JWTOther) when is_map(JWSMap) ->
	sign(JWKOther, {#{}, JWSMap}, JWTOther);
sign(JWKOther, JWSOther, JWTOther) ->
	sign(jose_jwk:from(JWKOther), jose_jws:from(JWSOther), from(JWTOther)).

verify(JWK=#jose_jwk{}, {Modules, Signed}) ->
	{Verified, JWTBinary, JWS} = jose_jwk:verify({Modules, Signed}, JWK),
	{Verified, from_binary({Modules, JWTBinary}), JWS};
verify(Other, SignedBinary) when is_binary(SignedBinary) ->
	verify(Other, {#{}, SignedBinary});
verify(Other, SignedMap) when is_map(SignedMap) ->
	verify(Other, {#{}, SignedMap});
verify(Other, Signed) ->
	verify(from(Other), Signed).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
normalize_signer([<<"typ">> | Keys], Map) ->
	normalize_signer(Keys, Map#{ <<"typ">> => <<"JWT">> });
normalize_signer([], Map) ->
	Map.

%% @private
record_to_map(_JWT, Modules, Fields) ->
	{Modules, Fields}.
