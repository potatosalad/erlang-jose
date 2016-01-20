%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jws_alg_ed25519_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("triq/include/triq.hrl").

-compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

opt_map() ->
	oneof([
		#{},
		#{ <<"b64">> => true  },
		#{ <<"b64">> => false }
	]).

ed25519_secret() ->
	binary(32).

ed25519_keypair(Secret) ->
	{PK, SK} = jose_curve25519:ed25519_keypair(Secret),
	{SK, PK}.

ed25519_keypair_gen() ->
	?LET(Secret,
		ed25519_secret(),
		ed25519_keypair(Secret)).

jwk_jws_maps() ->
	?LET({{SK, PK}, Opts},
		{ed25519_keypair_gen(), opt_map()},
		begin
			JWKSigner = jose_jwk:from_okp({'Ed25519', SK}),
			JWKVerifier = jose_jwk:from_okp({'Ed25519', PK}),
			JWSMap = maps:merge(Opts, #{
				<<"alg">> => <<"Ed25519">>
			}),
			{JWKSigner, JWKVerifier, JWSMap}
		end).

jwk_jws_gen() ->
	?LET({JWKSigner, JWKVerifier, JWSMap},
		jwk_jws_maps(),
		{JWKSigner, JWKVerifier, jose_jws:from_map(JWSMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWSMap,
		?LET({Opts, Extras},
			{opt_map(), binary_map()},
			maps:merge(maps:merge(Extras, Opts), #{ <<"alg">> => <<"Ed25519">> })),
		begin
			JWS = jose_jws:from_map(JWSMap),
			JWSMap =:= element(2, jose_jws:to_map(JWS))
		end).

prop_sign_and_verify() ->
	?FORALL({{JWKSigner, JWKVerifier, JWS}, Message},
		{jwk_jws_gen(), binary()},
		begin
			Signed = jose_jws:sign(JWKSigner, Message, JWS),
			CompactSigned = jose_jws:compact(Signed),
			{true, Message, JWS} =:= jose_jws:verify(JWKVerifier, Signed)
			andalso {true, Message, JWS} =:= jose_jws:verify(JWKVerifier, CompactSigned)
		end).
