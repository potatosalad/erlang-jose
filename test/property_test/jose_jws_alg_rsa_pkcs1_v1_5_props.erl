%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jws_alg_rsa_pkcs1_v1_5_props).

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

alg() ->
	oneof([
		<<"RS256">>,
		<<"RS384">>,
		<<"RS512">>
	]).

modulus_size()  -> int(1024, 2048). % int(256, 8192) | pos_integer().
exponent_size() -> return(65537).  % pos_integer().

rsa_keypair(ModulusSize) ->
	?LET(ExponentSize,
		exponent_size(),
		begin
			case cutkey:rsa(ModulusSize, ExponentSize, [{return, key}]) of
				{ok, PrivateKey=#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}} ->
					{PrivateKey, #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent}};
				{error, _} ->
					erlang:error({badarg, [ModulusSize, ExponentSize, [{return, key}]]})
			end
		end).

jwk_jws_maps() ->
	?LET({ModulusSize, ALG, {PrivateKey, PublicKey}},
		?LET(ModulusSize,
			modulus_size(),
			{ModulusSize, alg(), rsa_keypair(ModulusSize)}),
		begin
			JWKSigner = jose_jwk:from_key(PrivateKey),
			JWKVerifier = jose_jwk:from_key(PublicKey),
			JWSMap = #{
				<<"alg">> => ALG
			},
			{ModulusSize, {JWKSigner, JWKVerifier}, JWSMap}
		end).

jwk_jws_gen() ->
	?LET({ModulusSize, JWKs, JWSMap},
		jwk_jws_maps(),
		{ModulusSize, JWKs, jose_jws:from_map(JWSMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWSMap,
		?LET({ALG, Extras},
			{alg(), binary_map()},
			maps:merge(Extras, #{ <<"alg">> => ALG })),
		begin
			JWS = jose_jws:from_map(JWSMap),
			JWSMap =:= element(2, jose_jws:to_map(JWS))
		end).

prop_sign_and_verify() ->
	?FORALL({{_ModulusSize, {JWKSigner, JWKVerifier}, JWS}, Message},
		{jwk_jws_gen(), binary()},
		begin
			Signed = jose_jws:sign(JWKSigner, Message, JWS),
			CompactSigned = jose_jws:compact(Signed),
			{true, Message, JWS} =:= jose_jws:verify(JWKVerifier, Signed)
			andalso {true, Message, JWS} =:= jose_jws:verify(JWKVerifier, CompactSigned)
		end).
