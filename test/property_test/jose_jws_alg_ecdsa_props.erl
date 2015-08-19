%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jws_alg_ecdsa_props).

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
		<<"ES256">>,
		<<"ES384">>,
		<<"ES512">>
	]).

opt_map() ->
	oneof([
		#{},
		#{ <<"b64">> => true  },
		#{ <<"b64">> => false }
	]).

ec_curve() ->
	oneof([
		secp256r1,
		secp384r1,
		secp521r1
	]).

ec_keypair(CurveId) ->
	ECPrivateKey = #'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0} = public_key:generate_key({namedCurve, pubkey_cert_records:namedCurves(CurveId)}),
	Octets = case Octets0 of
		{_, Octets1} ->
			Octets1;
		_ ->
			Octets0
	end,
	ECPoint = #'ECPoint'{point=Octets},
	ECPublicKey = {ECPoint, ECParameters},
	{ECPrivateKey, ECPublicKey}.

jwk_jws_maps() ->
	?LET({CurveId, ALG, {PrivateKey, PublicKey}, Opts},
		?LET(CurveId,
			ec_curve(),
			{CurveId, alg(), ec_keypair(CurveId), opt_map()}),
		begin
			JWKSigner = jose_jwk:from_key(PrivateKey),
			JWKVerifier = jose_jwk:from_key(PublicKey),
			JWSMap = maps:merge(Opts, #{
				<<"alg">> => ALG
			}),
			{CurveId, {JWKSigner, JWKVerifier}, JWSMap}
		end).

jwk_jws_gen() ->
	?LET({CurveId, JWKs, JWSMap},
		jwk_jws_maps(),
		{CurveId, JWKs, jose_jws:from_map(JWSMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWSMap,
		?LET({ALG, Opts, Extras},
			{alg(), opt_map(), binary_map()},
			maps:merge(maps:merge(Extras, Opts), #{ <<"alg">> => ALG })),
		begin
			JWS = jose_jws:from_map(JWSMap),
			JWSMap =:= element(2, jose_jws:to_map(JWS))
		end).

prop_sign_and_verify() ->
	?FORALL({{_CurveId, {JWKSigner, JWKVerifier}, JWS}, Message},
		{jwk_jws_gen(), binary()},
		begin
			Signed = jose_jws:sign(JWKSigner, Message, JWS),
			CompactSigned = jose_jws:compact(Signed),
			{true, Message, JWS} =:= jose_jws:verify(JWKVerifier, Signed)
			andalso {true, Message, JWS} =:= jose_jws:verify(JWKVerifier, CompactSigned)
		end).
