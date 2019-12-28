%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_alg_ecdh_es_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		jose_jwa_base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

alg() ->
	oneof([
		<<"ECDH-ES">>,
		<<"ECDH-ES+A128KW">>,
		<<"ECDH-ES+A192KW">>,
		<<"ECDH-ES+A256KW">>,
		<<"ECDH-ES+C20PKW">>,
		<<"ECDH-ES+XC20PKW">>
	]).

alg_map() ->
	?LET({ALG, APU, APV},
		{alg(), binary(), binary()},
		#{
			<<"alg">> => ALG,
			<<"apu">> => jose_jwa_base64url:encode(APU),
			<<"apv">> => jose_jwa_base64url:encode(APV)
		}).

ec_curve() ->
	oneof([
		secp256r1,
		secp384r1,
		secp521r1
	]).

% ec_curve() ->
% 	?SUCHTHAT(CurveId,
% 		oneof(crypto:ec_curves()),
% 		begin
% 			try pubkey_cert_records:namedCurves(CurveId) of
% 				Curve when is_tuple(Curve) ->
% 					true;
% 				_ ->
% 					false
% 			catch
% 				_:_ ->
% 					false
% 			end
% 		end).

% ec_keypair() ->
% 	?LET(CurveId,
% 		ec_curve(),
% 		ec_keypair(CurveId)).

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

enc() ->
	oneof([
		<<"A128GCM">>,
		<<"A192GCM">>,
		<<"A256GCM">>,
		<<"C20P">>,
		<<"XC20P">>
	]).

jwk_jwe_maps() ->
	?LET({ALGMap, ENC, {BobPrivateKey, BobPublicKey}, {AlicePrivateKey, AlicePublicKey}},
		?LET(CurveId,
			ec_curve(),
			{alg_map(), enc(), ec_keypair(CurveId), ec_keypair(CurveId)}),
		begin
			BobPrivateJWK = jose_jwk:from_key(BobPrivateKey),
			BobPublicJWK = jose_jwk:from_key(BobPublicKey),
			AlicePrivateJWK = jose_jwk:from_key(AlicePrivateKey),
			AlicePublicJWK = jose_jwk:from_key(AlicePublicKey),
			{_, AlicePublicJWKMap} = jose_jwk:to_public_map(AlicePrivateJWK),
			BobBox = {AlicePublicJWK, BobPrivateJWK},
			AliceBox = {BobPublicJWK, AlicePrivateJWK},
			JWKs = {BobBox, AliceBox},
			JWEMap = maps:merge(#{ <<"enc">> => ENC, <<"epk">> => AlicePublicJWKMap }, ALGMap),
			{JWKs, JWEMap}
		end).

jwk_jwe_gen() ->
	?LET({JWKs, JWEMap},
		jwk_jwe_maps(),
		{JWKs, jose_jwe:from_map(JWEMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWEMap,
		?LET({{_JWKs, JWEMap}, Extras},
			{jwk_jwe_maps(), binary_map()},
			maps:merge(Extras, JWEMap)),
		begin
			JWE = jose_jwe:from_map(JWEMap),
			JWEMap =:= element(2, jose_jwe:to_map(JWE))
		end).

prop_key_encrypt_and_key_decrypt() ->
	?FORALL({{BobBox, AliceBox}, JWE},
		jwk_jwe_gen(),
		begin
			{DecKey, DecJWE} = jose_jwe:next_cek(AliceBox, JWE),
			{EncKey, EncJWE} = jose_jwe:key_encrypt(AliceBox, DecKey, DecJWE),
			DecKey =:= jose_jwe:key_decrypt(BobBox, EncKey, EncJWE)
		end).
