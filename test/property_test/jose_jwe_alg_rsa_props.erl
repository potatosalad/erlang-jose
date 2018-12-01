%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_alg_rsa_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

modulus_size()  -> integer(1024, 1280). % integer(256, 8192) | pos_integer().
exponent_size() -> return(65537).   % pos_integer().

rsa_keypair(ModulusSize) ->
	?LET(ExponentSize,
		exponent_size(),
		begin
			case public_key:generate_key({rsa, ModulusSize, ExponentSize}) of
				PrivateKey=#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent} ->
					{PrivateKey, #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent}}
			end
		end).

alg() ->
	oneof([
		<<"RSA1_5">>,
		<<"RSA-OAEP">>,
		<<"RSA-OAEP-256">>
	]).

enc() ->
	oneof([
		<<"A128GCM">>,
		<<"A192GCM">>,
		<<"A256GCM">>
	]).

jwk_jwe_maps(ModulusSize) ->
	?LET({ALG, ENC, {AlicePrivateKey, AlicePublicKey}},
		{alg(), enc(), rsa_keypair(ModulusSize)},
		begin
			AlicePrivateJWK = jose_jwk:from_key(AlicePrivateKey),
			AlicePublicJWK = jose_jwk:from_key(AlicePublicKey),
			JWKs = {AlicePrivateJWK, AlicePublicJWK},
			JWEMap = #{ <<"alg">> => ALG, <<"enc">> => ENC },
			{JWKs, JWEMap}
		end).

jwk_jwe_gen() ->
	?LET({JWKs, JWEMap},
		?LET(ModulusSize,
			modulus_size(),
			jwk_jwe_maps(ModulusSize)),
		{JWKs, jose_jwe:from_map(JWEMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWEMap,
		?LET({{_JWKs, JWEMap}, Extras},
			?LET(ModulusSize,
				integer(1024, 1280),
				{jwk_jwe_maps(ModulusSize), binary_map()}),
			maps:merge(Extras, JWEMap)),
		begin
			JWE = jose_jwe:from_map(JWEMap),
			JWEMap =:= element(2, jose_jwe:to_map(JWE))
		end).

prop_key_encrypt_and_key_decrypt() ->
	?FORALL({{AlicePrivateJWK, AlicePublicJWK}, JWE},
		jwk_jwe_gen(),
		begin
			{DecKey, DecJWE} = jose_jwe:next_cek(AlicePublicJWK, JWE),
			{EncKey, EncJWE} = jose_jwe:key_encrypt(AlicePublicJWK, DecKey, DecJWE),
			DecKey =:= jose_jwe:key_decrypt(AlicePrivateJWK, EncKey, EncJWE)
		end).
