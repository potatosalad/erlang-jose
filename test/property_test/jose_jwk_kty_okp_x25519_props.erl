%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwk_kty_okp_x25519_props).

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

x25519_secret() ->
	binary(32).

x25519_keypair(Secret) ->
	{PK, Secret} = jose_curve25519:x25519_keypair(Secret),
	{<< Secret/binary, PK/binary >>, PK}.

jwk_map() ->
	?LET({AliceSecret, BobSecret},
		{x25519_secret(), x25519_secret()},
		begin
			AliceKeys = {AlicePrivateKey, _} = x25519_keypair(AliceSecret),
			BobKeys = x25519_keypair(BobSecret),
			AlicePrivateJWK = jose_jwk:from_okp({'X25519', AlicePrivateKey}),
			{_, AlicePrivateJWKMap} = jose_jwk:to_map(AlicePrivateJWK),
			Keys = {AliceKeys, BobKeys},
			{Keys, AlicePrivateJWKMap}
		end).

jwk_gen() ->
	?LET({Keys, AlicePrivateJWKMap},
		jwk_map(),
		{Keys, jose_jwk:from_map(AlicePrivateJWKMap)}).

prop_from_map_and_to_map() ->
	?FORALL({{{AlicePrivateKey, AlicePublicKey}, _}, AlicePrivateJWKMap},
		?LET({{Keys, JWKMap}, Extras},
			{jwk_map(), binary_map()},
			{Keys, maps:merge(Extras, JWKMap)}),
		begin
			AlicePrivateJWK = jose_jwk:from_map(AlicePrivateJWKMap),
			AlicePublicJWK = jose_jwk:to_public(AlicePrivateJWK),
			AlicePublicJWKMap = element(2, jose_jwk:to_map(AlicePublicJWK)),
			AlicePublicThumbprint = jose_jwk:thumbprint(AlicePublicJWK),
			AlicePrivateJWKMap =:= element(2, jose_jwk:to_map(AlicePrivateJWK))
			andalso AlicePrivateKey =:= element(2, jose_jwk:to_key(AlicePrivateJWK))
			andalso AlicePublicKey =:= element(2, jose_jwk:to_public_key(AlicePrivateJWK))
			andalso AlicePublicJWKMap =:= element(2, jose_jwk:to_public_map(AlicePrivateJWK))
			andalso AlicePublicThumbprint =:= jose_jwk:thumbprint(AlicePrivateJWK)
		end).

prop_box_encrypt_and_box_decrypt() ->
	?FORALL({{{_, {BobPrivateKey, BobPublicKey}}, AlicePrivateJWK}, PlainText},
		{jwk_gen(), binary()},
		begin
			BobPrivateJWK = jose_jwk:from_okp({'X25519', BobPrivateKey}),
			BobPublicJWK = jose_jwk:from_okp({'X25519', BobPublicKey}),
			Encrypted = jose_jwk:box_encrypt(PlainText, BobPublicJWK, AlicePrivateJWK),
			CompactEncrypted = jose_jwe:compact(Encrypted),
			Decrypted = {_, JWE} = jose_jwk:box_decrypt(Encrypted, BobPrivateJWK),
			{PlainText, JWE} =:= Decrypted
			andalso {PlainText, JWE} =:= jose_jwk:block_decrypt(CompactEncrypted, BobPrivateJWK)
		end).
