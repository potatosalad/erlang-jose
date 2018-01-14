%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwk_kty_okp_ed25519_props).

-include("jose_public_key.hrl").

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

ed25519_secret() ->
	binary(32).

ed25519_keypair(Secret) ->
	{PK, << S:32/binary, _:32/binary >>} = jose_curve25519:eddsa_keypair(Secret),
	PublicKey = #'jose_EdDSA25519PublicKey'{publicKey=PK},
	SecretKey = #'jose_EdDSA25519PrivateKey'{publicKey=PublicKey, privateKey=S},
	{SecretKey, PublicKey}.

jwk_map() ->
	?LET({AliceSecret, BobSecret},
		{ed25519_secret(), ed25519_secret()},
		begin
			AliceKeys = {AlicePrivateKey, _} = ed25519_keypair(AliceSecret),
			BobKeys = ed25519_keypair(BobSecret),
			AlicePrivateJWK = jose_jwk:from_key(AlicePrivateKey),
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

prop_from_pem_and_to_pem() ->
	?FORALL({_Keys, AlicePrivateJWK, Password},
		?LET({{Keys, AlicePrivateJWK}, Bytes},
			{jwk_gen(), binary()},
			{Keys, AlicePrivateJWK, base64url:encode(Bytes)}),
		begin
			AlicePrivatePEM = element(2, jose_jwk:to_pem(AlicePrivateJWK)),
			EncryptedAlicePrivatePEM = element(2, jose_jwk:to_pem(Password, AlicePrivateJWK)),
			AlicePublicJWK = jose_jwk:to_public(AlicePrivateJWK),
			AlicePublicPEM = element(2, jose_jwk:to_pem(AlicePublicJWK)),
			EncryptedAlicePublicPEM = element(2, jose_jwk:to_pem(Password, AlicePublicJWK)),
			AlicePrivateJWK =:= jose_jwk:from_pem(AlicePrivatePEM)
			andalso AlicePrivateJWK =:= jose_jwk:from_pem(Password, EncryptedAlicePrivatePEM)
			andalso AlicePublicJWK =:= jose_jwk:from_pem(AlicePublicPEM)
			andalso AlicePublicJWK =:= jose_jwk:from_pem(Password, EncryptedAlicePublicPEM)
		end).

prop_sign_and_verify() ->
	?FORALL({_Keys, JWK, Message},
		?LET({Keys, JWK},
			jwk_gen(),
			{Keys, JWK, binary()}),
		begin
			Signed = jose_jwk:sign(Message, JWK),
			CompactSigned = jose_jws:compact(Signed),
			Verified = {_, _, JWS} = jose_jwk:verify(Signed, JWK),
			{true, Message, JWS} =:= Verified
			andalso {true, Message, JWS} =:= jose_jwk:verify(CompactSigned, JWK)
		end).
