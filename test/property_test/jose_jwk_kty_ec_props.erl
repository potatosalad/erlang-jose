%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwk_kty_ec_props).

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

jwk_map() ->
	?LET(CurveId,
		ec_curve(),
		begin
			AliceKeys = {AlicePrivateKey, _} = ec_keypair(CurveId),
			BobKeys = ec_keypair(CurveId),
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
			{Keys, AlicePrivateJWK, jose_jwa_base64url:encode(Bytes)}),
		begin
			AlicePrivatePEM = element(2, jose_jwk:to_pem(AlicePrivateJWK)),
			EncryptedAlicePrivatePEM = element(2, jose_jwk:to_pem(Password, AlicePrivateJWK)),
			AlicePrivateJWK =:= jose_jwk:from_pem(AlicePrivatePEM)
			andalso AlicePrivateJWK =:= jose_jwk:from_pem(Password, EncryptedAlicePrivatePEM)
		end).

prop_box_encrypt_and_box_decrypt() ->
	?FORALL({{{_, {BobPrivateKey, BobPublicKey}}, AlicePrivateJWK}, PlainText},
		{jwk_gen(), binary()},
		begin
			BobPrivateJWK = jose_jwk:from_key(BobPrivateKey),
			BobPublicJWK = jose_jwk:from_key(BobPublicKey),
			Encrypted = jose_jwk:box_encrypt_ecdh_es(PlainText, BobPublicJWK, AlicePrivateJWK),
			CompactEncrypted = jose_jwe:compact(Encrypted),
			Decrypted = {_, JWE} = jose_jwk:box_decrypt_ecdh_es(Encrypted, BobPrivateJWK),
			{PlainText, JWE} =:= Decrypted
			andalso {PlainText, JWE} =:= jose_jwk:block_decrypt(CompactEncrypted, BobPrivateJWK)
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
