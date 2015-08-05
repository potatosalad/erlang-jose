%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwk_kty_rsa_props).

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

jwk_map() ->
	?LET({_ModulusSize, Keys={PrivateKey, _}},
		?LET(ModulusSize,
			modulus_size(),
			{ModulusSize, rsa_keypair(ModulusSize)}),
		begin
			PrivateJWK = jose_jwk:from_key(PrivateKey),
			PrivateJWKMap = element(2, jose_jwk:to_map(PrivateJWK)),
			{Keys, PrivateJWKMap}
		end).

jwk_gen() ->
	?LET({Keys, PrivateJWKMap},
		jwk_map(),
		{Keys, jose_jwk:from_map(PrivateJWKMap)}).

prop_from_map_and_to_map() ->
	?FORALL({{PrivateKey, PublicKey}, PrivateJWKMap},
		?LET({{Keys, JWKMap}, Extras},
			{jwk_map(), binary_map()},
			{Keys, maps:merge(Extras, JWKMap)}),
		begin
			PrivateJWK = jose_jwk:from_map(PrivateJWKMap),
			PublicJWK = jose_jwk:to_public(PrivateJWK),
			PublicJWKMap = element(2, jose_jwk:to_map(PublicJWK)),
			PublicThumbprint = jose_jwk:thumbprint(PublicJWK),
			PrivateJWKMap =:= element(2, jose_jwk:to_map(PrivateJWK))
			andalso PrivateKey =:= element(2, jose_jwk:to_key(PrivateJWK))
			andalso PublicKey =:= element(2, jose_jwk:to_public_key(PrivateJWK))
			andalso PublicJWKMap =:= element(2, jose_jwk:to_public_map(PrivateJWK))
			andalso PublicThumbprint =:= jose_jwk:thumbprint(PrivateJWK)
		end).

prop_from_pem_and_to_pem() ->
	?FORALL({{_, PublicKey}, PrivateJWK, Password},
		?LET({{Keys, PrivateJWK}, Bytes},
			{jwk_gen(), binary()},
			{Keys, PrivateJWK, base64url:encode(Bytes)}),
		begin
			PublicJWK = jose_jwk:from_key(PublicKey),
			PublicPEM = element(2, jose_jwk:to_pem(PublicJWK)),
			EncryptedPublicPEM = element(2, jose_jwk:to_pem(Password, PublicJWK)),
			PrivatePEM = element(2, jose_jwk:to_pem(PrivateJWK)),
			EncryptedPrivatePEM = element(2, jose_jwk:to_pem(Password, PrivateJWK)),
			PrivateJWK =:= jose_jwk:from_pem(PrivatePEM)
			andalso PrivateJWK =:= jose_jwk:from_pem(Password, EncryptedPrivatePEM)
			andalso PublicJWK =:= jose_jwk:from_pem(PublicPEM)
			andalso PublicJWK =:= jose_jwk:from_pem(Password, EncryptedPublicPEM)
		end).

prop_block_encrypt_and_block_decrypt() ->
	?FORALL({{{_, PublicKey}, PrivateJWK}, PlainText},
		{jwk_gen(), binary()},
		begin
			PublicJWK = jose_jwk:from_key(PublicKey),
			Encrypted = jose_jwk:block_encrypt(PlainText, PublicJWK),
			CompactEncrypted = jose_jwe:compact(Encrypted),
			Decrypted = {_, JWE} = jose_jwk:box_decrypt(Encrypted, PrivateJWK),
			{PlainText, JWE} =:= Decrypted
			andalso {PlainText, JWE} =:= jose_jwk:block_decrypt(CompactEncrypted, PrivateJWK)
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
