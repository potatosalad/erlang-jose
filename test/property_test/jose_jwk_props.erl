%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
-module(jose_jwk_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

alg_map() ->
	oneof([
		#{ <<"alg">> => <<"RSA1_5">> },
		#{ <<"alg">> => <<"RSA-OAEP">> },
		#{ <<"alg">> => <<"RSA-OAEP-256">> },
		#{ <<"alg">> => <<"A128KW">> },
		#{ <<"alg">> => <<"A192KW">> },
		#{ <<"alg">> => <<"A256KW">> },
		#{ <<"alg">> => <<"dir">> },
		#{ <<"alg">> => <<"ECDH-1PU">> },
		#{ <<"alg">> => <<"ECDH-1PU+A128GCMKW">> },
		#{ <<"alg">> => <<"ECDH-1PU+A192GCMKW">> },
		#{ <<"alg">> => <<"ECDH-1PU+A256GCMKW">> },
		#{ <<"alg">> => <<"ECDH-1PU+A128KW">> },
		#{ <<"alg">> => <<"ECDH-1PU+A192KW">> },
		#{ <<"alg">> => <<"ECDH-1PU+A256KW">> },
		#{ <<"alg">> => <<"ECDH-1PU+C20PKW">> },
		#{ <<"alg">> => <<"ECDH-1PU+XC20PKW">> },
		#{ <<"alg">> => <<"ECDH-ES">> },
		#{ <<"alg">> => <<"ECDH-ES+A128GCMKW">> },
		#{ <<"alg">> => <<"ECDH-ES+A192GCMKW">> },
		#{ <<"alg">> => <<"ECDH-ES+A256GCMKW">> },
		#{ <<"alg">> => <<"ECDH-ES+A128KW">> },
		#{ <<"alg">> => <<"ECDH-ES+A192KW">> },
		#{ <<"alg">> => <<"ECDH-ES+A256KW">> },
		#{ <<"alg">> => <<"ECDH-ES+C20PKW">> },
		#{ <<"alg">> => <<"ECDH-ES+XC20PKW">> },
		#{ <<"alg">> => <<"A128GCMKW">> },
		#{ <<"alg">> => <<"A192GCMKW">> },
		#{ <<"alg">> => <<"A256GCMKW">> },
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS256+A128GCMKW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS384+A192GCMKW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS512+A256GCMKW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS256+A128KW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS384+A192KW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS512+A256KW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS512+C20PKW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) }),
		?LET({P2C, P2S},
			{integer(1, 256), binary()},
			#{ <<"alg">> => <<"PBES2-HS512+XC20PKW">>, <<"p2c">> => P2C, <<"p2s">> => jose_jwa_base64url:encode(P2S) })
	]).

enc_map() ->
	oneof([
		#{ <<"enc">> => <<"A128CBC-HS256">> },
		#{ <<"enc">> => <<"A192CBC-HS384">> },
		#{ <<"enc">> => <<"A256CBC-HS512">> },
		#{ <<"enc">> => <<"A128GCM">> },
		#{ <<"enc">> => <<"A192GCM">> },
		#{ <<"enc">> => <<"A256GCM">> },
		#{ <<"enc">> => <<"C20P">> },
		#{ <<"enc">> => <<"XC20P">> }
	]).

jwk_encryptor_gen() ->
	?LET({ALGMap, ENCMap},
		?SUCHTHAT({#{ <<"alg">> := _ALG }, #{ <<"enc">> := _ENC }},
			{alg_map(), enc_map()},
			true),
		begin
			ALG = maps:get(<<"alg">>, ALGMap),
			ENC = maps:get(<<"enc">>, ENCMap),
			JWE = jose_jwe:from_map(maps:merge(ENCMap, ALGMap)),
			case {ALG, ENC} of
				{<<"RSA", _/binary>>, _} ->
					?LET({RSAPrivateKey, RSAPublicKey},
						?LET(ModulusSize,
							modulus_size(),
							rsa_keypair(ModulusSize)),
						begin
							PrivateJWK = jose_jwk:from_key(RSAPrivateKey),
							PublicJWK = jose_jwk:from_key(RSAPublicKey),
							{{rsa, RSAPrivateKey, RSAPublicKey}, JWE, {PrivateJWK, PublicJWK}}
						end);
				{<<"A128KW">>, _} ->
					K = crypto:strong_rand_bytes(16),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"A192KW">>, _} ->
					K = crypto:strong_rand_bytes(24),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"A256KW">>, _} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"A128CBC-HS256">>} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"A192CBC-HS384">>} ->
					K = crypto:strong_rand_bytes(48),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"A256CBC-HS512">>} ->
					K = crypto:strong_rand_bytes(64),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"A128GCM">>} ->
					K = crypto:strong_rand_bytes(16),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"A192GCM">>} ->
					K = crypto:strong_rand_bytes(24),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"A256GCM">>} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"C20P">>} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"dir">>, <<"XC20P">>} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"ECDH-1PU", _/binary>>, _} ->
					?LET(CurveId,
						ec_curve(),
						begin
							VStaticKeypair = {VStaticSecret, VStaticPublic} = ec_keypair(CurveId),
							UStaticKeypair = {UStaticSecret, UStaticPublic} = ec_keypair(CurveId),
							UEphemeralKeypair = {UEphemeralSecret, UEphemeralPublic} = ec_keypair(CurveId),
							VStaticSecretKey = jose_jwk:from_key(VStaticSecret),
							VStaticPublicKey = jose_jwk:from_key(VStaticPublic),
							UStaticSecretKey = jose_jwk:from_key(UStaticSecret),
							UStaticPublicKey = jose_jwk:from_key(UStaticPublic),
							UEphemeralSecretKey = jose_jwk:from_key(UEphemeralSecret),
							UEphemeralPublicKey = jose_jwk:from_key(UEphemeralPublic),
							{{ecdh_1pu, VStaticKeypair, UStaticKeypair, UEphemeralKeypair}, JWE, {{VStaticSecretKey, VStaticPublicKey}, {UStaticSecretKey, UStaticPublicKey}, {UEphemeralSecretKey, UEphemeralPublicKey}}}
						end);
				{<<"ECDH-ES", _/binary>>, _} ->
					?LET(CurveId,
						ec_curve(),
						begin
							AliceKeypair = {AlicePrivateKey, AlicePublicKey} = ec_keypair(CurveId),
							BobKeypair = {BobPrivateKey, BobPublicKey} = ec_keypair(CurveId),
							AlicePrivateJWK = jose_jwk:from_key(AlicePrivateKey),
							AlicePublicJWK = jose_jwk:from_key(AlicePublicKey),
							BobPrivateJWK = jose_jwk:from_key(BobPrivateKey),
							BobPublicJWK = jose_jwk:from_key(BobPublicKey),
							{{ecdh_es, AliceKeypair, BobKeypair}, JWE, {{AlicePrivateJWK, AlicePublicJWK}, {BobPrivateJWK, BobPublicJWK}}}
						end);
				{<<"A128GCMKW">>, _} ->
					K = crypto:strong_rand_bytes(16),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"A192GCMKW">>, _} ->
					K = crypto:strong_rand_bytes(24),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"A256GCMKW">>, _} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"C20PKW">>, _} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"XC20PKW">>, _} ->
					K = crypto:strong_rand_bytes(32),
					{K, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(K) })};
				{<<"PBES2", _/binary>>, _} ->
					?LET(Key,
						binary(),
						begin
							Password = jose_jwa_base64url:encode(Key),
							{Password, JWE, jose_jwk:from_map(#{ <<"kty">> => <<"oct">>, <<"k">> => jose_jwa_base64url:encode(Password) })}
						end)
			end
		end).

ec_curve() ->
	oneof([
		secp256r1,
		secp384r1,
		secp521r1,
		x25519,
		x448
	]).

ec_keypair(x25519) ->
	SecretJWK = jose_jwk:generate_key({okp, 'X25519'}),
	{_, SecretKey} = jose_jwk:to_key(SecretJWK),
	{_, PublicKey} = jose_jwk:to_public_key(SecretJWK),
	{SecretKey, PublicKey};
ec_keypair(x448) ->
	SecretJWK = jose_jwk:generate_key({okp, 'X448'}),
	{_, SecretKey} = jose_jwk:to_key(SecretJWK),
	{_, PublicKey} = jose_jwk:to_public_key(SecretJWK),
	{SecretKey, PublicKey};
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

modulus_size()  -> integer(1048, 1280). % integer(256, 8192) | pos_integer().
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

prop_encrypt_and_decrypt() ->
	?FORALL({Keys, JWE, JWKs, PlainText},
		?LET({Keys, JWE, JWKs},
			jwk_encryptor_gen(),
			{Keys, JWE, JWKs, binary()}),
		begin
			case {Keys, JWKs} of
				{{ecdh_1pu, _, _, _}, {{VStaticSecretKey, VStaticPublicKey}, {UStaticSecretKey, UStaticPublicKey}, {UEphemeralSecretKey, UEphemeralPublicKey}}} ->
					JWEMap = jose_jwe:to_map(JWE),
					Encrypted = jose_jwk:box_encrypt_ecdh_1pu(PlainText, JWEMap, VStaticPublicKey, UStaticSecretKey, UEphemeralSecretKey),
					CompactEncrypted = jose_jwe:compact(Encrypted),
					Decrypted = {_, NewJWE} = jose_jwk:box_decrypt_ecdh_1pu(Encrypted, UStaticPublicKey, VStaticSecretKey),
					{PlainText, NewJWE} =:= Decrypted
					andalso {PlainText, NewJWE} =:= jose_jwe:block_decrypt({UStaticPublicKey, VStaticSecretKey, UEphemeralPublicKey}, CompactEncrypted);
				{{ecdh_es, _, _}, {{AlicePrivateJWK, _AlicePublicJWK}, {BobPrivateJWK, BobPublicJWK}}} ->
					JWEMap = jose_jwe:to_map(JWE),
					Encrypted = jose_jwk:box_encrypt_ecdh_es(PlainText, JWEMap, BobPublicJWK, AlicePrivateJWK),
					CompactEncrypted = jose_jwe:compact(Encrypted),
					Decrypted = {_, NewJWE} = jose_jwk:box_decrypt_ecdh_es(Encrypted, BobPrivateJWK),
					{PlainText, NewJWE} =:= Decrypted
					andalso {PlainText, NewJWE} =:= jose_jwk:block_decrypt(CompactEncrypted, BobPrivateJWK);
				{{rsa, _, _}, {PrivateJWK, PublicJWK}} ->
					Encrypted = jose_jwk:block_encrypt(PlainText, JWE, PublicJWK),
					CompactEncrypted = jose_jwe:compact(Encrypted),
					Decrypted = {_, NewJWE} = jose_jwk:block_decrypt(Encrypted, PrivateJWK),
					{PlainText, NewJWE} =:= Decrypted
					andalso {PlainText, NewJWE} =:= jose_jwk:block_decrypt(CompactEncrypted, PrivateJWK);
				{_, JWK} ->
					Encrypted = jose_jwk:block_encrypt(PlainText, JWE, JWK),
					CompactEncrypted = jose_jwe:compact(Encrypted),
					Decrypted = {_, NewJWE} = jose_jwk:block_decrypt(Encrypted, JWK),
					{PlainText, NewJWE} =:= Decrypted
					andalso {PlainText, NewJWE} =:= jose_jwk:block_decrypt(CompactEncrypted, JWK)
			end
		end).
