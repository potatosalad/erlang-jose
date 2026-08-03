%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_alg_rsa_props).

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

alg() ->
	oneof([
		<<"RSA1_5">>,
		<<"RSA-OAEP">>,
		<<"RSA-OAEP-256">>
	]).

enc() ->
	oneof([
		<<"A128CBC-HS256">>,
		<<"A192CBC-HS384">>,
		<<"A256CBC-HS512">>,
		<<"A128GCM">>,
		<<"A192GCM">>,
		<<"A256GCM">>,
		<<"C20P">>,
		<<"XC20P">>
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

%% GHSA-vwvr-f994-6j9j: RSA key unwrapping must not tell the caller whether the
%% decrypted RSA block was well formed. RFC 7516, Section 11.5 (and RFC 3218)
%% require that format, padding, and length errors of the JWE Encrypted Key be
%% indistinguishable, and that a random CEK be substituted on failure. Anything
%% else is the one-bit oracle a Bleichenbacher adaptive chosen-ciphertext attack
%% against RSAES-PKCS1-v1_5 ("RSA1_5") consumes.
%%
%% Every ciphertext below is buildable by an attacker who knows only the public
%% key, which is precisely the reported threat model.
prop_ghsa_vwvr_f994_6j9j() ->
	?FORALL({{AlicePrivateJWK, AlicePublicJWK}, JWE},
		jwk_jwe_gen(),
		begin
			{DecKey, DecJWE} = jose_jwe:next_cek(AlicePublicJWK, JWE),
			{EncKey, EncJWE} = jose_jwe:key_encrypt(AlicePublicJWK, DecKey, DecJWE),
			K = byte_size(EncKey),
			MalformedKeys = [
				binary:copy(<< 16#00 >>, K),      % c = 0, decrypts to an all-zero block
				binary:copy(<< 16#FF >>, K),      % c >= n, rejected by the modexp itself
				crypto:strong_rand_bytes(K),      % non-conforming padding
				binary:part(EncKey, 0, K - 1),    % length error (short)
				<< EncKey/binary, 16#00 >>        % length error (long)
			],
			DecKey =:= jose_jwe:key_decrypt(AlicePrivateJWK, EncKey, EncJWE)
				andalso lists:all(fun(MalformedKey) ->
					case catch jose_jwe:key_decrypt(AlicePrivateJWK, MalformedKey, EncJWE) of
						SubstituteKey when is_binary(SubstituteKey) ->
							byte_size(SubstituteKey) =:= byte_size(DecKey)
								andalso SubstituteKey =/= DecKey;
						_Distinguishable ->
							false
					end
				end, MalformedKeys)
		end).
