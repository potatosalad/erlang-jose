%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  21 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa).

-include_lib("public_key/include/public_key.hrl").

%% Crypto API
-export([block_decrypt/3]).
-export([block_encrypt/3]).
-export([block_decrypt/4]).
-export([block_encrypt/4]).
%% Public Key API
-export([decrypt_private/3]).
-export([encrypt_public/3]).
-export([sign/4]).
-export([verify/5]).
%% API
-export([block_cipher/1]).
-export([crypto_ciphers/0]).
-export([crypto_fallback/0]).
-export([crypto_fallback/1]).
-export([crypto_supports/0]).
-export([constant_time_compare/2]).
-export([ec_key_mode/0]).
-export([is_block_cipher_supported/1]).
-export([is_rsa_crypt_supported/1]).
-export([is_rsa_sign_supported/1]).
-export([supports/0]).

-define(TAB, ?MODULE).

-define(MAYBE_START_JOSE(F), try
	F
catch
	_:_ ->
		_ = jose:start(),
		F
end).

%%====================================================================
%% Crypto API functions
%%====================================================================

block_decrypt(Cipher, Key, CipherText)
		when is_binary(CipherText) ->
	case block_cipher(Cipher) of
		{crypto, aes_ecb} ->
			<< << (crypto:block_decrypt(aes_ecb, Key, Block))/binary >> || << Block:128/bitstring >> <= CipherText >>;
		{Module, BlockCipher} ->
			Module:block_decrypt(BlockCipher, Key, CipherText)
	end.

block_encrypt(Cipher, Key, PlainText)
		when is_binary(PlainText) ->
	case block_cipher(Cipher) of
		{crypto, aes_ecb} ->
			<< << (crypto:block_encrypt(aes_ecb, Key, Block))/binary >> || << Block:128/bitstring >> <= PlainText >>;
		{Module, BlockCipher} ->
			Module:block_encrypt(BlockCipher, Key, PlainText)
	end.

block_decrypt(Cipher, Key, IV, CipherText)
		when is_binary(CipherText) ->
	{Module, BlockCipher} = block_cipher(Cipher),
	Module:block_decrypt(BlockCipher, Key, IV, CipherText);
block_decrypt(Cipher, Key, IV, {AAD, CipherText, CipherTag})
		when is_binary(AAD)
		andalso is_binary(CipherText)
		andalso is_binary(CipherTag) ->
	{Module, BlockCipher} = block_cipher(Cipher),
	Module:block_decrypt(BlockCipher, Key, IV, {AAD, CipherText, CipherTag}).

block_encrypt(Cipher, Key, IV, PlainText)
		when is_binary(PlainText) ->
	{Module, BlockCipher} = block_cipher(Cipher),
	Module:block_encrypt(BlockCipher, Key, IV, PlainText);
block_encrypt(Cipher, Key, IV, {AAD, PlainText})
		when is_binary(AAD)
		andalso is_binary(PlainText) ->
	{Module, BlockCipher} = block_cipher(Cipher),
	Module:block_encrypt(BlockCipher, Key, IV, {AAD, PlainText}).

%%====================================================================
%% Public Key API functions
%%====================================================================

decrypt_private(CipherText, RSAPrivateKey=#'RSAPrivateKey'{}, Algorithm)
		when is_atom(Algorithm) ->
	{Module, Options} = rsa_crypt(Algorithm),
	Module:decrypt_private(CipherText, RSAPrivateKey, Options);
decrypt_private(CipherText, PrivateKey, Options) ->
	public_key:decrypt_private(CipherText, PrivateKey, Options).

encrypt_public(PlainText, RSAPublicKey=#'RSAPublicKey'{}, Algorithm)
		when is_atom(Algorithm) ->
	{Module, Options} = rsa_crypt(Algorithm),
	Module:encrypt_public(PlainText, RSAPublicKey, Options);
encrypt_public(PlainText, PublicKey, Options) ->
	public_key:encrypt_public(PlainText, PublicKey, Options).

sign(Message, DigestType, RSAPrivateKey=#'RSAPrivateKey'{}, Padding)
		when is_atom(Padding) ->
	case rsa_sign(Padding) of
		{Module, undefined} ->
			Module:sign(Message, DigestType, RSAPrivateKey);
		{Module, Options} ->
			Module:sign(Message, DigestType, RSAPrivateKey, Options)
	end;
sign(Message, DigestType, PrivateKey, _Options) ->
	public_key:sign(Message, DigestType, PrivateKey).

verify(Message, DigestType, Signature, RSAPublicKey=#'RSAPublicKey'{}, Padding)
		when is_atom(Padding) ->
	case rsa_sign(Padding) of
		{Module, undefined} ->
			Module:verify(Message, DigestType, Signature, RSAPublicKey);
		{Module, Options} ->
			Module:verify(Message, DigestType, Signature, RSAPublicKey, Options)
	end;
verify(Message, DigestType, Signature, PublicKey, _Options) ->
	public_key:verify(Message, DigestType, Signature, PublicKey).

%%====================================================================
%% API functions
%%====================================================================

block_cipher(Cipher) ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, {cipher, Cipher}, 2)).

crypto_ciphers() ->
	?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{cipher, '$1'}, {'$2', '_'}},
		[{'=/=', '$2', 'jose_jwa_unsupported'}],
		[{{'$1', '$2'}}]
	}])).

crypto_fallback() ->
	application:get_env(jose, crypto_fallback, false).

crypto_fallback(Boolean) when is_boolean(Boolean) ->
	application:set_env(jose, crypto_fallback, Boolean),
	?MAYBE_START_JOSE(jose_server:config_change()).

crypto_supports() ->
	Ciphers = ?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{cipher, '$1'}, {'$2', '_'}},
		[{'=/=', '$2', 'jose_jwa_unsupported'}],
		['$1']
	}])),
	RSACrypt = ?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{rsa_crypt, '$1'}, {'$2', '_'}},
		[{'=/=', '$2', 'jose_jwa_unsupported'}],
		['$1']
	}])),
	RSASign = ?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{rsa_sign, '$1'}, {'$2', '_'}},
		[{'=/=', '$2', 'jose_jwa_unsupported'}],
		['$1']
	}])),
	Supports = crypto:supports(),
	RecommendedHashs = [md5, sha, sha256, sha384, sha512],
	Hashs = RecommendedHashs -- (RecommendedHashs -- proplists:get_value(hashs, Supports)),
	RecommendedPublicKeys = [ec_gf2m, ecdh, ecdsa, rsa],
	PublicKeys = RecommendedPublicKeys -- (RecommendedPublicKeys -- proplists:get_value(public_keys, Supports)),
	[
		{ciphers, Ciphers},
		{hashs, Hashs},
		{public_keys, PublicKeys},
		{rsa_crypt, RSACrypt},
		{rsa_sign, RSASign}
	].

constant_time_compare(<<>>, _) ->
	false;
constant_time_compare(_, <<>>) ->
	false;
constant_time_compare(A, B)
		when is_binary(A) andalso is_binary(B)
		andalso (byte_size(A) =/= byte_size(B)) ->
	false;
constant_time_compare(A, B)
		when is_binary(A) andalso is_binary(B)
		andalso (byte_size(A) =:= byte_size(B)) ->
	constant_time_compare(A, B, 0).

ec_key_mode() ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, ec_key_mode, 2)).

is_block_cipher_supported(Cipher) ->
	case catch block_cipher(Cipher) of
		{crypto, _} ->
			true;
		_ ->
			false
	end.

is_rsa_crypt_supported(Padding) ->
	case catch rsa_crypt(Padding) of
		{public_key, _} ->
			true;
		_ ->
			false
	end.

is_rsa_sign_supported(Padding) ->
	case catch rsa_sign(Padding) of
		{public_key, _} ->
			true;
		_ ->
			false
	end.

rsa_crypt(Algorithm) ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, {rsa_crypt, Algorithm}, 2)).

rsa_sign(Padding) ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, {rsa_sign, Padding}, 2)).

supports() ->
	Supports = crypto_supports(),
	JWEALG = support_check([
		{<<"A128GCMKW">>, ciphers, {aes_gcm, 128}},
		{<<"A192GCMKW">>, ciphers, {aes_gcm, 192}},
		{<<"A256GCMKW">>, ciphers, {aes_gcm, 256}},
		{<<"A128KW">>, ciphers, {aes_ecb, 128}},
		{<<"A192KW">>, ciphers, {aes_ecb, 192}},
		{<<"A256KW">>, ciphers, {aes_ecb, 256}},
		<<"ECDH-ES">>,
		<<"ECDH-ES+A128KW">>,
		<<"ECDH-ES+A192KW">>,
		<<"ECDH-ES+A256KW">>,
		{<<"PBES2-HS256+A128KW">>, ciphers, {aes_ecb, 128}},
		{<<"PBES2-HS384+A192KW">>, ciphers, {aes_ecb, 192}},
		{<<"PBES2-HS512+A256KW">>, ciphers, {aes_ecb, 256}},
		{<<"RSA1_5">>, rsa_crypt, rsa1_5},
		{<<"RSA-OAEP">>, rsa_crypt, rsa_oaep},
		{<<"RSA-OAEP-256">>, rsa_crypt, rsa_oaep_256},
		<<"dir">>
	], Supports, []),
	JWEENC = support_check([
		{<<"A128CBC-HS256">>, ciphers, {aes_cbc, 128}},
		{<<"A192CBC-HS384">>, ciphers, {aes_cbc, 192}},
		{<<"A256CBC-HS512">>, ciphers, {aes_cbc, 256}},
		{<<"A128GCM">>, ciphers, {aes_gcm, 128}},
		{<<"A192GCM">>, ciphers, {aes_gcm, 192}},
		{<<"A256GCM">>, ciphers, {aes_gcm, 256}}
	], Supports, []),
	JWEZIP = support_check([
		<<"DEF">>
	], Supports, []),
	JWKKTY = support_check([
		<<"EC">>,
		<<"oct">>,
		<<"RSA">>
	], Supports, []),
	JWSALG = support_check([
		{<<"ES256">>, public_keys, ecdsa},
		{<<"ES384">>, public_keys, ecdsa},
		{<<"ES512">>, public_keys, ecdsa},
		<<"HS256">>,
		<<"HS384">>,
		<<"HS512">>,
		{<<"PS256">>, rsa_sign, rsa_pkcs1_pss_padding},
		{<<"PS384">>, rsa_sign, rsa_pkcs1_pss_padding},
		{<<"PS512">>, rsa_sign, rsa_pkcs1_pss_padding},
		{<<"RS256">>, rsa_sign, rsa_pkcs1_padding},
		{<<"RS384">>, rsa_sign, rsa_pkcs1_padding},
		{<<"RS512">>, rsa_sign, rsa_pkcs1_padding}
	], Supports, []),
	[
		{jwe,
			{alg, JWEALG},
			{enc, JWEENC},
			{zip, JWEZIP}},
		{jwk,
			{kty, JWKKTY}},
		{jws,
			{alg, JWSALG}}
	].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
constant_time_compare(<< AH, AT/binary >>, << BH, BT/binary >>, R) ->
	constant_time_compare(AT, BT, R bor (BH bxor AH));
constant_time_compare(<<>>, <<>>, R) ->
	R =:= 0.

%% @private
support_check([], _Supports, Acc) ->
	lists:usort(Acc);
support_check([{ALG, Key, Val} | Rest], Supports, Acc) ->
	case lists:member(Val, proplists:get_value(Key, Supports)) of
		false ->
			support_check(Rest, Supports, Acc);
		true ->
			support_check(Rest, Supports, [ALG | Acc])
	end;
support_check([ALG | Rest], Supports, Acc) when is_binary(ALG) ->
	support_check(Rest, Supports, [ALG | Acc]).
