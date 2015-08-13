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

%% API
-export([block_cipher/1]).
-export([block_decrypt/3]).
-export([block_encrypt/3]).
-export([block_decrypt/4]).
-export([block_encrypt/4]).
-export([crypto_supports/0]).
-export([crypto_ciphers/0]).
-export([constant_time_compare/2]).
-export([ec_key_mode/0]).
-export([is_native_cipher/1]).
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
%% API functions
%%====================================================================

block_cipher(Cipher) ->
	?MAYBE_START_JOSE(ets:lookup_element(?TAB, {cipher, Cipher}, 2)).

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

crypto_ciphers() ->
	?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{cipher, '$1'}, {'$2', '_'}},
		[{'andalso',
			{is_atom, '$1'},
			{'=/=', '$2', 'jose_jwa_unsupported'}}],
		[{{'$1', '$2'}}]
	}])).

crypto_supports() ->
	Ciphers = ?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{cipher, '$1'}, {'$2', '_'}},
		[{'andalso',
			{is_atom, '$1'},
			{'=/=', '$2', 'jose_jwa_unsupported'}}],
		['$1']
	}])),
	RSAPadding = ?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{rsa_padding, '$1'}},
		[],
		['$1']
	}])),
	Signers = ?MAYBE_START_JOSE(ets:select(?TAB, [{
		{{signer, '$1'}},
		[],
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
		{rsa_paddings, RSAPadding},
		{signers, Signers}
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

is_native_cipher(Cipher) ->
	try block_cipher(Cipher) of
		crypto ->
			true;
		_ ->
			false
	catch
		_:_ ->
			false
	end.

supports() ->
	Supports = crypto_supports(),
	JWEALG = support_check([
		{<<"A128GCMKW">>, ciphers, aes_gcm128},
		{<<"A192GCMKW">>, ciphers, aes_gcm192},
		{<<"A256GCMKW">>, ciphers, aes_gcm256},
		{<<"A128KW">>, ciphers, aes_ecb128},
		{<<"A192KW">>, ciphers, aes_ecb192},
		{<<"A256KW">>, ciphers, aes_ecb256},
		<<"ECDH-ES">>,
		<<"ECDH-ES+A128KW">>,
		<<"ECDH-ES+A192KW">>,
		<<"ECDH-ES+A256KW">>,
		{<<"PBES2-HS256+A128KW">>, ciphers, aes_ecb128},
		{<<"PBES2-HS384+A192KW">>, ciphers, aes_ecb192},
		{<<"PBES2-HS512+A256KW">>, ciphers, aes_ecb256},
		{<<"RSA1_5">>, rsa_paddings, rsa_pkcs1_padding},
		{<<"RSA-OAEP">>, rsa_paddings, rsa_pkcs1_oaep_padding},
		{<<"RSA-OAEP-256">>, rsa_paddings, rsa_pkcs1_oaep256_padding},
		<<"dir">>
	], Supports, []),
	JWEENC = support_check([
		{<<"A128CBC-HS256">>, ciphers, aes_cbc128},
		{<<"A192CBC-HS384">>, ciphers, aes_cbc192},
		{<<"A256CBC-HS512">>, ciphers, aes_cbc256},
		{<<"A128GCM">>, ciphers, aes_gcm128},
		{<<"A192GCM">>, ciphers, aes_gcm192},
		{<<"A256GCM">>, ciphers, aes_gcm256}
	], Supports, []),
	JWSALG = support_check([
		{<<"ES256">>, signers, ecdsa},
		{<<"ES384">>, signers, ecdsa},
		{<<"ES512">>, signers, ecdsa},
		{<<"HS256">>, signers, hmac},
		{<<"HS384">>, signers, hmac},
		{<<"HS512">>, signers, hmac},
		{<<"PS256">>, signers, rsa_pss},
		{<<"PS384">>, signers, rsa_pss},
		{<<"PS512">>, signers, rsa_pss},
		{<<"RS256">>, signers, rsa_pkcs1_v1_5},
		{<<"RS384">>, signers, rsa_pkcs1_v1_5},
		{<<"RS512">>, signers, rsa_pkcs1_v1_5}
	], Supports, []),
	[
		{jwe,
			{alg, JWEALG},
			{enc, JWEENC}},
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
