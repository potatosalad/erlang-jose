%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc PKCS #1: RSA Cryptography Specifications Version 2.0
%%% See RFC 2437: https://tools.ietf.org/html/rfc2437
%%% @end
%%% Created :  28 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_pkcs1).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([mgf1/3]).
-export([rsaes_oaep_decrypt/3]).
-export([rsaes_oaep_encrypt/3]).

%%====================================================================
%% API functions
%%====================================================================

mgf1(Hash, Seed, MaskLen)
		when is_function(Hash, 1)
		andalso is_binary(Seed)
		andalso is_integer(MaskLen)
		andalso MaskLen >= 0 ->
	HashLen = byte_size(Hash(<<>>)),
	case MaskLen > (16#FFFFFFFF * HashLen) of
		false ->
			Reps = ceiling(MaskLen / HashLen),
			{ok, derive_mgf1(Hash, 0, Reps, Seed, MaskLen, <<>>)};
		true ->
			{error, mask_too_long}
	end;
mgf1(Hash, Seed, MaskLen)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	mgf1(HashFun, Seed, MaskLen).

rsaes_oaep_decrypt(Hash, CipherText, RSAPrivateKey=#'RSAPrivateKey'{modulus=N})
		when is_function(Hash, 1)
		andalso is_binary(CipherText) ->
	PublicBitSize = int_to_bit_size(N),
	PrivateByteSize = PublicBitSize div 8,
	HashLen = byte_size(Hash(<<>>)),
	EM = dp(CipherText, RSAPrivateKey),
	LabelHash = Hash(<<>>),
	<< MaskedSeed:HashLen/binary, MaskedDB/binary >> = EM,
	{ok, SeedMask} = mgf1(Hash, MaskedDB, HashLen),
	Seed = crypto:exor(MaskedSeed, SeedMask),
	{ok, DBMask} = mgf1(Hash, Seed, PrivateByteSize - HashLen - 1),
	DB = crypto:exor(MaskedDB, DBMask),
	<< LabelHash:HashLen/binary, DB1/binary >> = DB,
	<< 1, Message/binary >> = unpad_zero(DB1),
	Message;
rsaes_oaep_decrypt(Hash, CipherText, RSAPrivateKey)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsaes_oaep_decrypt(HashFun, CipherText, RSAPrivateKey).

rsaes_oaep_encrypt(Hash, PlainText, RSAPublicKey=#'RSAPublicKey'{modulus=N})
		when is_function(Hash, 1)
		andalso is_binary(PlainText) ->
	HashLen = byte_size(Hash(<<>>)),
	Seed = crypto:rand_bytes(HashLen),
	PublicByteSize = int_to_byte_size(N),
	PlainTextLen = byte_size(PlainText),
	LabelHash = Hash(<<>>),
	DB = << LabelHash/binary, 0:((PublicByteSize - PlainTextLen - (2 * HashLen) - 2) * 8), 1, PlainText/binary >>,
	{ok, DBMask} = mgf1(Hash, Seed, PublicByteSize - HashLen - 1),
	MaskedDB = crypto:exor(DB, DBMask),
	{ok, SeedMask} = mgf1(Hash, MaskedDB, HashLen),
	MaskedSeed = crypto:exor(Seed, SeedMask),
	EM = << MaskedSeed/binary, MaskedDB/binary >>,
	ep(EM, RSAPublicKey);
rsaes_oaep_encrypt(Hash, PlainText, RSAPublicKey)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsaes_oaep_encrypt(HashFun, PlainText, RSAPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
ceiling(X) when X < 0 ->
	trunc(X);
ceiling(X) ->
	T = trunc(X),
	case X - T == 0 of
		false ->
			T + 1;
		true ->
			T
	end.

%% @private
derive_mgf1(_Hash, Reps, Reps, _Seed, MaskLen, T) ->
	binary:part(T, 0, MaskLen);
derive_mgf1(Hash, Counter, Reps, Seed, MaskLen, T) ->
	CounterBin = << Counter:8/unsigned-big-integer-unit:4 >>,
	NewT = << T/binary, (Hash(<< Seed/binary, CounterBin/binary >>))/binary >>,
	derive_mgf1(Hash, Counter + 1, Reps, Seed, MaskLen, NewT).

%% @private
dp(B, #'RSAPrivateKey'{modulus=N, privateExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
ep(B, #'RSAPublicKey'{modulus=N, publicExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
int_to_bit_size(I) ->
	int_to_bit_size(I, 0).

%% @private
int_to_bit_size(0, B) ->
	B;
int_to_bit_size(I, B) ->
	int_to_bit_size(I bsr 1, B + 1).

%% @private
int_to_byte_size(I) ->
	int_to_byte_size(I, 0).

%% @private
int_to_byte_size(0, B) ->
	B;
int_to_byte_size(I, B) ->
	int_to_byte_size(I bsr 8, B + 1).

%% @private
resolve_hash(HashFun) when is_function(HashFun, 1) ->
	HashFun;
resolve_hash(DigestType) when is_atom(DigestType) ->
	fun(Data) ->
		crypto:hash(DigestType, Data)
	end;
resolve_hash({hmac, DigestType, Key}) when is_atom(DigestType) ->
	fun(Data) ->
		crypto:hmac(DigestType, Key, Data)
	end.

%% @private
unpad_zero(<< 0, Rest/binary >>) ->
	unpad_zero(Rest);
unpad_zero(Rest) ->
	Rest.
