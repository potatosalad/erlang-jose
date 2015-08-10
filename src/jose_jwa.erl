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
-export([ciphers/0]).
-export([constant_time_compare/2]).
-export([ec_key_mode/0]).
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

ciphers() ->
	?MAYBE_START_JOSE(ets:select(?TAB, [{{{cipher, '$1'}, {'$2', '_'}}, [{is_atom, '$1'}], [{{'$1', '$2'}}]}])).

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

supports() ->
	Ciphers = ?MAYBE_START_JOSE(ets:select(?TAB, [{{{cipher, '$1'}, '_'}, [{is_atom, '$1'}], ['$1']}])),
	Supports = crypto:supports(),
	RecommendedHashs = [md5, sha, sha256, sha384, sha512],
	Hashs = RecommendedHashs -- (RecommendedHashs -- proplists:get_value(hashs, Supports)),
	RecommendedPublicKeys = [ec_gf2m, ecdh, ecdsa, rsa],
	PublicKeys = RecommendedPublicKeys -- (RecommendedPublicKeys -- proplists:get_value(public_keys, Supports)),
	[{ciphers, Ciphers}, {hashs, Hashs}, {public_keys, PublicKeys}].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
constant_time_compare(<< AH, AT/binary >>, << BH, BT/binary >>, R) ->
	constant_time_compare(AT, BT, R bor (BH bxor AH));
constant_time_compare(<<>>, <<>>, R) ->
	R =:= 0.
