%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc Advanced Encryption Standard (AES) Key Wrap Algorithm
%%% See RFC 3394 [https://tools.ietf.org/html/rfc3394]
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_aes_kw).

-behaviour(jose_provider).
-behaviour(jose_aes_kw).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_aes_kw callbacks
-export([
	aes_128_kw_unwrap/2,
	aes_128_kw_wrap/2,
	aes_192_kw_unwrap/2,
	aes_192_kw_wrap/2,
	aes_256_kw_unwrap/2,
	aes_256_kw_wrap/2
]).
%% Internal API
-export([
	wrap/3,
	wrap/4,
	unwrap/3,
	unwrap/4
]).

%% Macros
-define(MSB64,      1/unsigned-big-integer-unit:64).
-define(DEFAULT_IV, << 16#A6A6A6A6A6A6A6A6:?MSB64 >>).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_aes_kw,
		priority => low,
		requirements => [
			{app, crypto},
			crypto,
			{app, jose},
			jose_aes_ecb
		]
	}.

%%====================================================================
%% jose_aes_kw callbacks
%%====================================================================

-spec aes_128_kw_unwrap(CipherText, KEK) -> PlainText | error when
	CipherText :: jose_aes_kw:cipher_text(),
	KEK :: jose_aes_kw:aes_128_key(),
	PlainText :: jose_aes_kw:plain_text().
aes_128_kw_unwrap(CipherText, KEK) when bit_size(CipherText) rem 64 =:= 0 andalso bit_size(KEK) =:= 128 ->
	unwrap(fun jose_aes_ecb:aes_128_ecb_decrypt/2, CipherText, KEK).

-spec aes_128_kw_wrap(PlainText, KEK) -> CipherText when
	PlainText :: jose_aes_kw:plain_text(),
	KEK :: jose_aes_kw:aes_128_key(),
	CipherText :: jose_aes_kw:cipher_text().
aes_128_kw_wrap(PlainText, KEK) when bit_size(PlainText) rem 64 =:= 0 andalso bit_size(KEK) =:= 128 ->
	wrap(fun jose_aes_ecb:aes_128_ecb_encrypt/2, PlainText, KEK).

-spec aes_192_kw_unwrap(CipherText, KEK) -> PlainText | error when
	CipherText :: jose_aes_kw:cipher_text(),
	KEK :: jose_aes_kw:aes_192_key(),
	PlainText :: jose_aes_kw:plain_text().
aes_192_kw_unwrap(CipherText, KEK) when bit_size(CipherText) rem 64 =:= 0 andalso bit_size(KEK) =:= 192 ->
	unwrap(fun jose_aes_ecb:aes_192_ecb_decrypt/2, CipherText, KEK).

-spec aes_192_kw_wrap(PlainText, KEK) -> CipherText when
	PlainText :: jose_aes_kw:plain_text(),
	KEK :: jose_aes_kw:aes_192_key(),
	CipherText :: jose_aes_kw:cipher_text().
aes_192_kw_wrap(PlainText, KEK) when bit_size(PlainText) rem 64 =:= 0 andalso bit_size(KEK) =:= 192 ->
	wrap(fun jose_aes_ecb:aes_192_ecb_encrypt/2, PlainText, KEK).

-spec aes_256_kw_unwrap(CipherText, KEK) -> PlainText | error when
	CipherText :: jose_aes_kw:cipher_text(),
	KEK :: jose_aes_kw:aes_256_key(),
	PlainText :: jose_aes_kw:plain_text().
aes_256_kw_unwrap(CipherText, KEK) when bit_size(CipherText) rem 64 =:= 0 andalso bit_size(KEK) =:= 256 ->
	unwrap(fun jose_aes_ecb:aes_256_ecb_decrypt/2, CipherText, KEK).

-spec aes_256_kw_wrap(PlainText, KEK) -> CipherText when
	PlainText :: jose_aes_kw:plain_text(),
	KEK :: jose_aes_kw:aes_256_key(),
	CipherText :: jose_aes_kw:cipher_text().
aes_256_kw_wrap(PlainText, KEK) when bit_size(PlainText) rem 64 =:= 0 andalso bit_size(KEK) =:= 256 ->
	wrap(fun jose_aes_ecb:aes_256_ecb_encrypt/2, PlainText, KEK).

%%====================================================================
%% Internal API functions
%%====================================================================

wrap(EncryptBlock, PlainText, KEK) ->
	wrap(EncryptBlock, PlainText, KEK, ?DEFAULT_IV).

wrap(EncryptBlock, PlainText, KEK, IV)
		when is_function(EncryptBlock, 2)
		andalso (bit_size(PlainText) rem 64) =:= 0
		andalso (bit_size(KEK) =:= 128
			orelse bit_size(KEK) =:= 192
			orelse bit_size(KEK) =:= 256) ->
	Buffer = << IV/binary, PlainText/binary >>,
	BlockCount = (byte_size(Buffer) div 8) - 1,
	do_wrap(EncryptBlock, Buffer, 0, BlockCount, KEK).

unwrap(DecryptBlock, CipherText, KEK) ->
	unwrap(DecryptBlock, CipherText, KEK, ?DEFAULT_IV).

unwrap(DecryptBlock, CipherText, KEK, IV)
		when is_function(DecryptBlock, 2)
		andalso (bit_size(CipherText) rem 64) =:= 0
		andalso (bit_size(KEK) =:= 128
			orelse bit_size(KEK) =:= 192
			orelse bit_size(KEK) =:= 256) ->
	BlockCount = (byte_size(CipherText) div 8) - 1,
	IVSize = byte_size(IV),
	case do_unwrap(DecryptBlock, CipherText, 5, BlockCount, KEK) of
		<< IV:IVSize/binary, PlainText/binary >> ->
			PlainText;
		_ ->
			error
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
do_wrap(_EncryptBlock, Buffer, 6, _BlockCount, _KEK) ->
	Buffer;
do_wrap(EncryptBlock, Buffer, J, BlockCount, KEK) ->
	do_wrap(EncryptBlock, do_wrap(EncryptBlock, Buffer, J, 1, BlockCount, KEK), J + 1, BlockCount, KEK).

%% @private
do_wrap(_EncryptBlock, Buffer, _J, I, BlockCount, _KEK) when I > BlockCount ->
	Buffer;
do_wrap(EncryptBlock, << A0:8/binary, Rest/binary >>, J, I, BlockCount, KEK) ->
	HeadSize = (I - 1) * 8,
	<< Head:HeadSize/binary, B0:8/binary, Tail/binary >> = Rest,
	Round = (BlockCount * J) + I,
	Data = << A0/binary, B0/binary >>,
	<< A1:?MSB64, B1/binary >> = EncryptBlock(Data, KEK),
	A2 = A1 bxor Round,
	do_wrap(EncryptBlock, << A2:?MSB64, Head/binary, B1/binary, Tail/binary >>, J, I + 1, BlockCount, KEK).

%% @private
do_unwrap(_DecryptBlock, Buffer, J, _BlockCount, _KEK) when J < 0 ->
	Buffer;
do_unwrap(DecryptBlock, Buffer, J, BlockCount, KEK) ->
	do_unwrap(DecryptBlock, do_unwrap(DecryptBlock, Buffer, J, BlockCount, BlockCount, KEK), J - 1, BlockCount, KEK).

%% @private
do_unwrap(_DecryptBlock, Buffer, _J, I, _BlockCount, _KEK) when I < 1 ->
	Buffer;
do_unwrap(DecryptBlock, << A0:?MSB64, Rest/binary >>, J, I, BlockCount, KEK) ->
	HeadSize = (I - 1) * 8,
	<< Head:HeadSize/binary, B0:8/binary, Tail/binary >> = Rest,
	Round = (BlockCount * J) + I,
	A1 = A0 bxor Round,
	Data = << A1:?MSB64, B0/binary >>,
	<< A2:8/binary, B1/binary >> = DecryptBlock(Data, KEK),
	do_unwrap(DecryptBlock, << A2/binary, Head/binary, B1/binary, Tail/binary >>, J, I - 1, BlockCount, KEK).
