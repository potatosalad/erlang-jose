%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_aes_ecb).

-behaviour(jose_provider).
-behaviour(jose_aes_ecb).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_aes_ecb callbacks
-export([
	aes_128_ecb_decrypt/2,
	aes_128_ecb_encrypt/2,
	aes_192_ecb_decrypt/2,
	aes_192_ecb_encrypt/2,
	aes_256_ecb_decrypt/2,
	aes_256_ecb_encrypt/2
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_aes_ecb,
		priority => low,
		requirements => [
			{app, crypto},
			crypto,
			{app, jose},
			jose_jwa_aes
		]
	}.

%%====================================================================
%% jose_aes_ecb callbacks
%%====================================================================

-spec aes_128_ecb_decrypt(CipherText, CEK) -> PlainText when
	CipherText :: jose_aes_ecb:cipher_text(),
	CEK :: jose_aes_ecb:aes_128_key(),
	PlainText :: jose_aes_ecb:plain_text().
aes_128_ecb_decrypt(CipherText, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(CEK) =:= 128 ->
	jose_jwa_aes:block_decrypt({aes_ecb, 128}, CEK, CipherText).

-spec aes_128_ecb_encrypt(PlainText, CEK) -> CipherText when
	PlainText :: jose_aes_ecb:plain_text(),
	CEK :: jose_aes_ecb:aes_128_key(),
	CipherText :: jose_aes_ecb:cipher_text().
aes_128_ecb_encrypt(PlainText, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(CEK) =:= 128 ->
	jose_jwa_aes:block_encrypt({aes_ecb, 128}, CEK, PlainText).

-spec aes_192_ecb_decrypt(CipherText, CEK) -> PlainText when
	CipherText :: jose_aes_ecb:cipher_text(),
	CEK :: jose_aes_ecb:aes_192_key(),
	PlainText :: jose_aes_ecb:plain_text().
aes_192_ecb_decrypt(CipherText, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(CEK) =:= 192 ->
	jose_jwa_aes:block_decrypt({aes_ecb, 192}, CEK, CipherText).

-spec aes_192_ecb_encrypt(PlainText, CEK) -> CipherText when
	PlainText :: jose_aes_ecb:plain_text(),
	CEK :: jose_aes_ecb:aes_192_key(),
	CipherText :: jose_aes_ecb:cipher_text().
aes_192_ecb_encrypt(PlainText, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(CEK) =:= 192 ->
	jose_jwa_aes:block_encrypt({aes_ecb, 192}, CEK, PlainText).

-spec aes_256_ecb_decrypt(CipherText, CEK) -> PlainText when
	CipherText :: jose_aes_ecb:cipher_text(),
	CEK :: jose_aes_ecb:aes_256_key(),
	PlainText :: jose_aes_ecb:plain_text().
aes_256_ecb_decrypt(CipherText, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(CEK) =:= 256 ->
	jose_jwa_aes:block_decrypt({aes_ecb, 256}, CEK, CipherText).

-spec aes_256_ecb_encrypt(PlainText, CEK) -> CipherText when
	PlainText :: jose_aes_ecb:plain_text(),
	CEK :: jose_aes_ecb:aes_256_key(),
	CipherText :: jose_aes_ecb:cipher_text().
aes_256_ecb_encrypt(PlainText, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(CEK) =:= 256 ->
	jose_jwa_aes:block_encrypt({aes_ecb, 256}, CEK, PlainText).
