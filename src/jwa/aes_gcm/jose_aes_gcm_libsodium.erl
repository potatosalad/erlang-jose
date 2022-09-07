%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  03 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_aes_gcm_libsodium).

-behaviour(jose_provider).
-behaviour(jose_aes_gcm).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_aes_gcm callbacks
-export([
	aes_256_gcm_decrypt/5,
	aes_256_gcm_encrypt/4
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_aes_gcm,
		priority => normal,
		requirements => [
			{app, libsodium},
			libsodium_crypto_aead_aes256gcm
		]
	}.

%%====================================================================
%% jose_aes_gcm callbacks
%%====================================================================

-spec aes_256_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_gcm:cipher_text(),
	CipherTag  :: jose_aes_gcm:aes_gcm_gmac(),
	AAD        :: jose_aes_gcm:additional_authenticated_data(),
	IV         :: jose_aes_gcm:aes_gcm_iv(),
	CEK        :: jose_aes_gcm:aes_256_key(),
	PlainText  :: jose_aes_gcm:plain_text().
aes_256_gcm_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 128
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 96
		andalso bit_size(CEK) =:= 256 ->
	case libsodium_crypto_aead_aes256gcm:decrypt_detached(CipherText, CipherTag, AAD, IV, CEK) of
		-1 ->
			error;
		PlainText when is_binary(PlainText) ->
			PlainText
	end.

-spec aes_256_gcm_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_gcm:plain_text(),
	AAD        :: jose_aes_gcm:additional_authenticated_data(),
	IV         :: jose_aes_gcm:aes_gcm_iv(),
	CEK        :: jose_aes_gcm:aes_256_key(),
	CipherText :: jose_aes_gcm:cipher_text(),
	CipherTag  :: jose_aes_gcm:aes_gcm_gmac().
aes_256_gcm_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 96
		andalso bit_size(CEK) =:= 256 ->
	libsodium_crypto_aead_aes256gcm:encrypt_detached(PlainText, AAD, IV, CEK).
