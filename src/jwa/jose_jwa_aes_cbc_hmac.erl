%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  03 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_aes_cbc_hmac).

-behaviour(jose_provider).
-behaviour(jose_aes_cbc_hmac).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_aes_cbc_hmac callbacks
-export([
	aes_128_cbc_hmac_sha256_decrypt/5,
	aes_128_cbc_hmac_sha256_encrypt/4,
	aes_192_cbc_hmac_sha384_decrypt/5,
	aes_192_cbc_hmac_sha384_encrypt/4,
	aes_256_cbc_hmac_sha512_decrypt/5,
	aes_256_cbc_hmac_sha512_encrypt/4
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_aes_cbc_hmac,
        priority => low,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%====================================================================
%% jose_aes_cbc_hmac callbacks
%%====================================================================

-spec aes_128_cbc_hmac_sha256_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
aes_128_cbc_hmac_sha256_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 128
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 256 ->
	MacKeyBits = 128,
	EncKeyBits = 128,
	CipherTagBits = 128,
	<< MacKey:MacKeyBits/bits, EncKey:EncKeyBits/bits >> = CEK,
	AADLength = << (bit_size(AAD)):1/unsigned-big-integer-unit:64 >>,
	MacData = << AAD/binary, IV/binary, CipherText/binary, AADLength/binary >>,
	case jose_hmac:hmac_sha256(MacKey, MacData) of
		<< CipherTag:CipherTagBits/bits, _/bits >> ->
			PaddedPlainText = jose_aes_cbc:aes_128_cbc_decrypt(CipherText, IV, EncKey),
			PlainText = jose_jwa_pkcs7:unpad(PaddedPlainText),
			PlainText;
		_ ->
			error
	end.

-spec aes_128_cbc_hmac_sha256_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag().
aes_128_cbc_hmac_sha256_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 256 ->
	MacKeyBits = 128,
	EncKeyBits = 128,
	CipherTagBits = 128,
	<< MacKey:MacKeyBits/bits, EncKey:EncKeyBits/bits >> = CEK,
	PaddedPlainText = jose_jwa_pkcs7:pad(PlainText),
	CipherText = jose_aes_cbc:aes_128_cbc_encrypt(PaddedPlainText, IV, EncKey),
	AADLength = << (bit_size(AAD)):1/unsigned-big-integer-unit:64 >>,
	MacData = << AAD/binary, IV/binary, CipherText/binary, AADLength/binary >>,
	<< CipherTag:CipherTagBits/bits, _/bits >> = jose_hmac:hmac_sha256(MacKey, MacData),
	{CipherText, CipherTag}.

-spec aes_192_cbc_hmac_sha384_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
aes_192_cbc_hmac_sha384_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 192
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 384 ->
	MacKeyBits = 192,
	EncKeyBits = 192,
	CipherTagBits = 192,
	<< MacKey:MacKeyBits/bits, EncKey:EncKeyBits/bits >> = CEK,
	AADLength = << (bit_size(AAD)):1/unsigned-big-integer-unit:64 >>,
	MacData = << AAD/binary, IV/binary, CipherText/binary, AADLength/binary >>,
	case jose_hmac:hmac_sha384(MacKey, MacData) of
		<< CipherTag:CipherTagBits/bits, _/bits >> ->
			PaddedPlainText = jose_aes_cbc:aes_192_cbc_decrypt(CipherText, IV, EncKey),
			PlainText = jose_jwa_pkcs7:unpad(PaddedPlainText),
			PlainText;
		_ ->
			error
	end.

-spec aes_192_cbc_hmac_sha384_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_tag().
aes_192_cbc_hmac_sha384_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 384 ->
	MacKeyBits = 192,
	EncKeyBits = 192,
	CipherTagBits = 192,
	<< MacKey:MacKeyBits/bits, EncKey:EncKeyBits/bits >> = CEK,
	PaddedPlainText = jose_jwa_pkcs7:pad(PlainText),
	CipherText = jose_aes_cbc:aes_192_cbc_encrypt(PaddedPlainText, IV, EncKey),
	AADLength = << (bit_size(AAD)):1/unsigned-big-integer-unit:64 >>,
	MacData = << AAD/binary, IV/binary, CipherText/binary, AADLength/binary >>,
	<< CipherTag:CipherTagBits/bits, _/bits >> = jose_hmac:hmac_sha384(MacKey, MacData),
	{CipherText, CipherTag}.

-spec aes_256_cbc_hmac_sha512_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
aes_256_cbc_hmac_sha512_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 256
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 512 ->
	MacKeyBits = 256,
	EncKeyBits = 256,
	CipherTagBits = 256,
	<< MacKey:MacKeyBits/bits, EncKey:EncKeyBits/bits >> = CEK,
	AADLength = << (bit_size(AAD)):1/unsigned-big-integer-unit:64 >>,
	MacData = << AAD/binary, IV/binary, CipherText/binary, AADLength/binary >>,
	case jose_hmac:hmac_sha512(MacKey, MacData) of
		<< CipherTag:CipherTagBits/bits, _/bits >> ->
			PaddedPlainText = jose_aes_cbc:aes_256_cbc_decrypt(CipherText, IV, EncKey),
			PlainText = jose_jwa_pkcs7:unpad(PaddedPlainText),
			PlainText;
		_ ->
			error
	end.

-spec aes_256_cbc_hmac_sha512_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_tag().
aes_256_cbc_hmac_sha512_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 512 ->
	MacKeyBits = 256,
	EncKeyBits = 256,
	CipherTagBits = 256,
	<< MacKey:MacKeyBits/bits, EncKey:EncKeyBits/bits >> = CEK,
	PaddedPlainText = jose_jwa_pkcs7:pad(PlainText),
	CipherText = jose_aes_cbc:aes_256_cbc_encrypt(PaddedPlainText, IV, EncKey),
	AADLength = << (bit_size(AAD)):1/unsigned-big-integer-unit:64 >>,
	MacData = << AAD/binary, IV/binary, CipherText/binary, AADLength/binary >>,
	<< CipherTag:CipherTagBits/bits, _/bits >> = jose_hmac:hmac_sha512(MacKey, MacData),
	{CipherText, CipherTag}.
