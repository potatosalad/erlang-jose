%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_aes_props).

-include_lib("triq/include/triq.hrl").

-compile(export_all).

block_size() -> oneof([128, 192, 256]).
cbc_iv()     -> binary(16).

cbc_block_encryptor_gen() ->
	?LET({Bits, IV, PlainText},
		{block_size(), cbc_iv(), binary()},
		{Bits, binary(Bits div 8), IV, jose_jwa_pkcs7:pad(PlainText)}).

ecb_block_encryptor_gen() ->
	?LET({Bits, PlainText},
		{block_size(), binary()},
		{Bits, binary(Bits div 8), jose_jwa_pkcs7:pad(PlainText)}).

prop_cbc_block_encrypt_and_cbc_block_decrypt() ->
	?FORALL({Bits, Key, IV, PlainText},
		cbc_block_encryptor_gen(),
		begin
			CipherText = jose_jwa_aes:block_encrypt(Bits, Key, IV, PlainText),
			PlainText =:= jose_jwa_aes:block_decrypt(Bits, Key, IV, CipherText)
		end).

prop_cbc_block_encrypt_and_crypto_block_decrypt() ->
	?FORALL({Bits, Key, IV, PlainText},
		?SUCHTHAT({Bits, _Key, _IV, _PlainText},
			cbc_block_encryptor_gen(),
			Bits =/= 192),
		begin
			CipherText = jose_jwa_aes:block_encrypt(Bits, Key, IV, PlainText),
			Cipher = list_to_atom("aes_cbc" ++ integer_to_list(Bits)),
			PlainText =:= crypto:block_decrypt(Cipher, Key, IV, CipherText)
		end).

prop_crypto_block_encrypt_and_cbc_block_decrypt() ->
	?FORALL({Bits, Key, IV, PlainText},
		?SUCHTHAT({Bits, _Key, _IV, _PlainText},
			cbc_block_encryptor_gen(),
			Bits =/= 192),
		begin
			Cipher = list_to_atom("aes_cbc" ++ integer_to_list(Bits)),
			CipherText = crypto:block_encrypt(Cipher, Key, IV, PlainText),
			PlainText =:= jose_jwa_aes:block_decrypt(Bits, Key, IV, CipherText)
		end).

prop_crypto_block_encrypt_and_ecb_block_decrypt() ->
	?FORALL({Bits, Key, PlainText},
		?SUCHTHAT({Bits, _Key, _PlainText},
			ecb_block_encryptor_gen(),
			Bits =/= 192),
		begin
			Cipher = aes_ecb,
			CipherText = << << (crypto:block_encrypt(Cipher, Key, Block))/binary >> || << Block:16/binary >> <= PlainText >>,
			PlainText =:= jose_jwa_aes:block_decrypt(Bits, Key, CipherText)
		end).

prop_ecb_block_encrypt_and_ecb_block_decrypt() ->
	?FORALL({Bits, Key, PlainText},
		ecb_block_encryptor_gen(),
		begin
			CipherText = jose_jwa_aes:block_encrypt(Bits, Key, PlainText),
			PlainText =:= jose_jwa_aes:block_decrypt(Bits, Key, CipherText)
		end).

prop_ecb_block_encrypt_and_crypto_block_decrypt() ->
	?FORALL({Bits, Key, PlainText},
		?SUCHTHAT({Bits, _Key, _PlainText},
			ecb_block_encryptor_gen(),
			Bits =/= 192),
		begin
			CipherText = jose_jwa_aes:block_encrypt(Bits, Key, PlainText),
			Cipher = aes_ecb,
			PlainText =:= << << (crypto:block_decrypt(Cipher, Key, Block))/binary >> || << Block:16/binary >> <= CipherText >>
		end).
