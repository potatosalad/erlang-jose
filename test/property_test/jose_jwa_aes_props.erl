%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_aes_props).

-include_lib("triq/include/triq.hrl").

-compile(export_all).

block_size() -> oneof([128, 192, 256]).
iv()         -> binary(16).

block_encryptor_gen() ->
	?LET({Bits, IV, PlainText},
		{block_size(), iv(), binary()},
		{Bits, binary(Bits div 8), IV, jose_jwa_pkcs7:pad(PlainText)}).

prop_block_encrypt_and_block_decrypt() ->
	?FORALL({Bits, Key, IV, PlainText},
		block_encryptor_gen(),
		begin
			CipherText = jose_jwa_aes:block_encrypt(Bits, Key, IV, PlainText),
			PlainText =:= jose_jwa_aes:block_decrypt(Bits, Key, IV, CipherText)
		end).
