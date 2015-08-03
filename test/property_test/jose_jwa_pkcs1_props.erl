%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_pkcs1_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("triq/include/triq.hrl").

-compile(export_all).

digest_type()   -> oneof([md5, sha, sha224, sha256, sha384, sha512, {hmac, md5, <<>>}, {hmac, sha, <<>>}, {hmac, sha224, <<>>}, {hmac, sha256, <<>>}, {hmac, sha384, <<>>}, {hmac, sha512, <<>>}]).
salt_size()     -> non_neg_integer().
modulus_size()  -> int(256, 2048). % int(256, 8192) | pos_integer().
exponent_size() -> return(65537).  % pos_integer().

rsa_keypair(ModulusSize) ->
	?LET(ExponentSize,
		exponent_size(),
		begin
			case cutkey:rsa(ModulusSize, ExponentSize, [{return, key}]) of
				{ok, PrivateKey=#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}} ->
					{PrivateKey, #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent}};
				{error, _} ->
					erlang:error({badarg, [ModulusSize, ExponentSize, [{return, key}]]})
			end
		end).

%%====================================================================
%% RSAES-OAEP
%%====================================================================

rsaes_oaep_encryptor_gen() ->
	?LET({DigestType, ModulusSize, PlainText},
		?SUCHTHAT({DigestType, ModulusSize, PlainText},
			{digest_type(), modulus_size(), binary()},
			ModulusSize >= ((byte_size(do_hash(DigestType, <<>>)) * 2 + 2 + byte_size(PlainText)) * 8)),
		{rsa_keypair(ModulusSize), ModulusSize, DigestType, PlainText}).

rsaes_oaep_encryptor_with_label_gen() ->
	?LET({DigestType, ModulusSize, PlainText},
		?SUCHTHAT({DigestType, ModulusSize, PlainText},
			{digest_type(), modulus_size(), binary()},
			ModulusSize >= ((byte_size(do_hash(DigestType, <<>>)) * 2 + 2 + byte_size(PlainText)) * 8)),
		{rsa_keypair(ModulusSize), ModulusSize, DigestType, binary(), PlainText}).

prop_rsaes_oaep_encrypt_and_decrypt() ->
	?FORALL({{PrivateKey, PublicKey}, _ModulusSize, DigestType, PlainText},
		rsaes_oaep_encryptor_gen(),
		begin
			{ok, CipherText} = jose_jwa_pkcs1:rsaes_oaep_encrypt(DigestType, PlainText, PublicKey),
			PlainText =:= jose_jwa_pkcs1:rsaes_oaep_decrypt(DigestType, CipherText, PrivateKey)
		end).

prop_rsaes_oaep_encrypt_and_decrypt_with_label() ->
	?FORALL({{PrivateKey, PublicKey}, _ModulusSize, DigestType, Label, PlainText},
		rsaes_oaep_encryptor_with_label_gen(),
		begin
			{ok, CipherText} = jose_jwa_pkcs1:rsaes_oaep_encrypt(DigestType, PlainText, Label, PublicKey),
			PlainText =:= jose_jwa_pkcs1:rsaes_oaep_decrypt(DigestType, CipherText, Label, PrivateKey)
		end).

%%====================================================================
%% RSASSA-PSS
%%====================================================================

rsassa_pss_signer_gen() ->
	?LET({DigestType, ModulusSize},
		?SUCHTHAT({DigestType, ModulusSize},
			{digest_type(), modulus_size()},
			ModulusSize >= (bit_size(do_hash(DigestType, <<>>)) * 2 + 16)),
		{rsa_keypair(ModulusSize), ModulusSize, DigestType, binary()}).

rsassa_pss_signer_with_salt_gen() ->
	?LET({DigestType, ModulusSize, SaltSize},
		?SUCHTHAT({DigestType, ModulusSize, SaltSize},
			{digest_type(), modulus_size(), salt_size()},
			ModulusSize >= (bit_size(do_hash(DigestType, <<>>)) + (SaltSize * 8) + 16)),
		{rsa_keypair(ModulusSize), ModulusSize, DigestType, binary(SaltSize), binary()}).

prop_rsassa_pss_sign_and_verify() ->
	?FORALL({{PrivateKey, PublicKey}, _, DigestType, Message},
		rsassa_pss_signer_gen(),
		begin
			{ok, Signature} = jose_jwa_pkcs1:rsassa_pss_sign(DigestType, Message, PrivateKey),
			jose_jwa_pkcs1:rsassa_pss_verify(DigestType, Message, Signature, PublicKey)
		end).

prop_rsassa_pss_sign_and_verify_with_salt() ->
	?FORALL({{PrivateKey, PublicKey}, _ModulusSize, DigestType, Salt, Message},
		rsassa_pss_signer_with_salt_gen(),
		begin
			{ok, Signature} = jose_jwa_pkcs1:rsassa_pss_sign(DigestType, Message, Salt, PrivateKey),
			jose_jwa_pkcs1:rsassa_pss_verify(DigestType, Message, Signature, byte_size(Salt), PublicKey)
		end).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

do_hash(DigestType, PlainText) when is_atom(DigestType) ->
	crypto:hash(DigestType, PlainText);
do_hash({hmac, DigestType, Key}, PlainText) ->
	crypto:hmac(DigestType, Key, PlainText).
