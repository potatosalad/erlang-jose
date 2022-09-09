%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_rsa_crypto).

-include("jose_rsa.hrl").
-include_lib("public_key/include/public_key.hrl").

-behaviour(jose_provider).
-behaviour(jose_rsa).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_rsa callbacks
-export([
	rsa_keypair/0,
	rsa_keypair/1,
	rsa_keypair/2,
	rsa_private_to_public/1,
	rsaes_pkcs1_v1_5_private_decrypt/2,
	rsaes_pkcs1_v1_5_public_encrypt/2,
	rsaes_oaep_private_decrypt/2,
	rsaes_oaep_public_encrypt/2,
	rsaes_oaep_sha256_mgf1_sha256_private_decrypt/2,
	rsaes_oaep_sha256_mgf1_sha256_public_encrypt/2,
	rsaes_oaep_sha384_mgf1_sha384_private_decrypt/2,
	rsaes_oaep_sha384_mgf1_sha384_public_encrypt/2,
	rsaes_oaep_sha512_mgf1_sha512_private_decrypt/2,
	rsaes_oaep_sha512_mgf1_sha512_public_encrypt/2,
	rsassa_pkcs1_v1_5_sha1_sign/2,
	rsassa_pkcs1_v1_5_sha1_verify/3,
	rsassa_pkcs1_v1_5_sha256_sign/2,
	rsassa_pkcs1_v1_5_sha256_verify/3,
	rsassa_pkcs1_v1_5_sha384_sign/2,
	rsassa_pkcs1_v1_5_sha384_verify/3,
	rsassa_pkcs1_v1_5_sha512_sign/2,
	rsassa_pkcs1_v1_5_sha512_verify/3,
	rsassa_pss_sha256_mgf1_sha256_sign/2,
	rsassa_pss_sha256_mgf1_sha256_verify/3,
	rsassa_pss_sha384_mgf1_sha384_sign/2,
	rsassa_pss_sha384_mgf1_sha384_verify/3,
	rsassa_pss_sha512_mgf1_sha512_sign/2,
	rsassa_pss_sha512_mgf1_sha512_verify/3
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_rsa,
		priority => high,
		requirements => [
			{app, crypto},
			crypto
		]
	}.

%%====================================================================
%% jose_rsa callbacks
%%====================================================================

-spec rsa_keypair() -> {PublicKey, PrivateKey} when
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
rsa_keypair() ->
	rsa_keypair(2048).

-spec rsa_keypair(ModulusSize) -> {PublicKey, PrivateKey} when
	ModulusSize :: jose_rsa:rsa_modulus_size(),
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
rsa_keypair(ModulusSize)
		when (is_integer(ModulusSize) andalso ModulusSize >= 1) ->
	rsa_keypair(ModulusSize, binary:encode_unsigned(65537, big)).

-spec rsa_keypair(ModulusSize, PublicExponent) -> {PublicKey, PrivateKey} when
	ModulusSize :: jose_rsa:rsa_modulus_size(),
	PublicExponent :: jose_rsa:rsa_public_exponent(),
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
rsa_keypair(ModulusSize, PublicExponent)
		when (is_integer(ModulusSize) andalso ModulusSize >= 1)
		andalso (is_binary(PublicExponent) andalso byte_size(PublicExponent) >= 1) ->
	{CryptoPK, CryptoSK} = crypto:generate_key(rsa, {ModulusSize, PublicExponent}),
	PK = public_key_crypto_to_record(CryptoPK),
	SK = private_key_crypto_to_record(CryptoSK),
	{PK, SK}.

-spec rsa_private_to_public(PrivateKey) -> PublicKey when
	PrivateKey :: jose_rsa:rsa_private_key(),
	PublicKey :: jose_rsa:rsa_public_key().
rsa_private_to_public(_PrivateKey = #jose_rsa_private_key{e = PublicExponent, n = Modulus}) ->
	#jose_rsa_public_key{e = PublicExponent, n = Modulus}.

-spec rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	try crypto:private_decrypt(rsa, CipherText, CryptoSK, Options) of
		PlainText when is_binary(PlainText) ->
			PlainText
	catch
		error:{error, {"pkey.c", _}, "Couldn't get the result"} ->
			error
	end.

-spec rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:public_encrypt(rsa, PlainText, CryptoPK, Options).

-spec rsaes_oaep_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha}
	],
	try crypto:private_decrypt(rsa, CipherText, CryptoSK, Options) of
		PlainText when is_binary(PlainText) ->
			PlainText
	catch
		error:{error, {"pkey.c", _}, "Couldn't get the result"} ->
			error
	end.

-spec rsaes_oaep_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha}
	],
	crypto:public_encrypt(rsa, PlainText, CryptoPK, Options).

-spec rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha256},
		{rsa_mgf1_md, sha256}
	],
	try crypto:private_decrypt(rsa, CipherText, CryptoSK, Options) of
		PlainText when is_binary(PlainText) ->
			PlainText
	catch
		error:{error, {"pkey.c", _}, "Couldn't get the result"} ->
			error
	end.

-spec rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha256},
		{rsa_mgf1_md, sha256}
	],
	crypto:public_encrypt(rsa, PlainText, CryptoPK, Options).

-spec rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha384},
		{rsa_mgf1_md, sha384}
	],
	try crypto:private_decrypt(rsa, CipherText, CryptoSK, Options) of
		PlainText when is_binary(PlainText) ->
			PlainText
	catch
		error:{error, {"pkey.c", _}, "Couldn't get the result"} ->
			error
	end.

-spec rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha384},
		{rsa_mgf1_md, sha384}
	],
	crypto:public_encrypt(rsa, PlainText, CryptoPK, Options).

-spec rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha512},
		{rsa_mgf1_md, sha512}
	],
	try crypto:private_decrypt(rsa, CipherText, CryptoSK, Options) of
		PlainText when is_binary(PlainText) ->
			PlainText
	catch
		error:{error, {"pkey.c", _}, "Couldn't get the result"} ->
			error
	end.

-spec rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_oaep_padding},
		{rsa_oaep_label, <<>>},
		{rsa_oaep_md, sha512},
		{rsa_mgf1_md, sha512}
	],
	crypto:public_encrypt(rsa, PlainText, CryptoPK, Options).

-spec rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha1_signature().
rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:sign(rsa, sha, Message, CryptoSK, Options).

-spec rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha1_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:verify(rsa, sha, Message, Signature, CryptoPK, Options).

-spec rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha256_signature().
rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:sign(rsa, sha256, Message, CryptoSK, Options).

-spec rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha256_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:verify(rsa, sha256, Message, Signature, CryptoPK, Options).

-spec rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha384_signature().
rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:sign(rsa, sha384, Message, CryptoSK, Options).

-spec rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha384_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:verify(rsa, sha384, Message, Signature, CryptoPK, Options).

-spec rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha512_signature().
rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:sign(rsa, sha512, Message, CryptoSK, Options).

-spec rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha512_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_padding, rsa_pkcs1_padding}
	],
	crypto:verify(rsa, sha512, Message, Signature, CryptoPK, Options).

-spec rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature().
rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_mgf1_md, sha256},
		{rsa_padding, rsa_pkcs1_pss_padding},
		{rsa_pss_saltlen, -1}
	],
	crypto:sign(rsa, sha256, Message, CryptoSK, Options).

-spec rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_mgf1_md, sha256},
		{rsa_padding, rsa_pkcs1_pss_padding},
		{rsa_pss_saltlen, -1}
	],
	crypto:verify(rsa, sha256, Message, Signature, CryptoPK, Options).

-spec rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature().
rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_mgf1_md, sha384},
		{rsa_padding, rsa_pkcs1_pss_padding},
		{rsa_pss_saltlen, -1}
	],
	crypto:sign(rsa, sha384, Message, CryptoSK, Options).

-spec rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_mgf1_md, sha384},
		{rsa_padding, rsa_pkcs1_pss_padding},
		{rsa_pss_saltlen, -1}
	],
	crypto:verify(rsa, sha384, Message, Signature, CryptoPK, Options).

-spec rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature().
rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	CryptoSK = private_key_record_to_crypto(PrivateKey),
	Options = [
		{rsa_mgf1_md, sha512},
		{rsa_padding, rsa_pkcs1_pss_padding},
		{rsa_pss_saltlen, -1}
	],
	crypto:sign(rsa, sha512, Message, CryptoSK, Options).

-spec rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	CryptoPK = public_key_record_to_crypto(PublicKey),
	Options = [
		{rsa_mgf1_md, sha512},
		{rsa_padding, rsa_pkcs1_pss_padding},
		{rsa_pss_saltlen, -1}
	],
	crypto:verify(rsa, sha512, Message, Signature, CryptoPK, Options).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
private_key_crypto_to_record([E, N, D])
		when ?is_rsa_key_integer(E)
		andalso ?is_rsa_key_integer(N)
		andalso ?is_rsa_key_integer(D) ->
	#jose_rsa_private_key{
		e = E,
		n = N,
		d = D
	};
private_key_crypto_to_record([E, N, D, P1, P2, E1, E2, C])
		when ?is_rsa_key_integer(E)
		andalso ?is_rsa_key_integer(N)
		andalso ?is_rsa_key_integer(D)
		andalso ?is_rsa_key_integer(P1)
		andalso ?is_rsa_key_integer(P2)
		andalso ?is_rsa_key_integer(E1)
		andalso ?is_rsa_key_integer(E2)
		andalso ?is_rsa_key_integer(C) ->
	#jose_rsa_private_key{
		e = E,
		n = N,
		d = D,
		p = P1,
		q = P2,
		dp = E1,
		dq = E2,
		qi = C
	}.

%% @private
private_key_record_to_crypto(#jose_rsa_private_key{
		e = E,
		n = N,
		d = D,
		p = P1,
		q = P2,
		dp = E1,
		dq = E2,
		qi = C
	})
		when ?is_rsa_key_integer(E)
		andalso ?is_rsa_key_integer(N)
		andalso ?is_rsa_key_integer(D)
		andalso ?is_rsa_key_integer(P1)
		andalso ?is_rsa_key_integer(P2)
		andalso ?is_rsa_key_integer(E1)
		andalso ?is_rsa_key_integer(E2)
		andalso ?is_rsa_key_integer(C) ->
	[E, N, D, P1, P2, E1, E2, C];
private_key_record_to_crypto(#jose_rsa_private_key{
		e = E,
		n = N,
		d = D
	})
		when ?is_rsa_key_integer(E)
		andalso ?is_rsa_key_integer(N)
		andalso ?is_rsa_key_integer(D) ->
	[E, N, D].

%% @private
public_key_crypto_to_record([E, N])
		when ?is_rsa_key_integer(E)
		andalso ?is_rsa_key_integer(N) ->
	#jose_rsa_public_key{
		e = E,
		n = N
	}.

%% @private
public_key_record_to_crypto(#jose_rsa_public_key{
		e = E,
		n = N
	})
		when ?is_rsa_key_integer(E)
		andalso ?is_rsa_key_integer(N) ->
	[E, N].
