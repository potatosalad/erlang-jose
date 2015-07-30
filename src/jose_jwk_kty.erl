%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  24 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_kty).

-include_lib("public_key/include/public_key.hrl").

-callback block_encryptor(KTY, Fields, PlainText) -> JWEMap
	when
		KTY       :: any(),
		Fields    :: map(),
		PlainText :: iodata(),
		JWEMap    :: map().
-callback derive_key(KTY) -> DerivedKey
	when
		KTY        :: any(),
		DerivedKey :: iodata().
-callback derive_key(OtherKTY, KTY) -> DerivedKey
	when
		OtherKTY   :: any(),
		KTY        :: any(),
		DerivedKey :: iodata().
-callback key_encryptor(KTY, Fields, Key) -> JWEMap
	when
		KTY    :: any(),
		Fields :: map(),
		Key    :: any(),
		JWEMap :: map().
-callback private_decrypt(CipherText, Options, KTY) -> PlainText
	when
		CipherText :: iodata(),
		Options    :: any(),
		KTY        :: any(),
		PlainText  :: iodata().
-callback public_encrypt(PlainText, Options, KTY) -> CipherText
	when
		PlainText  :: iodata(),
		Options    :: any(),
		KTY        :: any(),
		CipherText :: iodata().
-callback sign(Message, Options, KTY) -> Signature
	when
		Message   :: iodata(),
		Options   :: any(),
		KTY       :: any(),
		Signature :: iodata().
-callback signer(KTY, Fields, Message) -> JWSMap
	when
		KTY     :: any(),
		Fields  :: map(),
		Message :: any(),
		JWSMap  :: map().
-callback verify(Message, Options, Signature, KTY) -> boolean()
	when
		Message   :: iodata(),
		Options   :: any(),
		Signature :: iodata(),
		KTY       :: any().

-optional_callbacks([block_encryptor/3]).
-optional_callbacks([derive_key/1]).
-optional_callbacks([derive_key/2]).
-optional_callbacks([key_encryptor/3]).
-optional_callbacks([private_decrypt/3]).
-optional_callbacks([public_encrypt/3]).
-optional_callbacks([sign/3]).
-optional_callbacks([signer/3]).
-optional_callbacks([verify/4]).

%% API
-export([from_key/1]).
-export([key_encryptor/3]).

-define(KTY_EC_MODULE,  jose_jwk_kty_ec).
-define(KTY_RSA_MODULE, jose_jwk_kty_rsa).

%%====================================================================
%% API functions
%%====================================================================

from_key(ECPrivateKey=#'ECPrivateKey'{}) ->
	{?KTY_EC_MODULE, ?KTY_EC_MODULE:from_key(ECPrivateKey)};
from_key(ECPublicKey={#'ECPoint'{}, _}) ->
	{?KTY_EC_MODULE, ?KTY_EC_MODULE:from_key(ECPublicKey)};
from_key(RSAPrivateKey=#'RSAPrivateKey'{}) ->
	{?KTY_RSA_MODULE, ?KTY_RSA_MODULE:from_key(RSAPrivateKey)};
from_key(RSAPublicKey=#'RSAPublicKey'{}) ->
	{?KTY_RSA_MODULE, ?KTY_RSA_MODULE:from_key(RSAPublicKey)};
from_key(UnknownKey) ->
	{error, {unknown_key, UnknownKey}}.

key_encryptor(_KTY, _Fields, Key) when is_binary(Key) ->
	#{
		<<"alg">> => <<"PBES2-HS256+A128KW">>,
		<<"cty">> => <<"jwk+json">>,
		<<"enc">> => <<"A128CBC-HS256">>,
		<<"p2c">> => 4096,
		<<"p2s">> => base64url:encode(crypto:rand_bytes(16))
	}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
