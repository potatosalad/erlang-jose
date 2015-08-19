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

-ifdef(optional_callbacks).
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
-callback generate_key(Parameters) -> KTY
	when
		Parameters :: any(),
		KTY        :: any().
-callback generate_key(KTY, Fields) -> NewKTY
	when
		KTY    :: any(),
		Fields :: map(),
		NewKTY :: any().
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
-optional_callbacks([generate_key/1]).
-optional_callbacks([generate_key/2]).
-optional_callbacks([key_encryptor/3]).
-optional_callbacks([private_decrypt/3]).
-optional_callbacks([public_encrypt/3]).
-optional_callbacks([sign/3]).
-optional_callbacks([signer/3]).
-optional_callbacks([verify/4]).
-else.
-callback sign(Message, Options, KTY) -> Signature
	when
		Message   :: iodata(),
		Options   :: any(),
		KTY       :: any(),
		Signature :: iodata().
-endif.

%% API
-export([from_key/1]).
-export([from_oct/1]).
-export([generate_key/1]).
-export([key_encryptor/3]).

-define(KTY_EC_MODULE,  jose_jwk_kty_ec).
-define(KTY_OCT_MODULE, jose_jwk_kty_oct).
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

from_oct(OCTBinary) when is_binary(OCTBinary) ->
	{?KTY_OCT_MODULE, ?KTY_OCT_MODULE:from_oct(OCTBinary)};
from_oct(UnknownKey) ->
	{error, {unknown_key, UnknownKey}}.

generate_key(P=#'ECParameters'{}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P=#'ECPrivateKey'{}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={#'ECPoint'{}, _}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={namedCurve, _}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P) when is_atom(P) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P=#'RSAPrivateKey'{}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_RSA_MODULE }, P});
generate_key(P=#'RSAPublicKey'{}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_RSA_MODULE }, P});
generate_key(P) when is_integer(P) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OCT_MODULE }, P});
generate_key(P={ec, #'ECParameters'{}}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={ec, #'ECPrivateKey'{}}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={ec, {#'ECPoint'{}, _}}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={ec, {namedCurve, _}}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={ec, Atom}) when is_atom(Atom) ->
	jose_jwk:generate_key({#{ kty => ?KTY_EC_MODULE }, P});
generate_key(P={oct, Size}) when is_integer(Size) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OCT_MODULE }, P});
generate_key(P={rsa, ModulusSize}) when is_integer(ModulusSize) ->
	jose_jwk:generate_key({#{ kty => ?KTY_RSA_MODULE }, P});
generate_key(P={rsa, ModulusSize, ExponentSize})
		when is_integer(ModulusSize)
		andalso is_integer(ExponentSize) ->
	jose_jwk:generate_key({#{ kty => ?KTY_RSA_MODULE }, P}).

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
