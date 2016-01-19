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
-callback decrypt_private(CipherText, Options, KTY) -> PlainText
	when
		CipherText :: iodata(),
		Options    :: any(),
		KTY        :: any(),
		PlainText  :: iodata().
-callback derive_key(KTY) -> DerivedKey
	when
		KTY        :: any(),
		DerivedKey :: iodata().
-callback derive_key(OtherKTY, KTY) -> DerivedKey
	when
		OtherKTY   :: any(),
		KTY        :: any(),
		DerivedKey :: iodata().
-callback encrypt_public(PlainText, Options, KTY) -> CipherText
	when
		PlainText  :: iodata(),
		Options    :: any(),
		KTY        :: any(),
		CipherText :: iodata().
-callback key_encryptor(KTY, Fields, Key) -> JWEMap
	when
		KTY    :: any(),
		Fields :: map(),
		Key    :: any(),
		JWEMap :: map().
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
-optional_callbacks([decrypt_private/3]).
-optional_callbacks([derive_key/1]).
-optional_callbacks([derive_key/2]).
-optional_callbacks([encrypt_public/3]).
-optional_callbacks([key_encryptor/3]).
-optional_callbacks([sign/3]).
-optional_callbacks([signer/3]).
-optional_callbacks([verify/4]).
-endif.

-callback generate_key(Parameters) -> KTY
	when
		Parameters :: any(),
		KTY        :: any().
-callback generate_key(KTY, Fields) -> NewKTY
	when
		KTY    :: any(),
		Fields :: map(),
		NewKTY :: any().

%% API
-export([from_key/1]).
-export([from_oct/1]).
-export([generate_key/1]).
-export([key_encryptor/3]).

-define(KTY_EC_MODULE,  jose_jwk_kty_ec).
-define(KTY_OCT_MODULE, jose_jwk_kty_oct).
-define(KTY_RSA_MODULE, jose_jwk_kty_rsa).

-define(KTY_OKP_Ed25519_MODULE,   jose_jwk_kty_okp_ed25519).
-define(KTY_OKP_Ed25519ph_MODULE, jose_jwk_kty_okp_ed25519ph).
-define(KTY_OKP_X25519_MODULE,    jose_jwk_kty_okp_x25519).
-define(KTY_OKP_Ed448_MODULE,     jose_jwk_kty_okp_ed448).
-define(KTY_OKP_Ed448ph_MODULE,   jose_jwk_kty_okp_ed448ph).
-define(KTY_OKP_X448_MODULE,      jose_jwk_kty_okp_x448).

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
from_key(#'PrivateKeyInfo'{privateKeyAlgorithm=#'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=?rsaEncryption}, privateKey=PrivateKey}) ->
	from_key(public_key:der_decode('RSAPrivateKey', PrivateKey));
from_key(#'PrivateKeyInfo'{privateKeyAlgorithm=#'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=?'id-ecPublicKey'}, privateKey=PrivateKey}) ->
	from_key(public_key:der_decode('ECPrivateKey', PrivateKey));
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
generate_key(P={okp, 'Ed25519'}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed25519_MODULE }, P});
generate_key(P={okp, 'Ed25519ph'}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed25519ph_MODULE }, P});
generate_key(P={okp, 'X25519'}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_X25519_MODULE }, P});
generate_key(P={okp, 'Ed25519', Seed}) when is_binary(Seed) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed25519_MODULE }, P});
generate_key(P={okp, 'Ed25519ph', Seed}) when is_binary(Seed) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed25519ph_MODULE }, P});
generate_key(P={okp, 'X25519', Seed}) when is_binary(Seed) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_X25519_MODULE }, P});
generate_key(P={okp, 'Ed448'}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed448_MODULE }, P});
generate_key(P={okp, 'Ed448ph'}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed448ph_MODULE }, P});
generate_key(P={okp, 'X448'}) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_X448_MODULE }, P});
generate_key(P={okp, 'Ed448', Seed}) when is_binary(Seed) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed448_MODULE }, P});
generate_key(P={okp, 'Ed448ph', Seed}) when is_binary(Seed) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_Ed448ph_MODULE }, P});
generate_key(P={okp, 'X448', Seed}) when is_binary(Seed) ->
	jose_jwk:generate_key({#{ kty => ?KTY_OKP_X448_MODULE }, P});
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
		<<"enc">> => case jose_jwa:is_block_cipher_supported({aes_gcm, 128}) of
			false -> <<"A128CBC-HS256">>;
			true  -> <<"A128GCM">>
		end,
		<<"p2c">> => 4096,
		<<"p2s">> => base64url:encode(crypto:rand_bytes(16))
	}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
