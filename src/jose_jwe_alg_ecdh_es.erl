%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  23 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwe_alg_ecdh_es).
-behaviour(jose_jwe).
-behaviour(jose_jwe_alg).

-include_lib("public_key/include/public_key.hrl").

-include("jose_jwk.hrl").

%% jose_jwe callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jwe_alg callbacks
-export([key_decrypt/3]).
-export([key_encrypt/3]).
-export([next_cek/4]).
%% API
-export([algorithm/1]).

%% Types
-type ec_public_key() :: {#'ECPoint'{},{namedCurve, Oid::tuple()} | #'ECParameters'{}}.

-record(jose_jwe_alg_ecdh_es, {
	epk  = undefined :: undefined | {ec_public_key(), map()},
	apu  = undefined :: undefined | binary(),
	apv  = undefined :: undefined | binary(),
	bits = undefined :: undefined | 128 | 192 | 256
}).

-type alg() :: #jose_jwe_alg_ecdh_es{}.

-export_type([alg/0]).

-define(ECDH_ES,        #jose_jwe_alg_ecdh_es{}).
-define(ECDH_ES_A128KW, #jose_jwe_alg_ecdh_es{bits=128}).
-define(ECDH_ES_A192KW, #jose_jwe_alg_ecdh_es{bits=192}).
-define(ECDH_ES_A256KW, #jose_jwe_alg_ecdh_es{bits=256}).

%%====================================================================
%% jose_jwe callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"ECDH-ES">> }) ->
	from_map_ecdh_es(maps:remove(<<"alg">>, F), ?ECDH_ES);
from_map(F = #{ <<"alg">> := <<"ECDH-ES+A128KW">> }) ->
	from_map_ecdh_es(maps:remove(<<"alg">>, F), ?ECDH_ES_A128KW);
from_map(F = #{ <<"alg">> := <<"ECDH-ES+A192KW">> }) ->
	from_map_ecdh_es(maps:remove(<<"alg">>, F), ?ECDH_ES_A192KW);
from_map(F = #{ <<"alg">> := <<"ECDH-ES+A256KW">> }) ->
	from_map_ecdh_es(maps:remove(<<"alg">>, F), ?ECDH_ES_A256KW).

to_map(A = ?ECDH_ES_A128KW, F) ->
	to_map_ecdh_es(F#{ <<"alg">> => <<"ECDH-ES+A128KW">> }, A);
to_map(A = ?ECDH_ES_A192KW, F) ->
	to_map_ecdh_es(F#{ <<"alg">> => <<"ECDH-ES+A192KW">> }, A);
to_map(A = ?ECDH_ES_A256KW, F) ->
	to_map_ecdh_es(F#{ <<"alg">> => <<"ECDH-ES+A256KW">> }, A);
to_map(A = ?ECDH_ES, F) ->
	to_map_ecdh_es(F#{ <<"alg">> => <<"ECDH-ES">> }, A).

%%====================================================================
%% jose_jwe_alg callbacks
%%====================================================================

key_decrypt({#jose_jwk{kty={OtherPublicKTYModule, OtherPublicKTY}}, MyPrivateJWK}, EncryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{epk={EphemeralPublicKey, _}}) ->
	case OtherPublicKTYModule:to_key(OtherPublicKTY) of
		EphemeralPublicKey ->
			key_decrypt(MyPrivateJWK, EncryptedKey, JWEECDHES);
		_ ->
			error
	end;
key_decrypt(#jose_jwk{kty={MyPrivateKTYModule, MyPrivateKTY}}, EncryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{epk={EphemeralPublicKey, _}}) ->
	_ = code:ensure_loaded(MyPrivateKTYModule),
	DerivedKey = case erlang:function_exported(MyPrivateKTYModule, derive_key, 2) of
		false ->
			MyPrivateKTYModule:derive_key(EphemeralPublicKey);
		true ->
			MyPrivateKTYModule:derive_key(EphemeralPublicKey, MyPrivateKTY)
	end,
	key_decrypt(DerivedKey, EncryptedKey, JWEECDHES);
key_decrypt(Z, {ENCModule, ENC, <<>>}, #jose_jwe_alg_ecdh_es{apu=APU, apv=APV, bits=undefined}) when is_binary(Z) ->
	Algorithm = ENCModule:algorithm(ENC),
	KeyDataLen = ENCModule:bits(ENC),
	SuppPubInfo = << KeyDataLen:1/unsigned-big-integer-unit:32 >>,
	DerivedKey = jose_jwa_concat_kdf:kdf(sha256, Z, {Algorithm, APU, APV, SuppPubInfo}, KeyDataLen),
	DerivedKey;
key_decrypt(Z, {_ENCModule, _ENC, EncryptedKey}, JWEECDHES=#jose_jwe_alg_ecdh_es{apu=APU, apv=APV, bits=KeyDataLen}) when is_binary(Z) ->
	Algorithm = algorithm(JWEECDHES),
	SuppPubInfo = << KeyDataLen:1/unsigned-big-integer-unit:32 >>,
	DerivedKey = jose_jwa_concat_kdf:kdf(sha256, Z, {Algorithm, APU, APV, SuppPubInfo}, KeyDataLen),
	jose_jwa_aes_kw:unwrap(EncryptedKey, DerivedKey).

key_encrypt(_Key, _DecryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{bits=undefined}) ->
	{<<>>, JWEECDHES};
key_encrypt({#jose_jwk{kty={OtherPublicKTYModule, OtherPublicKTY}}, #jose_jwk{kty={_, MyPrivateKTY}}}, DecryptedKey, JWEECDHES) ->
	_ = code:ensure_loaded(OtherPublicKTYModule),
	DerivedKey = case erlang:function_exported(OtherPublicKTYModule, derive_key, 2) of
		false ->
			OtherPublicKTYModule:derive_key(OtherPublicKTY);
		true ->
			OtherPublicKTYModule:derive_key(OtherPublicKTY, MyPrivateKTY)
	end,
	key_encrypt(DerivedKey, DecryptedKey, JWEECDHES);
key_encrypt(#jose_jwk{kty={KTYModule, KTY}}, DecryptedKey, JWEECDHES) ->
	DerivedKey = KTYModule:derive_key(KTY),
	key_encrypt(DerivedKey, DecryptedKey, JWEECDHES);
key_encrypt(Z, DecryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{apu=APU, apv=APV, bits=KeyDataLen}) when is_binary(Z) ->
	Algorithm = algorithm(JWEECDHES),
	SuppPubInfo = << KeyDataLen:1/unsigned-big-integer-unit:32 >>,
	DerivedKey = jose_jwa_concat_kdf:kdf(sha256, Z, {Algorithm, APU, APV, SuppPubInfo}, KeyDataLen),
	{jose_jwa_aes_kw:wrap(DecryptedKey, DerivedKey), JWEECDHES}.

next_cek({#jose_jwk{kty={OtherPublicKTYModule, OtherPublicKTY}}, #jose_jwk{kty={_, MyPrivateKTY}}}, ENCModule, ENC, JWEECDHES=#jose_jwe_alg_ecdh_es{bits=undefined}) ->
	_ = code:ensure_loaded(OtherPublicKTYModule),
	DerivedKey = case erlang:function_exported(OtherPublicKTYModule, derive_key, 2) of
		false ->
			OtherPublicKTYModule:derive_key(OtherPublicKTY);
		true ->
			OtherPublicKTYModule:derive_key(OtherPublicKTY, MyPrivateKTY)
	end,
	next_cek(DerivedKey, ENCModule, ENC, JWEECDHES);
next_cek(#jose_jwk{kty={KTYModule, KTY}}, ENC, ENCModule, JWEECDHES=#jose_jwe_alg_ecdh_es{bits=undefined}) ->
	DerivedKey = KTYModule:derive_key(KTY),
	next_cek(DerivedKey, ENCModule, ENC, JWEECDHES);
next_cek(Z, ENCModule, ENC, #jose_jwe_alg_ecdh_es{apu=APU, apv=APV, bits=undefined}) when is_binary(Z) ->
	Algorithm = ENCModule:algorithm(ENC),
	KeyDataLen = ENCModule:bits(ENC),
	SuppPubInfo = << KeyDataLen:1/unsigned-big-integer-unit:32 >>,
	DerivedKey = jose_jwa_concat_kdf:kdf(sha256, Z, {Algorithm, APU, APV, SuppPubInfo}, KeyDataLen),
	DerivedKey;
next_cek(_Key, ENCModule, ENC, #jose_jwe_alg_ecdh_es{}) ->
	ENCModule:next_cek(ENC).

%%====================================================================
%% API functions
%%====================================================================

algorithm(?ECDH_ES_A128KW) -> <<"ECDH-ES+A128KW">>;
algorithm(?ECDH_ES_A192KW) -> <<"ECDH-ES+A192KW">>;
algorithm(?ECDH_ES_A256KW) -> <<"ECDH-ES+A256KW">>;
algorithm(?ECDH_ES)        -> <<"ECDH-ES">>.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
from_map_ecdh_es(F = #{ <<"epk">> := EPK }, H) ->
	from_map_ecdh_es(maps:remove(<<"epk">>, F), H#jose_jwe_alg_ecdh_es{ epk = jose_jwk_kty_ec:from_map(EPK) });
from_map_ecdh_es(F = #{ <<"apu">> := APU }, H) ->
	from_map_ecdh_es(maps:remove(<<"apu">>, F), H#jose_jwe_alg_ecdh_es{ apu = base64url:decode(APU) });
from_map_ecdh_es(F = #{ <<"apv">> := APV }, H) ->
	from_map_ecdh_es(maps:remove(<<"apv">>, F), H#jose_jwe_alg_ecdh_es{ apv = base64url:decode(APV) });
from_map_ecdh_es(F, H) ->
	{H, F}.

%% @private
to_map_ecdh_es(F, #jose_jwe_alg_ecdh_es{ epk = {EPK, EPKFields}, apu = APU, apv = APV }) ->
	F#{
		<<"epk">> => jose_jwk_kty_ec:to_map(EPK, EPKFields),
		<<"apu">> => base64url:encode(APU),
		<<"apv">> => base64url:encode(APV)
	}.
