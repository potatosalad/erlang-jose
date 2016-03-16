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
-export([generate_key/3]).
-export([key_decrypt/3]).
-export([key_encrypt/3]).
-export([next_cek/3]).
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

generate_key(_Fields, {ENCModule, ENC}, ALG=#jose_jwe_alg_ecdh_es{epk=EphemeralPublicJWK=#jose_jwk{}}) ->
	jose_jwe_alg:generate_key(EphemeralPublicJWK, maps:get(<<"alg">>, to_map(ALG, #{})), ENCModule:algorithm(ENC));
generate_key(_Fields, {ENCModule, ENC}, ALG=#jose_jwe_alg_ecdh_es{}) ->
	jose_jwe_alg:generate_key({ec, <<"P-521">>}, maps:get(<<"alg">>, to_map(ALG, #{})), ENCModule:algorithm(ENC)).

key_decrypt({OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}}, EncryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{epk=EphemeralPublicJWK=#jose_jwk{}}) ->
	case jose_jwk:thumbprint(OtherPublicJWK) =:= jose_jwk:thumbprint(EphemeralPublicJWK) of
		true ->
			key_decrypt(MyPrivateJWK, EncryptedKey, JWEECDHES);
		false ->
			error
	end;
key_decrypt(MyPrivateJWK=#jose_jwk{}, EncryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{epk=EphemeralPublicJWK=#jose_jwk{}}) ->
	DerivedKey = jose_jwk:shared_secret(EphemeralPublicJWK, MyPrivateJWK),
	key_decrypt(DerivedKey, EncryptedKey, JWEECDHES);
% key_decrypt({OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}}, EncryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{epk=undefined}) ->
% 	DerivedKey = jose_jwk:shared_secret(OtherPublicJWK, MyPrivateJWK),
% 	key_decrypt(DerivedKey, EncryptedKey, JWEECDHES);
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
key_encrypt({OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}}, DecryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{epk=EphemeralPublicJWK=#jose_jwk{}}) ->
	case jose_jwk:thumbprint(MyPrivateJWK) =:= jose_jwk:thumbprint(EphemeralPublicJWK) of
		true ->
			DerivedKey = jose_jwk:shared_secret(OtherPublicJWK, MyPrivateJWK),
			key_encrypt(DerivedKey, DecryptedKey, JWEECDHES);
		false ->
			error
	end;
key_encrypt({OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}}, DecryptedKey, JWEECDHES0=#jose_jwe_alg_ecdh_es{epk=undefined}) ->
	JWEECDHES1 = JWEECDHES0#jose_jwe_alg_ecdh_es{epk=jose_jwk:to_public(MyPrivateJWK)},
	key_encrypt({OtherPublicJWK, MyPrivateJWK}, DecryptedKey, JWEECDHES1);
key_encrypt(#jose_jwk{kty={KTYModule, KTY}}, DecryptedKey, JWEECDHES) ->
	DerivedKey = KTYModule:derive_key(KTY),
	key_encrypt(DerivedKey, DecryptedKey, JWEECDHES);
key_encrypt(Z, DecryptedKey, JWEECDHES=#jose_jwe_alg_ecdh_es{apu=APU, apv=APV, bits=KeyDataLen}) when is_binary(Z) ->
	Algorithm = algorithm(JWEECDHES),
	SuppPubInfo = << KeyDataLen:1/unsigned-big-integer-unit:32 >>,
	DerivedKey = jose_jwa_concat_kdf:kdf(sha256, Z, {Algorithm, APU, APV, SuppPubInfo}, KeyDataLen),
	{jose_jwa_aes_kw:wrap(DecryptedKey, DerivedKey), JWEECDHES}.

next_cek({OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}}, {ENCModule, ENC}, JWEECDHES=#jose_jwe_alg_ecdh_es{bits=undefined, epk=EphemeralPublicJWK=#jose_jwk{}}) ->
	case jose_jwk:thumbprint(MyPrivateJWK) =:= jose_jwk:thumbprint(EphemeralPublicJWK) of
		true ->
			DerivedKey = jose_jwk:shared_secret(OtherPublicJWK, MyPrivateJWK),
			next_cek(DerivedKey, {ENCModule, ENC}, JWEECDHES);
		false ->
			error
	end;
next_cek({OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}}, {ENCModule, ENC}, JWEECDHES0=#jose_jwe_alg_ecdh_es{bits=undefined, epk=undefined}) ->
	JWEECDHES1 = JWEECDHES0#jose_jwe_alg_ecdh_es{epk=jose_jwk:to_public(MyPrivateJWK)},
	next_cek({OtherPublicJWK, MyPrivateJWK}, {ENCModule, ENC}, JWEECDHES1);
next_cek(#jose_jwk{kty={KTYModule, KTY}}, {ENC, ENCModule}, JWEECDHES=#jose_jwe_alg_ecdh_es{bits=undefined}) ->
	DerivedKey = KTYModule:derive_key(KTY),
	next_cek(DerivedKey, {ENCModule, ENC}, JWEECDHES);
next_cek(Z, {ENCModule, ENC}, JWEECDHES=#jose_jwe_alg_ecdh_es{apu=APU, apv=APV, bits=undefined}) when is_binary(Z) ->
	Algorithm = ENCModule:algorithm(ENC),
	KeyDataLen = ENCModule:bits(ENC),
	SuppPubInfo = << KeyDataLen:1/unsigned-big-integer-unit:32 >>,
	DerivedKey = jose_jwa_concat_kdf:kdf(sha256, Z, {Algorithm, APU, APV, SuppPubInfo}, KeyDataLen),
	{DerivedKey, JWEECDHES};
next_cek(_Key, {ENCModule, ENC}, JWEECDHES=#jose_jwe_alg_ecdh_es{}) ->
	{ENCModule:next_cek(ENC), JWEECDHES}.

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
	from_map_ecdh_es(maps:remove(<<"epk">>, F), H#jose_jwe_alg_ecdh_es{ epk = jose_jwk:from_map(EPK) });
from_map_ecdh_es(F = #{ <<"apu">> := APU }, H) ->
	from_map_ecdh_es(maps:remove(<<"apu">>, F), H#jose_jwe_alg_ecdh_es{ apu = base64url:decode(APU) });
from_map_ecdh_es(F = #{ <<"apv">> := APV }, H) ->
	from_map_ecdh_es(maps:remove(<<"apv">>, F), H#jose_jwe_alg_ecdh_es{ apv = base64url:decode(APV) });
from_map_ecdh_es(F, H) ->
	{H, F}.

%% @private
to_map_ecdh_es(F, H=#jose_jwe_alg_ecdh_es{ epk = EPK = #jose_jwk{} }) ->
	to_map_ecdh_es(F#{ <<"epk">> => element(2, jose_jwk:to_public_map(EPK)) }, H#jose_jwe_alg_ecdh_es{ epk = undefined });
to_map_ecdh_es(F, H=#jose_jwe_alg_ecdh_es{ apu = APU }) when is_binary(APU) ->
	to_map_ecdh_es(F#{ <<"apu">> => base64url:encode(APU) }, H#jose_jwe_alg_ecdh_es{ apu = undefined });
to_map_ecdh_es(F, H=#jose_jwe_alg_ecdh_es{ apv = APV }) when is_binary(APV) ->
	to_map_ecdh_es(F#{ <<"apv">> => base64url:encode(APV) }, H#jose_jwe_alg_ecdh_es{ apv = undefined });
to_map_ecdh_es(F, _) ->
	F.
