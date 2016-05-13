%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwe_alg_pbes2).
-behaviour(jose_jwe).
-behaviour(jose_jwe_alg).

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
-export([hmac_supported/0]).
-export([wrap_supported/0]).

%% Types
-record(jose_jwe_alg_pbes2, {
	hmac = undefined :: undefined | sha256 | sha384 | sha512,
	bits = undefined :: undefined | 128 | 192 | 256,
	salt = undefined :: undefined | binary(),
	iter = undefined :: undefined | pos_integer()
}).

-type alg() :: #jose_jwe_alg_pbes2{}.

-export_type([alg/0]).

-define(PBES2_HS256_A128KW, #jose_jwe_alg_pbes2{hmac=sha256, bits=128}).
-define(PBES2_HS384_A192KW, #jose_jwe_alg_pbes2{hmac=sha384, bits=192}).
-define(PBES2_HS512_A256KW, #jose_jwe_alg_pbes2{hmac=sha512, bits=256}).

%%====================================================================
%% jose_jwe callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"PBES2-HS256+A128KW">> }) ->
	from_map_pbes2(maps:remove(<<"alg">>, F), ?PBES2_HS256_A128KW);
from_map(F = #{ <<"alg">> := <<"PBES2-HS384+A192KW">> }) ->
	from_map_pbes2(maps:remove(<<"alg">>, F), ?PBES2_HS384_A192KW);
from_map(F = #{ <<"alg">> := <<"PBES2-HS512+A256KW">> }) ->
	from_map_pbes2(maps:remove(<<"alg">>, F), ?PBES2_HS512_A256KW).

to_map(A = ?PBES2_HS256_A128KW, F) ->
	to_map_pbes2(F#{ <<"alg">> => <<"PBES2-HS256+A128KW">> }, A);
to_map(A = ?PBES2_HS384_A192KW, F) ->
	to_map_pbes2(F#{ <<"alg">> => <<"PBES2-HS384+A192KW">> }, A);
to_map(A = ?PBES2_HS512_A256KW, F) ->
	to_map_pbes2(F#{ <<"alg">> => <<"PBES2-HS512+A256KW">> }, A).

%%====================================================================
%% jose_jwe_alg callbacks
%%====================================================================

generate_key(_Fields, {ENCModule, ENC}, ALG=#jose_jwe_alg_pbes2{}) ->
	jose_jwe_alg:generate_key({oct, 16}, maps:get(<<"alg">>, to_map(ALG, #{})), ENCModule:algorithm(ENC)).

key_decrypt(Password, {_ENCModule, _ENC, EncryptedKey}, #jose_jwe_alg_pbes2{hmac=HMAC, bits=Bits, salt=Salt, iter=Iterations}) when is_binary(Password) ->
	{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf2({hmac, HMAC}, Password, Salt, Iterations, (Bits div 8) + (Bits rem 8)),
	jose_jwa_aes_kw:unwrap(EncryptedKey, DerivedKey);
key_decrypt(#jose_jwk{kty={KTYModule, KTY}}, EncryptedKey, JWEPBES2=#jose_jwe_alg_pbes2{}) ->
	key_decrypt(KTYModule:derive_key(KTY), EncryptedKey, JWEPBES2).

key_encrypt(Password, DecryptedKey, ALG0=#jose_jwe_alg_pbes2{bits=Bits, salt=undefined}) ->
	ALG1 = ALG0#jose_jwe_alg_pbes2{salt=wrap_salt(crypto:strong_rand_bytes(Bits div 8), ALG0)},
	key_encrypt(Password, DecryptedKey, ALG1);
key_encrypt(Password, DecryptedKey, ALG0=#jose_jwe_alg_pbes2{bits=Bits, iter=undefined}) ->
	ALG1 = ALG0#jose_jwe_alg_pbes2{iter=(Bits * 32)},
	key_encrypt(Password, DecryptedKey, ALG1);
key_encrypt(Password, DecryptedKey, JWEPBES2=#jose_jwe_alg_pbes2{hmac=HMAC, bits=Bits, salt=Salt, iter=Iterations})
		when is_binary(Password)
		andalso is_binary(Salt)
		andalso is_integer(Iterations) ->
	{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf2({hmac, HMAC}, Password, Salt, Iterations, (Bits div 8) + (Bits rem 8)),
	{jose_jwa_aes_kw:wrap(DecryptedKey, DerivedKey), JWEPBES2};
key_encrypt(#jose_jwk{kty={KTYModule, KTY}}, DecryptedKey, JWEPBES2=#jose_jwe_alg_pbes2{}) ->
	key_encrypt(KTYModule:derive_key(KTY), DecryptedKey, JWEPBES2).

next_cek(_Key, {ENCModule, ENC}, ALG=#jose_jwe_alg_pbes2{}) ->
	{ENCModule:next_cek(ENC), ALG}.

%%====================================================================
%% API functions
%%====================================================================

hmac_supported() ->
	[sha256, sha384, sha512].

wrap_supported() ->
	[128, 192, 256].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
from_map_pbes2(F = #{ <<"p2c">> := P2C }, H) ->
	from_map_pbes2(maps:remove(<<"p2c">>, F), H#jose_jwe_alg_pbes2{ iter = P2C });
from_map_pbes2(F = #{ <<"p2s">> := P2S }, H) ->
	from_map_pbes2(maps:remove(<<"p2s">>, F), H#jose_jwe_alg_pbes2{ salt = wrap_salt(base64url:decode(P2S), H) });
from_map_pbes2(F, H) ->
	{H, F}.

%% @private
to_map_pbes2(F, H=#jose_jwe_alg_pbes2{ iter = P2C, salt = P2S }) ->
	F#{
		<<"p2c">> => P2C,
		<<"p2s">> => base64url:encode(unwrap_salt(P2S, H))
	}.

%% @private
wrap_salt(SaltInput, ?PBES2_HS256_A128KW) ->
	<< "PBES2-HS256+A128KW", 0, SaltInput/binary >>;
wrap_salt(SaltInput, ?PBES2_HS384_A192KW) ->
	<< "PBES2-HS384+A192KW", 0, SaltInput/binary >>;
wrap_salt(SaltInput, ?PBES2_HS512_A256KW) ->
	<< "PBES2-HS512+A256KW", 0, SaltInput/binary >>.

%% @private
unwrap_salt(<< "PBES2-HS256+A128KW", 0, SaltInput/binary >>, ?PBES2_HS256_A128KW) ->
	SaltInput;
unwrap_salt(<< "PBES2-HS384+A192KW", 0, SaltInput/binary >>, ?PBES2_HS384_A192KW) ->
	SaltInput;
unwrap_salt(<< "PBES2-HS512+A256KW", 0, SaltInput/binary >>, ?PBES2_HS512_A256KW) ->
	SaltInput.
