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
-module(jose_jwe_alg_rsa).
-behaviour(jose_jwe).
-behaviour(jose_jwe_alg).

-include("jose_jwk.hrl").

%% jose_jwe callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jwe_alg callbacks
-export([key_decrypt/3]).
-export([key_encrypt/3]).
-export([next_cek/4]).
%% API

%% Types
-record(jose_jwe_alg_rsa, {
	algorithm = undefined :: undefined | rsa1_5 | rsa_oaep | rsa_oaep_256
}).

-type alg() :: #jose_jwe_alg_rsa{}.

-export_type([alg/0]).

-define(RSA1_5,       #jose_jwe_alg_rsa{algorithm=rsa1_5}).
-define(RSA_OAEP,     #jose_jwe_alg_rsa{algorithm=rsa_oaep}).
-define(RSA_OAEP_256, #jose_jwe_alg_rsa{algorithm=rsa_oaep_256}).

%%====================================================================
%% jose_jwe callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"RSA1_5">> }) ->
	{?RSA1_5, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"RSA-OAEP">> }) ->
	{?RSA_OAEP, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"RSA-OAEP-256">> }) ->
	{?RSA_OAEP_256, maps:remove(<<"alg">>, F)}.

to_map(?RSA1_5, F) ->
	F#{ <<"alg">> => <<"RSA1_5">> };
to_map(?RSA_OAEP, F) ->
	F#{ <<"alg">> => <<"RSA-OAEP">> };
to_map(?RSA_OAEP_256, F) ->
	F#{ <<"alg">> => <<"RSA-OAEP-256">> }.

%%====================================================================
%% jose_jwe_alg callbacks
%%====================================================================

key_decrypt(#jose_jwk{kty={KTYModule, KTY}}, {_ENCModule, _ENC, EncryptedKey}, #jose_jwe_alg_rsa{algorithm=Algorithm}) ->
	KTYModule:decrypt_private(EncryptedKey, Algorithm, KTY).

key_encrypt(#jose_jwk{kty={KTYModule, KTY}}, DecryptedKey, JWERSA=#jose_jwe_alg_rsa{algorithm=Algorithm}) ->
	{KTYModule:encrypt_public(DecryptedKey, Algorithm, KTY), JWERSA}.

next_cek(_Key, ENCModule, ENC, #jose_jwe_alg_rsa{}) ->
	ENCModule:next_cek(ENC).

%%====================================================================
%% API functions
%%====================================================================

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
