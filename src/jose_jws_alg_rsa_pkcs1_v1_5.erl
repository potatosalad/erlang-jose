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
-module(jose_jws_alg_rsa_pkcs1_v1_5).
-behaviour(jose_jws).
-behaviour(jose_jws_alg).

-include("jose_jwk.hrl").

%% jose_jws callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jws_alg callbacks
-export([sign/3]).
-export([verify/4]).

%% API

%% Types
-record(jose_jws_alg_rsa_pkcs1_v1_5, {
	digest = undefined :: undefined | sha256 | sha384 | sha512
}).

-type alg() :: #jose_jws_alg_rsa_pkcs1_v1_5{}.

-export_type([alg/0]).

-define(RS256, #jose_jws_alg_rsa_pkcs1_v1_5{digest=sha256}).
-define(RS384, #jose_jws_alg_rsa_pkcs1_v1_5{digest=sha384}).
-define(RS512, #jose_jws_alg_rsa_pkcs1_v1_5{digest=sha512}).

%%====================================================================
%% jose_jws callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"RS256">> }) ->
	{?RS256, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"RS384">> }) ->
	{?RS384, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"RS512">> }) ->
	{?RS512, maps:remove(<<"alg">>, F)}.

to_map(?RS256, F) ->
	F#{ <<"alg">> => <<"RS256">> };
to_map(?RS384, F) ->
	F#{ <<"alg">> => <<"RS384">> };
to_map(?RS512, F) ->
	F#{ <<"alg">> => <<"RS512">> }.

%%====================================================================
%% jose_jws_alg callbacks
%%====================================================================

sign(#jose_jwk{kty={KTYModule, KTY}}, Message, #jose_jws_alg_rsa_pkcs1_v1_5{digest=DigestType}) ->
	KTYModule:sign(Message, {rsa_pkcs1_padding, DigestType}, KTY).

verify(#jose_jwk{kty={KTYModule, KTY}}, Message, Signature, #jose_jws_alg_rsa_pkcs1_v1_5{digest=DigestType}) ->
	KTYModule:verify(Message, {rsa_pkcs1_padding, DigestType}, Signature, KTY).

%%====================================================================
%% API functions
%%====================================================================

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
