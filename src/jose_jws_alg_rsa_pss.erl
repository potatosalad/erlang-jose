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
-module(jose_jws_alg_rsa_pss).

-include("jose_jwk.hrl").

%% jose_jws callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jws_alg callbacks
-export([sign/3]).
-export([verify/4]).

%% API

%% Types
-record(jose_jws_alg_rsa_pss, {
	digest = undefined :: undefined | sha256 | sha384 | sha512
}).

-type alg() :: #jose_jws_alg_rsa_pss{}.

-export_type([alg/0]).

-define(PS256, #jose_jws_alg_rsa_pss{digest=sha256}).
-define(PS384, #jose_jws_alg_rsa_pss{digest=sha384}).
-define(PS512, #jose_jws_alg_rsa_pss{digest=sha512}).

%%====================================================================
%% jose_jws callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"PS256">> }) ->
	{?PS256, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"PS384">> }) ->
	{?PS384, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"PS512">> }) ->
	{?PS512, maps:remove(<<"alg">>, F)}.

to_map(?PS256, F) ->
	F#{ <<"alg">> => <<"PS256">> };
to_map(?PS384, F) ->
	F#{ <<"alg">> => <<"PS384">> };
to_map(?PS512, F) ->
	F#{ <<"alg">> => <<"PS512">> }.

%%====================================================================
%% jose_jws_alg callbacks
%%====================================================================

sign(#jose_jwk{kty={KTYModule, KTY}}, Message, #jose_jws_alg_rsa_pss{digest=DigestType}) ->
	KTYModule:sign(Message, {rsa_pss, DigestType}, KTY).

verify(#jose_jwk{kty={KTYModule, KTY}}, Message, Signature, #jose_jws_alg_rsa_pss{digest=DigestType}) ->
	KTYModule:verify(Message, {rsa_pss, DigestType}, Signature, KTY).

%%====================================================================
%% API functions
%%====================================================================

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
