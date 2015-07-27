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
-module(jose_jws_alg_ecdsa).

-include("jose_jwk.hrl").

%% jose_jws callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jws_alg callbacks
-export([sign/3]).
-export([verify/4]).

%% API

%% Types
-record(jose_jws_alg_ecdsa, {
	digest = undefined :: undefined | sha256 | sha384 | sha512
}).

-type alg() :: #jose_jws_alg_ecdsa{}.

-export_type([alg/0]).

-define(ES256, #jose_jws_alg_ecdsa{digest=sha256}).
-define(ES384, #jose_jws_alg_ecdsa{digest=sha384}).
-define(ES512, #jose_jws_alg_ecdsa{digest=sha512}).

%%====================================================================
%% jose_jws callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"ES256">> }) ->
	{?ES256, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"ES384">> }) ->
	{?ES384, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"ES512">> }) ->
	{?ES512, maps:remove(<<"alg">>, F)}.

to_map(?ES256, F) ->
	F#{ <<"alg">> => <<"ES256">> };
to_map(?ES384, F) ->
	F#{ <<"alg">> => <<"ES384">> };
to_map(?ES512, F) ->
	F#{ <<"alg">> => <<"ES512">> }.

%%====================================================================
%% jose_jws_alg callbacks
%%====================================================================

sign(#jose_jwk{kty={KTYModule, KTY}}, Message, #jose_jws_alg_ecdsa{digest=DigestType}) ->
	KTYModule:sign(Message, DigestType, KTY).

verify(#jose_jwk{kty={KTYModule, KTY}}, Message, Signature, #jose_jws_alg_ecdsa{digest=DigestType}) ->
	KTYModule:verify(Message, DigestType, Signature, KTY).

%%====================================================================
%% API functions
%%====================================================================

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
