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
-module(jose_jws_alg_hmac).
-behaviour(jose_jws).
-behaviour(jose_jws_alg).

-include("jose_jwk.hrl").

%% jose_jws callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jws_alg callbacks
-export([generate_key/2]).
-export([sign/3]).
-export([verify/4]).
%% API

%% Types
-record(jose_jws_alg_hmac, {
	hmac = undefined :: undefined | sha256 | sha384 | sha512
}).

-type alg() :: #jose_jws_alg_hmac{}.

-export_type([alg/0]).

-define(HS256, #jose_jws_alg_hmac{hmac=sha256}).
-define(HS384, #jose_jws_alg_hmac{hmac=sha384}).
-define(HS512, #jose_jws_alg_hmac{hmac=sha512}).

%%====================================================================
%% jose_jws callbacks
%%====================================================================

from_map(F = #{ <<"alg">> := <<"HS256">> }) ->
	{?HS256, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"HS384">> }) ->
	{?HS384, maps:remove(<<"alg">>, F)};
from_map(F = #{ <<"alg">> := <<"HS512">> }) ->
	{?HS512, maps:remove(<<"alg">>, F)}.

to_map(?HS256, F) ->
	F#{ <<"alg">> => <<"HS256">> };
to_map(?HS384, F) ->
	F#{ <<"alg">> => <<"HS384">> };
to_map(?HS512, F) ->
	F#{ <<"alg">> => <<"HS512">> }.

%%====================================================================
%% jose_jws_alg callbacks
%%====================================================================

generate_key(?HS256, _Fields) ->
	jose_jws_alg:generate_key({oct, 32}, <<"HS256">>);
generate_key(?HS384, _Fields) ->
	jose_jws_alg:generate_key({oct, 48}, <<"HS384">>);
generate_key(?HS512, _Fields) ->
	jose_jws_alg:generate_key({oct, 64}, <<"HS512">>).

sign(#jose_jwk{kty={KTYModule, KTY}}, Message, #jose_jws_alg_hmac{hmac=HMAC}) ->
	KTYModule:sign(Message, HMAC, KTY).

verify(#jose_jwk{kty={KTYModule, KTY}}, Message, Signature, #jose_jws_alg_hmac{hmac=HMAC}) ->
	KTYModule:verify(Message, HMAC, Signature, KTY).

%%====================================================================
%% API functions
%%====================================================================

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
