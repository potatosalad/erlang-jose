%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Jan 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_curve448_unsupported).

-behaviour(jose_curve448).

%% jose_curve448 callbacks
-export([ed448_keypair/0]).
-export([ed448_keypair/1]).
-export([ed448_secret_to_public/1]).
-export([ed448_sign/2]).
-export([ed448_verify/3]).
-export([ed448ph_keypair/0]).
-export([ed448ph_keypair/1]).
-export([ed448ph_secret_to_public/1]).
-export([ed448ph_sign/2]).
-export([ed448ph_verify/3]).
-export([x448_keypair/0]).
-export([x448_keypair/1]).
-export([x448_secret_to_public/1]).
-export([x448_shared_secret/2]).

%% Macros
-define(unsupported, erlang:error(curve448_unsupported)).

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

% Ed448
ed448_keypair() ->
	?unsupported.

ed448_keypair(_Seed) ->
	?unsupported.

ed448_secret_to_public(_SecretKey) ->
	?unsupported.

ed448_sign(_Message, _SecretKey) ->
	?unsupported.

ed448_verify(_Signature, _Message, _PublicKey) ->
	?unsupported.

% Ed448ph
ed448ph_keypair() ->
	?unsupported.

ed448ph_keypair(_Seed) ->
	?unsupported.

ed448ph_secret_to_public(_SecretKey) ->
	?unsupported.

ed448ph_sign(_Message, _SecretKey) ->
	?unsupported.

ed448ph_verify(_Signature, _Message, _PublicKey) ->
	?unsupported.

% X448
x448_keypair() ->
	?unsupported.

x448_keypair(_Seed) ->
	?unsupported.

x448_secret_to_public(_SecretKey) ->
	?unsupported.

x448_shared_secret(_MySecretKey, _YourPublicKey) ->
	?unsupported.
