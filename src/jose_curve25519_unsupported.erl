%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_curve25519_unsupported).

-behaviour(jose_curve25519).

%% jose_curve25519 callbacks
-export([eddsa_keypair/0]).
-export([eddsa_keypair/1]).
-export([eddsa_secret_to_public/1]).
-export([ed25519_sign/2]).
-export([ed25519_verify/3]).
-export([ed25519ph_sign/2]).
-export([ed25519ph_verify/3]).
-export([x25519_keypair/0]).
-export([x25519_keypair/1]).
-export([x25519_secret_to_public/1]).
-export([x25519_shared_secret/2]).

%% Macros
-define(unsupported, erlang:error(curve25519_unsupported)).

%%====================================================================
%% jose_curve25519 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	?unsupported.

eddsa_keypair(_Seed) ->
	?unsupported.

eddsa_secret_to_public(_SecretKey) ->
	?unsupported.

% Ed25519
ed25519_sign(_Message, _SecretKey) ->
	?unsupported.

ed25519_verify(_Signature, _Message, _PublicKey) ->
	?unsupported.

% Ed25519ph
ed25519ph_sign(_Message, _SecretKey) ->
	?unsupported.

ed25519ph_verify(_Signature, _Message, _PublicKey) ->
	?unsupported.

% X25519
x25519_keypair() ->
	?unsupported.

x25519_keypair(_Seed) ->
	?unsupported.

x25519_secret_to_public(_SecretKey) ->
	?unsupported.

x25519_shared_secret(_MySecretKey, _YourPublicKey) ->
	?unsupported.
