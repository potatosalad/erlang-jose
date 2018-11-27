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
-module(jose_curve25519).

-callback eddsa_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback eddsa_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback eddsa_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback ed25519_sign(Message::binary(), SecretKey::binary()) -> Signature::binary().
-callback ed25519_verify(Signature::binary(), Message::binary(), PublicKey::binary()) -> boolean().
-callback ed25519ph_sign(Message::binary(), SecretKey::binary()) -> Signature::binary().
-callback ed25519ph_verify(Signature::binary(), Message::binary(), PublicKey::binary()) -> boolean().
-callback x25519_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback x25519_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback x25519_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback x25519_shared_secret(MySecretKey::binary(), YourPublicKey::binary()) -> SharedSecret::binary().

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
-define(JOSE_CURVE25519, (jose:curve25519_module())).

%%====================================================================
%% jose_curve25519 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	?JOSE_CURVE25519:eddsa_keypair().

eddsa_keypair(Seed) ->
	?JOSE_CURVE25519:eddsa_keypair(Seed).

eddsa_secret_to_public(SecretKey) ->
	?JOSE_CURVE25519:eddsa_secret_to_public(SecretKey).

% Ed25519
ed25519_sign(Message, SecretKey) ->
	?JOSE_CURVE25519:ed25519_sign(Message, SecretKey).

ed25519_verify(Signature, Message, PublicKey) ->
	?JOSE_CURVE25519:ed25519_verify(Signature, Message, PublicKey).

% Ed25519ph
ed25519ph_sign(Message, SecretKey) ->
	?JOSE_CURVE25519:ed25519ph_sign(Message, SecretKey).

ed25519ph_verify(Signature, Message, PublicKey) ->
	?JOSE_CURVE25519:ed25519ph_verify(Signature, Message, PublicKey).

% X25519
x25519_keypair() ->
	?JOSE_CURVE25519:x25519_keypair().

x25519_keypair(Seed) ->
	?JOSE_CURVE25519:x25519_keypair(Seed).

x25519_secret_to_public(SecretKey) ->
	?JOSE_CURVE25519:x25519_secret_to_public(SecretKey).

x25519_shared_secret(MySecretKey, YourPublicKey) ->
	?JOSE_CURVE25519:x25519_shared_secret(MySecretKey, YourPublicKey).
