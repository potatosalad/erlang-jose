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
-module(jose_curve448).

-callback eddsa_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback eddsa_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback eddsa_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback ed448_sign(Message::binary(), SecretKey::binary()) -> Signature::binary().
-callback ed448_sign(Message::binary(), SecretKey::binary(), Context::binary()) -> Signature::binary().
-callback ed448_verify(Signature::binary(), Message::binary(), PublicKey::binary()) -> boolean().
-callback ed448_verify(Signature::binary(), Message::binary(), PublicKey::binary(), Context::binary()) -> boolean().
-callback ed448ph_sign(Message::binary(), SecretKey::binary()) -> Signature::binary().
-callback ed448ph_sign(Message::binary(), SecretKey::binary(), Context::binary()) -> Signature::binary().
-callback ed448ph_verify(Signature::binary(), Message::binary(), PublicKey::binary()) -> boolean().
-callback ed448ph_verify(Signature::binary(), Message::binary(), PublicKey::binary(), Context::binary()) -> boolean().
-callback x448_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback x448_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback x448_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback x448_shared_secret(MySecretKey::binary(), YourPublicKey::binary()) -> SharedSecret::binary().

%% jose_curve448 callbacks
-export([eddsa_keypair/0]).
-export([eddsa_keypair/1]).
-export([eddsa_secret_to_public/1]).
-export([ed448_sign/2]).
-export([ed448_sign/3]).
-export([ed448_verify/3]).
-export([ed448_verify/4]).
-export([ed448ph_sign/2]).
-export([ed448ph_sign/3]).
-export([ed448ph_verify/3]).
-export([ed448ph_verify/4]).
-export([x448_keypair/0]).
-export([x448_keypair/1]).
-export([x448_secret_to_public/1]).
-export([x448_shared_secret/2]).

%% Macros
-define(JOSE_CURVE448, (jose:curve448_module())).

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	?JOSE_CURVE448:eddsa_keypair().

eddsa_keypair(Seed) ->
	?JOSE_CURVE448:eddsa_keypair(Seed).

eddsa_secret_to_public(SecretKey) ->
	?JOSE_CURVE448:eddsa_secret_to_public(SecretKey).

% Ed448
ed448_sign(Message, SecretKey) ->
	?JOSE_CURVE448:ed448_sign(Message, SecretKey).

ed448_sign(Message, SecretKey, Context) ->
	?JOSE_CURVE448:ed448_sign(Message, SecretKey, Context).

ed448_verify(Signature, Message, PublicKey) ->
	?JOSE_CURVE448:ed448_verify(Signature, Message, PublicKey).

ed448_verify(Signature, Message, PublicKey, Context) ->
	?JOSE_CURVE448:ed448_verify(Signature, Message, PublicKey, Context).

% Ed448ph
ed448ph_sign(Message, SecretKey) ->
	?JOSE_CURVE448:ed448ph_sign(Message, SecretKey).

ed448ph_sign(Message, SecretKey, Context) ->
	?JOSE_CURVE448:ed448ph_sign(Message, SecretKey, Context).

ed448ph_verify(Signature, Message, PublicKey) ->
	?JOSE_CURVE448:ed448ph_verify(Signature, Message, PublicKey).

ed448ph_verify(Signature, Message, PublicKey, Context) ->
	?JOSE_CURVE448:ed448ph_verify(Signature, Message, PublicKey, Context).

% X448
x448_keypair() ->
	?JOSE_CURVE448:x448_keypair().

x448_keypair(Seed) ->
	?JOSE_CURVE448:x448_keypair(Seed).

x448_secret_to_public(SecretKey) ->
	?JOSE_CURVE448:x448_secret_to_public(SecretKey).

x448_shared_secret(MySecretKey, YourPublicKey) ->
	?JOSE_CURVE448:x448_shared_secret(MySecretKey, YourPublicKey).
