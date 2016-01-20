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

-callback ed448_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback ed448_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback ed448_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback ed448_sign(Message::binary()|{binary(),binary()}, SecretKey::binary()) -> Signature::binary().
-callback ed448_verify(Signature::binary(), Message::binary()|{binary(),binary()}, PublicKey::binary()) -> boolean().
-callback ed448ph_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback ed448ph_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback ed448ph_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback ed448ph_sign(Message::binary()|{binary(),binary()}, SecretKey::binary()) -> Signature::binary().
-callback ed448ph_verify(Signature::binary(), Message::binary()|{binary(),binary()}, PublicKey::binary()) -> boolean().
-callback x448_keypair() -> {PublicKey::binary(), SecretKey::binary()}.
-callback x448_keypair(Seed::binary()) -> {PublicKey::binary(), SecretKey::binary()}.
-callback x448_secret_to_public(SecretKey::binary()) -> PublicKey::binary().
-callback x448_shared_secret(MySecretKey::binary(), YourPublicKey::binary()) -> SharedSecret::binary().

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
-define(JOSE_CURVE448, (jose:curve448_module())).

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

% Ed448
ed448_keypair() ->
	?JOSE_CURVE448:ed448_keypair().

ed448_keypair(Seed) ->
	?JOSE_CURVE448:ed448_keypair(Seed).

ed448_secret_to_public(SecretKey) ->
	?JOSE_CURVE448:ed448_secret_to_public(SecretKey).

ed448_sign(Message, SecretKey) ->
	?JOSE_CURVE448:ed448_sign(Message, SecretKey).

ed448_verify(Signature, Message, PublicKey) ->
	?JOSE_CURVE448:ed448_verify(Signature, Message, PublicKey).

% Ed448ph
ed448ph_keypair() ->
	?JOSE_CURVE448:ed448ph_keypair().

ed448ph_keypair(Seed) ->
	?JOSE_CURVE448:ed448ph_keypair(Seed).

ed448ph_secret_to_public(SecretKey) ->
	?JOSE_CURVE448:ed448ph_secret_to_public(SecretKey).

ed448ph_sign(Message, SecretKey) ->
	?JOSE_CURVE448:ed448ph_sign(Message, SecretKey).

ed448ph_verify(Signature, Message, PublicKey) ->
	?JOSE_CURVE448:ed448ph_verify(Signature, Message, PublicKey).

% X448
x448_keypair() ->
	?JOSE_CURVE448:x448_keypair().

x448_keypair(Seed) ->
	?JOSE_CURVE448:x448_keypair(Seed).

x448_secret_to_public(SecretKey) ->
	?JOSE_CURVE448:x448_secret_to_public(SecretKey).

x448_shared_secret(MySecretKey, YourPublicKey) ->
	?JOSE_CURVE448:x448_shared_secret(MySecretKey, YourPublicKey).
