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
-module(jose_curve25519_libsodium).

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
-define(PH(M), libsodium_crypto_hash_sha512:crypto_hash_sha512(M)).

%%====================================================================
%% jose_curve25519 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	libsodium_crypto_sign_ed25519:keypair().

eddsa_keypair(Seed) ->
	libsodium_crypto_sign_ed25519:seed_keypair(Seed).

eddsa_secret_to_public(SecretKey) ->
	{PK, _} = libsodium_crypto_sign_ed25519:seed_keypair(SecretKey),
	PK.

% Ed25519
ed25519_sign(Message, SecretKey) ->
	libsodium_crypto_sign_ed25519:detached(Message, SecretKey).

ed25519_verify(Signature, Message, PublicKey) ->
	try libsodium_crypto_sign_ed25519:verify_detached(Signature, Message, PublicKey) of
		0 ->
			true;
		_ ->
			false
	catch
		_:_ ->
			false
	end.

% Ed25519ph
ed25519ph_sign(Message, SecretKey) ->
	ed25519_sign(?PH(Message), SecretKey).

ed25519ph_verify(Signature, Message, PublicKey) ->
	ed25519_verify(Signature, ?PH(Message), PublicKey).

% X25519
x25519_keypair() ->
	libsodium_crypto_box_curve25519xsalsa20poly1305:keypair().

x25519_keypair(SK = << _:32/binary >>) ->
	PK = x25519_secret_to_public(SK),
	{PK, SK}.

x25519_secret_to_public(SecretKey) ->
	libsodium_crypto_scalarmult_curve25519:base(SecretKey).

x25519_shared_secret(MySecretKey, YourPublicKey) ->
	libsodium_crypto_scalarmult_curve25519:crypto_scalarmult_curve25519(MySecretKey, YourPublicKey).
