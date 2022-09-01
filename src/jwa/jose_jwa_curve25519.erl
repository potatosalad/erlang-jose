%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_curve25519).

-behaviour(jose_curve25519).

%% jose_curve25519 callbacks
-export([eddsa_keypair/0]).
-export([eddsa_keypair/1]).
-export([eddsa_secret_to_public/1]).
-export([ed25519_sign/2]).
-export([ed25519_verify/3]).
-export([ed25519ctx_sign/3]).
-export([ed25519ctx_verify/4]).
-export([ed25519ph_sign/2]).
-export([ed25519ph_sign/3]).
-export([ed25519ph_verify/3]).
-export([ed25519ph_verify/4]).
-export([x25519_keypair/0]).
-export([x25519_keypair/1]).
-export([x25519_secret_to_public/1]).
-export([x25519_shared_secret/2]).

%%====================================================================
%% jose_curve25519 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	jose_jwa_ed25519:keypair().

eddsa_keypair(Seed)
		when is_binary(Seed) ->
	jose_jwa_ed25519:keypair(Seed).

eddsa_secret_to_public(SecretKey)
		when is_binary(SecretKey) ->
	jose_jwa_ed25519:secret_to_pk(SecretKey).

% Ed25519
ed25519_sign(Message, SecretKey)
		when is_binary(Message)
		andalso is_binary(SecretKey) ->
	jose_jwa_ed25519:ed25519_sign(Message, SecretKey).

ed25519_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(PublicKey) ->
	try
		jose_jwa_ed25519:ed25519_verify(Signature, Message, PublicKey)
	catch
		_:_ ->
			false
	end.

% Ed25519ctx
ed25519ctx_sign(Message, SecretKey, Context)
		when is_binary(Message)
		andalso is_binary(SecretKey)
		andalso is_binary(Context)
		andalso byte_size(Context) =< 255 ->
	jose_jwa_ed25519:ed25519ctx_sign(Message, SecretKey, Context).

ed25519ctx_verify(Signature, Message, PublicKey, Context)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(PublicKey)
		andalso is_binary(Context)
		andalso byte_size(Context) =< 255 ->
	try
		jose_jwa_ed25519:ed25519ctx_verify(Signature, Message, PublicKey, Context)
	catch
		_:_ ->
			false
	end.

% Ed25519ph
ed25519ph_sign(Message, SecretKey)
		when is_binary(Message)
		andalso is_binary(SecretKey) ->
	jose_jwa_ed25519:ed25519ph_sign(Message, SecretKey).

ed25519ph_sign(Message, SecretKey, Context)
		when is_binary(Message)
		andalso is_binary(SecretKey)
		andalso is_binary(Context)
		andalso byte_size(Context) =< 255 ->
	jose_jwa_ed25519:ed25519ph_sign(Message, SecretKey, Context).

ed25519ph_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(PublicKey) ->
	try
		jose_jwa_ed25519:ed25519ph_verify(Signature, Message, PublicKey)
	catch
		_:_ ->
			false
	end.

ed25519ph_verify(Signature, Message, PublicKey, Context)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(PublicKey)
		andalso is_binary(Context)
		andalso byte_size(Context) =< 255 ->
	try
		jose_jwa_ed25519:ed25519ph_verify(Signature, Message, PublicKey, Context)
	catch
		_:_ ->
			false
	end.

% X25519
x25519_keypair() ->
	jose_jwa_x25519:keypair().

x25519_keypair(Seed)
		when is_binary(Seed) ->
	jose_jwa_x25519:keypair(Seed).

x25519_secret_to_public(SecretKey)
		when is_binary(SecretKey) ->
	jose_jwa_x25519:sk_to_pk(SecretKey).

x25519_shared_secret(MySecretKey, YourPublicKey)
		when is_binary(MySecretKey)
		andalso is_binary(YourPublicKey) ->
	jose_jwa_x25519:x25519(MySecretKey, YourPublicKey).
