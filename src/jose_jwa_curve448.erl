%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Jan 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_curve448).

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

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

% Ed448
ed448_keypair() ->
	jose_curve25519_unsupported:keypair().

ed448_keypair(Seed)
		when is_binary(Seed) ->
	jose_curve25519_unsupported:keypair(Seed).

ed448_secret_to_public(SecretKey)
		when is_binary(SecretKey) ->
	jose_curve25519_unsupported:sk_to_pk(SecretKey).

ed448_sign(Message, SecretKey)
		when is_binary(Message)
		andalso is_binary(SecretKey) ->
	jose_curve25519_unsupported:sign(Message, SecretKey).

ed448_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(PublicKey) ->
	try
		jose_curve25519_unsupported:verify(Signature, Message, PublicKey)
	catch
		_:_ ->
			false
	end.

% Ed448ph
ed448ph_keypair() ->
	jose_curve25519_unsupported:keypair().

ed448ph_keypair(Seed)
		when is_binary(Seed) ->
	jose_curve25519_unsupported:keypair(Seed).

ed448ph_secret_to_public(SecretKey)
		when is_binary(SecretKey) ->
	jose_curve25519_unsupported:sk_to_pk(SecretKey).

ed448ph_sign(Message, SecretKey)
		when is_binary(Message)
		andalso is_binary(SecretKey) ->
	jose_curve25519_unsupported:sign(Message, SecretKey).

ed448ph_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso is_binary(PublicKey) ->
	try
		jose_curve25519_unsupported:verify(Signature, Message, PublicKey)
	catch
		_:_ ->
			false
	end.

% X448
x448_keypair() ->
	jose_jwa_x448:keypair().

x448_keypair(Seed)
		when is_binary(Seed) ->
	jose_jwa_x448:keypair(Seed).

x448_secret_to_public(SecretKey)
		when is_binary(SecretKey) ->
	jose_jwa_x448:sk_to_pk(SecretKey).

x448_shared_secret(MySecretKey, YourPublicKey)
		when is_binary(MySecretKey)
		andalso is_binary(YourPublicKey) ->
	jose_jwa_x448:x448(MySecretKey, YourPublicKey).
