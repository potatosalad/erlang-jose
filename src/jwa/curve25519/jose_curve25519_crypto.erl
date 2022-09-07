%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Brett Beatty <brettbeatty@gmail.com>
%%% @copyright 2021, Brett Beatty
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Oct 2021 by Brett Beatty <brettbeatty@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_curve25519_crypto).

-behaviour(jose_provider).
-behaviour(jose_curve25519).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_curve25519 callbacks
-export([
	eddsa_keypair/0,
	eddsa_keypair/1,
	eddsa_secret_to_public/1,
	ed25519_sign/2,
	ed25519_verify/3,
	x25519_keypair/0,
	x25519_keypair/1,
	x25519_secret_to_public/1,
	x25519_shared_secret/2
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_curve25519,
		priority => high,
		requirements => [
			{app, crypto},
			crypto
		]
	}.

%%====================================================================
%% jose_curve25519 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	{PublicKey, Secret} = crypto:generate_key(eddsa, ed25519),
	{PublicKey, <<Secret/binary, PublicKey/binary>>}.

eddsa_keypair(<<Secret:32/binary>>) ->
	{PublicKey, Secret} = crypto:generate_key(eddsa, ed25519, Secret),
	{PublicKey, <<Secret/binary, PublicKey/binary>>}.

eddsa_secret_to_public(<<Secret:32/binary>>) ->
	{PublicKey, _} = crypto:generate_key(eddsa, ed25519, Secret),
	PublicKey.

% Ed25519
ed25519_sign(Message, <<Secret:32/binary, _:32/binary>>) ->
	crypto:sign(eddsa, none, Message, [Secret, ed25519]).

ed25519_verify(Signature, Message, <<PublicKey:32/binary>>) ->
	crypto:verify(eddsa, none, Message, Signature, [PublicKey, ed25519]).

% X25519
x25519_keypair() ->
	crypto:generate_key(ecdh, x25519).

x25519_keypair(<<Secret:32/binary>>) ->
	crypto:generate_key(ecdh, x25519, Secret).

x25519_secret_to_public(<<Secret:32/binary>>) ->
	{PublicKey, _} = crypto:generate_key(ecdh, x25519, Secret),
	PublicKey.

x25519_shared_secret(MySecretKey, YourPublicKey) ->
	crypto:compute_key(ecdh, YourPublicKey, MySecretKey, x25519).
