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
-module(jose_curve448_crypto).

-behaviour(jose_curve448).

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
-define(unsupported, erlang:error(not_yet_implemented)).

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	{PublicKey, Secret} = crypto:generate_key(eddsa, ed448),
	{PublicKey, <<Secret/binary, PublicKey/binary>>}.

eddsa_keypair(<<Secret:57/binary>>) ->
	{PublicKey, Secret} = crypto:generate_key(eddsa, ed448, Secret),
	{PublicKey, <<Secret/binary, PublicKey/binary>>}.

eddsa_secret_to_public(<<Secret:57/binary>>) ->
	{PublicKey, _} = crypto:generate_key(eddsa, ed448, Secret),
	PublicKey.

% Ed448
ed448_sign(Message, <<Secret:57/binary, _:57/binary>>) ->
	crypto:sign(eddsa, none, Message, [Secret, ed448]).

ed448_sign(_Message, _SecretKey, _Context) ->
	?unsupported.

ed448_verify(Signature, Message, <<PublicKey:57/binary>>) ->
	crypto:verify(eddsa, none, Message, Signature, [PublicKey, ed448]).

ed448_verify(_Signature, _Message, _PublicKey, _Context) ->
	?unsupported.

% Ed448ph
ed448ph_sign(_Message, _SecretKey) ->
	?unsupported.

ed448ph_sign(_Message, _SecretKey, _Context) ->
	?unsupported.

ed448ph_verify(_Signature, _Message, _PublicKey) ->
	?unsupported.

ed448ph_verify(_Signature, _Message, _PublicKey, _Context) ->
	?unsupported.

% X448
x448_keypair() ->
	crypto:generate_key(ecdh, x448).

x448_keypair(<<Secret:56/binary>>) ->
	crypto:generate_key(ecdh, x448, Secret).

x448_secret_to_public(<<Secret:56/binary>>) ->
	{PublicKey, _} = crypto:generate_key(ecdh, x448, Secret),
	PublicKey.

x448_shared_secret(MySecretKey, YourPublicKey) ->
	crypto:compute_key(ecdh, YourPublicKey, MySecretKey, x448).
