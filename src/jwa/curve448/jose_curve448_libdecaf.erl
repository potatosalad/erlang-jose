%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  01 Mar 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_curve448_libdecaf).

-behaviour(jose_provider).
-behaviour(jose_curve448).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_curve448 callbacks
-export([
	eddsa_keypair/0,
	eddsa_keypair/1,
	eddsa_secret_to_public/1,
	ed448_sign/2,
	ed448_sign/3,
	ed448_verify/3,
	ed448_verify/4,
	ed448ph_sign/2,
	ed448ph_sign/3,
	ed448ph_verify/3,
	ed448ph_verify/4,
	x448_keypair/0,
	x448_keypair/1,
	x448_secret_to_public/1,
	x448_shared_secret/2
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_curve448,
		priority => normal,
		requirements => [
			{app, libdecaf},
			libdecaf_curve448
		]
	}.

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

% EdDSA
eddsa_keypair() ->
	libdecaf_curve448:eddsa_keypair().

eddsa_keypair(Seed) ->
	libdecaf_curve448:eddsa_keypair(Seed).

eddsa_secret_to_public(SecretKey) ->
	libdecaf_curve448:eddsa_secret_to_pk(SecretKey).

% Ed448
ed448_sign(Message, SecretKey) ->
	libdecaf_curve448:ed448_sign(Message, SecretKey).

ed448_sign(Message, SecretKey, Context) ->
	libdecaf_curve448:ed448_sign(Message, SecretKey, Context).

ed448_verify(Signature, Message, PublicKey) ->
	libdecaf_curve448:ed448_verify(Signature, Message, PublicKey).

ed448_verify(Signature, Message, PublicKey, Context) ->
	libdecaf_curve448:ed448_verify(Signature, Message, PublicKey, Context).

% Ed448ph
ed448ph_sign(Message, SecretKey) ->
	M = Message,
	C = <<>>,
	CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
	libdecaf_curve448:ed448ph_sign(CM, SecretKey).

ed448ph_sign(Message, SecretKey, Context) ->
	M = Message,
	C = Context,
	CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
	libdecaf_curve448:ed448ph_sign(CM, SecretKey, Context).

ed448ph_verify(Signature, Message, PublicKey) ->
	M = Message,
	C = <<>>,
	CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
	libdecaf_curve448:ed448ph_verify(Signature, CM, PublicKey).

ed448ph_verify(Signature, Message, PublicKey, Context) ->
	M = Message,
	C = Context,
	CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
	libdecaf_curve448:ed448ph_verify(Signature, CM, PublicKey, Context).

% X448
x448_keypair() ->
	libdecaf_curve448:x448_keypair().

x448_keypair(Seed) ->
	libdecaf_curve448:x448_keypair(Seed).

x448_secret_to_public(SecretKey) ->
	libdecaf_curve448:x448(SecretKey).

x448_shared_secret(MySecretKey, YourPublicKey) ->
	libdecaf_curve448:x448(MySecretKey, YourPublicKey).
