%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_curve25519_libsodium).

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
    ed25519ph_sign/2,
    ed25519ph_verify/3,
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
        priority => normal,
        requirements => [
            {app, libsodium},
            libsodium_crypto_box_curve25519xchacha20poly1305,
            libsodium_crypto_scalarmult_curve25519,
            libsodium_crypto_sign_ed25519,
            libsodium_crypto_sign_ed25519ph
        ]
    }.

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
        _:_:_ ->
            false
    end.

% Ed25519ph
ed25519ph_sign(Message, SecretKey) ->
    State0 = libsodium_crypto_sign_ed25519ph:init(),
    State1 = libsodium_crypto_sign_ed25519ph:update(State0, Message),
    libsodium_crypto_sign_ed25519ph:final_create(State1, SecretKey).

ed25519ph_verify(Signature, Message, PublicKey) ->
    State0 = libsodium_crypto_sign_ed25519ph:init(),
    State1 = libsodium_crypto_sign_ed25519ph:update(State0, Message),
    try libsodium_crypto_sign_ed25519ph:final_verify(State1, Signature, PublicKey) of
        0 ->
            true;
        _ ->
            false
    catch
        _:_:_ ->
            false
    end.

% X25519
x25519_keypair() ->
    libsodium_crypto_box_curve25519xchacha20poly1305:keypair().

x25519_keypair(SK = <<_:32/binary>>) ->
    PK = x25519_secret_to_public(SK),
    {PK, SK}.

x25519_secret_to_public(SecretKey) ->
    libsodium_crypto_scalarmult_curve25519:base(SecretKey).

x25519_shared_secret(MySecretKey, YourPublicKey) ->
    libsodium_crypto_scalarmult_curve25519:crypto_scalarmult_curve25519(MySecretKey, YourPublicKey).
