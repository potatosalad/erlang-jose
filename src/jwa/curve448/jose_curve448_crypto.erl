%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%% Copyright (c) Brett Beatty
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Brett Beatty <brettbeatty@gmail.com>
%%% @copyright (c) Andrew Bennett, Brett Beatty
%%% @doc
%%%
%%% @end
%%% Created :  22 Oct 2021 by Brett Beatty <brettbeatty@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_curve448_crypto).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

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
    ed448_verify/3,
    x448_keypair/0,
    x448_keypair/1,
    x448_secret_to_public/1,
    x448_shared_secret/2
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_curve448,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%%=============================================================================
%%% jose_curve448 callbacks
%%%=============================================================================

% EdDSA
-spec eddsa_keypair() -> {PublicKey :: jose_curve448:eddsa_public_key(), SecretKey :: jose_curve448:eddsa_secret_key()}.
eddsa_keypair() ->
    {PublicKey, Secret} = crypto:generate_key(eddsa, ed448),
    {PublicKey, <<Secret/binary, PublicKey/binary>>}.

-spec eddsa_keypair(Seed :: jose_curve448:eddsa_seed()) ->
    {PublicKey :: jose_curve448:eddsa_public_key(), SecretKey :: jose_curve448:eddsa_secret_key()}.
eddsa_keypair(<<Secret:57/binary>>) ->
    {PublicKey, Secret} = crypto:generate_key(eddsa, ed448, Secret),
    {PublicKey, <<Secret/binary, PublicKey/binary>>}.

-spec eddsa_secret_to_public(SecretKey :: jose_curve448:eddsa_secret_key()) ->
    PublicKey :: jose_curve448:eddsa_public_key().
eddsa_secret_to_public(<<Secret:57/binary>>) ->
    {PublicKey, _} = crypto:generate_key(eddsa, ed448, Secret),
    PublicKey.

% Ed448
-spec ed448_sign(Message :: jose_curve448:message(), SecretKey :: jose_curve448:eddsa_secret_key()) ->
    Signature :: jose_curve448:signature().
ed448_sign(Message, <<Secret:57/binary, _:57/binary>>) ->
    crypto:sign(eddsa, none, Message, [Secret, ed448]).

-spec ed448_verify(
    Signature :: jose_curve448:maybe_invalid_signature(),
    Message :: jose_curve448:message(),
    PublicKey :: jose_curve448:eddsa_public_key()
) -> boolean().
ed448_verify(Signature, Message, <<PublicKey:57/binary>>) ->
    crypto:verify(eddsa, none, Message, Signature, [PublicKey, ed448]).

% X448
-spec x448_keypair() -> {PublicKey :: jose_curve448:eddsa_public_key(), SecretKey :: jose_curve448:eddsa_secret_key()}.
x448_keypair() ->
    crypto:generate_key(ecdh, x448).

-spec x448_keypair(Seed :: jose_curve448:x448_seed()) ->
    {PublicKey :: jose_curve448:x448_public_key(), SecretKey :: jose_curve448:x448_secret_key()}.
x448_keypair(<<Secret:56/binary>>) ->
    crypto:generate_key(ecdh, x448, Secret).

-spec x448_secret_to_public(SecretKey :: jose_curve448:x448_secret_key()) ->
    PublicKey :: jose_curve448:x448_public_key().
x448_secret_to_public(<<Secret:56/binary>>) ->
    {PublicKey, _} = crypto:generate_key(ecdh, x448, Secret),
    PublicKey.

-spec x448_shared_secret(
    MySecretKey :: jose_curve448:x448_secret_key(), YourPublicKey :: jose_curve448:x448_public_key()
) -> SharedSecret :: jose_curve448:x448_shared_secret().
x448_shared_secret(MySecretKey, YourPublicKey) ->
    crypto:compute_key(ecdh, YourPublicKey, MySecretKey, x448).
