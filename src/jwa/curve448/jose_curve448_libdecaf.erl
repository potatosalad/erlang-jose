%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  01 Mar 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_curve448_libdecaf).
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

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

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

%%%=============================================================================
%%% jose_curve448 callbacks
%%%=============================================================================

% EdDSA
-spec eddsa_keypair() -> {PublicKey :: jose_curve448:eddsa_public_key(), SecretKey :: jose_curve448:eddsa_secret_key()}.
eddsa_keypair() ->
    libdecaf_curve448:eddsa_keypair().

-spec eddsa_keypair(Seed :: jose_curve448:eddsa_seed()) ->
    {PublicKey :: jose_curve448:eddsa_public_key(), SecretKey :: jose_curve448:eddsa_secret_key()}.
eddsa_keypair(Seed) ->
    libdecaf_curve448:eddsa_keypair(Seed).

-spec eddsa_secret_to_public(SecretKey :: jose_curve448:eddsa_secret_key()) ->
    PublicKey :: jose_curve448:eddsa_public_key().
eddsa_secret_to_public(SecretKey) ->
    libdecaf_curve448:eddsa_secret_to_pk(SecretKey).

% Ed448
-spec ed448_sign(Message :: jose_curve448:message(), SecretKey :: jose_curve448:eddsa_secret_key()) ->
    Signature :: jose_curve448:signature().
ed448_sign(Message, SecretKey) ->
    libdecaf_curve448:ed448_sign(Message, SecretKey).

-spec ed448_sign(
    Message :: jose_curve448:message(),
    SecretKey :: jose_curve448:eddsa_secret_key(),
    Context :: jose_curve448:context()
) ->
    Signature :: jose_curve448:signature().
ed448_sign(Message, SecretKey, Context) ->
    libdecaf_curve448:ed448_sign(Message, SecretKey, Context).

-spec ed448_verify(
    Signature :: jose_curve448:maybe_invalid_signature(),
    Message :: jose_curve448:message(),
    PublicKey :: jose_curve448:eddsa_public_key()
) -> boolean().
ed448_verify(Signature, Message, PublicKey) ->
    libdecaf_curve448:ed448_verify(Signature, Message, PublicKey).

-spec ed448_verify(
    Signature :: jose_curve448:maybe_invalid_signature(),
    Message :: jose_curve448:message(),
    PublicKey :: jose_curve448:eddsa_public_key(),
    Context :: jose_curve448:context()
) -> boolean().
ed448_verify(Signature, Message, PublicKey, Context) ->
    libdecaf_curve448:ed448_verify(Signature, Message, PublicKey, Context).

% Ed448ph
-spec ed448ph_sign(Message :: jose_curve448:message(), SecretKey :: jose_curve448:eddsa_secret_key()) ->
    Signature :: jose_curve448:signature().
ed448ph_sign(Message, SecretKey) ->
    M = Message,
    C = <<>>,
    CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
    libdecaf_curve448:ed448ph_sign(CM, SecretKey).

-spec ed448ph_sign(
    Message :: jose_curve448:message(),
    SecretKey :: jose_curve448:eddsa_secret_key(),
    Context :: jose_curve448:context()
) ->
    Signature :: jose_curve448:signature().
ed448ph_sign(Message, SecretKey, Context) ->
    M = Message,
    C = Context,
    CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
    libdecaf_curve448:ed448ph_sign(CM, SecretKey, Context).

-spec ed448ph_verify(
    Signature :: jose_curve448:maybe_invalid_signature(),
    Message :: jose_curve448:message(),
    PublicKey :: jose_curve448:eddsa_public_key()
) -> boolean().
ed448ph_verify(Signature, Message, PublicKey) ->
    M = Message,
    C = <<>>,
    CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
    libdecaf_curve448:ed448ph_verify(Signature, CM, PublicKey).

-spec ed448ph_verify(
    Signature :: jose_curve448:maybe_invalid_signature(),
    Message :: jose_curve448:message(),
    PublicKey :: jose_curve448:eddsa_public_key(),
    Context :: jose_curve448:context()
) -> boolean().
ed448ph_verify(Signature, Message, PublicKey, Context) ->
    M = Message,
    C = Context,
    CM = <<"SigEd448", 16#02, (byte_size(C)):8/integer, C/binary, M/binary>>,
    libdecaf_curve448:ed448ph_verify(Signature, CM, PublicKey, Context).

% X448
-spec x448_keypair() -> {PublicKey :: jose_curve448:eddsa_public_key(), SecretKey :: jose_curve448:eddsa_secret_key()}.
x448_keypair() ->
    libdecaf_curve448:x448_keypair().

-spec x448_keypair(Seed :: jose_curve448:x448_seed()) ->
    {PublicKey :: jose_curve448:x448_public_key(), SecretKey :: jose_curve448:x448_secret_key()}.
x448_keypair(Seed) ->
    libdecaf_curve448:x448_keypair(Seed).

-spec x448_secret_to_public(SecretKey :: jose_curve448:x448_secret_key()) ->
    PublicKey :: jose_curve448:x448_public_key().
x448_secret_to_public(SecretKey) ->
    libdecaf_curve448:x448(SecretKey).

-spec x448_shared_secret(
    MySecretKey :: jose_curve448:x448_secret_key(), YourPublicKey :: jose_curve448:x448_public_key()
) -> SharedSecret :: jose_curve448:x448_shared_secret().
x448_shared_secret(MySecretKey, YourPublicKey) ->
    libdecaf_curve448:x448(MySecretKey, YourPublicKey).
