%%% % @format
%%%-------------------------------------------------------------------
%%% @author Brett Beatty <brettbeatty@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett, 2021, Brett Beatty
%%% @doc
%%%
%%% @end
%%% Created :  22 Oct 2021 by Brett Beatty <brettbeatty@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_curve448_crypto).

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

%%====================================================================
%% jose_provider callbacks
%%====================================================================

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

ed448_verify(Signature, Message, <<PublicKey:57/binary>>) ->
    crypto:verify(eddsa, none, Message, Signature, [PublicKey, ed448]).

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
