%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
-module(jose_jwa_curve25519_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

eddsa_secret() ->
    binary(32).

eddsa_keypair(Secret) ->
    {PK, SK} = jose_curve25519:eddsa_keypair(Secret),
    {SK, PK}.

x25519_secret() ->
    binary(32).

x25519_keypair(Secret) ->
    {PK, SK} = jose_curve25519:x25519_keypair(Secret),
    {SK, PK}.

eddsa_keypair_gen() ->
    ?LET(
        Secret,
        eddsa_secret(),
        eddsa_keypair(Secret)
    ).

prop_eddsa_secret_to_public() ->
    ?FORALL(
        {<<Secret:32/binary, _/binary>>, PK},
        eddsa_keypair_gen(),
        begin
            PK =:= jose_jwa_curve25519:eddsa_secret_to_public(Secret)
        end
    ).

prop_ed25519_sign_and_verify() ->
    ?FORALL(
        {{SK, PK}, M},
        {eddsa_keypair_gen(), binary()},
        begin
            S = jose_jwa_curve25519:ed25519_sign(M, SK),
            jose_jwa_curve25519:ed25519_verify(S, M, PK)
        end
    ).

prop_ed25519ph_sign_and_verify() ->
    ?FORALL(
        {{SK, PK}, M},
        {eddsa_keypair_gen(), binary()},
        begin
            S = jose_jwa_curve25519:ed25519ph_sign(M, SK),
            jose_jwa_curve25519:ed25519ph_verify(S, M, PK)
        end
    ).

x25519_keypair_gen() ->
    ?LET(
        Secret,
        x25519_secret(),
        x25519_keypair(Secret)
    ).

x25519_keypairs_gen() ->
    ?LET(
        {AliceSecret, BobSecret},
        {x25519_secret(), x25519_secret()},
        {x25519_keypair(AliceSecret), x25519_keypair(BobSecret)}
    ).

prop_x25519_secret_to_public() ->
    ?FORALL(
        {SK, PK},
        x25519_keypair_gen(),
        begin
            PK =:= jose_jwa_curve25519:x25519_secret_to_public(SK)
        end
    ).

prop_x25519_shared_secret() ->
    ?FORALL(
        {{AliceSK, AlicePK}, {BobSK, BobPK}},
        x25519_keypairs_gen(),
        begin
            K = jose_jwa_curve25519:x25519_shared_secret(AliceSK, BobPK),
            K =:= jose_jwa_curve25519:x25519_shared_secret(BobSK, AlicePK)
        end
    ).
