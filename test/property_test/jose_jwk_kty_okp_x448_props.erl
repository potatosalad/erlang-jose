%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
-module(jose_jwk_kty_okp_x448_props).

-include("jose_public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

base64url_binary() ->
    ?LET(
        Binary,
        binary(),
        jose_jwa_base64url:encode(Binary)
    ).

binary_map() ->
    ?LET(
        List,
        list({base64url_binary(), base64url_binary()}),
        maps:from_list(List)
    ).

x448_secret() ->
    binary(56).

x448_keypair(Secret) ->
    {PK, S} = jose_curve448:x448_keypair(Secret),
    PublicKey = #'jose_X448PublicKey'{publicKey = PK},
    SecretKey = #'jose_X448PrivateKey'{publicKey = PublicKey, privateKey = S},
    {SecretKey, PublicKey}.

jwk_map() ->
    ?LET(
        {AliceSecret, BobSecret},
        {x448_secret(), x448_secret()},
        begin
            AliceKeys = {AlicePrivateKey, _} = x448_keypair(AliceSecret),
            BobKeys = x448_keypair(BobSecret),
            AlicePrivateJWK = jose_jwk:from_key(AlicePrivateKey),
            {_, AlicePrivateJWKMap} = jose_jwk:to_map(AlicePrivateJWK),
            Keys = {AliceKeys, BobKeys},
            {Keys, AlicePrivateJWKMap}
        end
    ).

jwk_gen() ->
    ?LET(
        {Keys, AlicePrivateJWKMap},
        jwk_map(),
        {Keys, jose_jwk:from_map(AlicePrivateJWKMap)}
    ).

prop_from_der_and_to_der() ->
    ?FORALL(
        {_Keys, AlicePrivateJWK, Password},
        ?LET(
            {{Keys, AlicePrivateJWK}, Bytes},
            {jwk_gen(), binary()},
            {Keys, AlicePrivateJWK, jose_jwa_base64url:encode(Bytes)}
        ),
        begin
            AlicePrivateDER = element(2, jose_jwk:to_der(AlicePrivateJWK)),
            EncryptedAlicePrivateDER = element(2, jose_jwk:to_der(Password, AlicePrivateJWK)),
            AlicePublicJWK = jose_jwk:to_public(AlicePrivateJWK),
            AlicePublicDER = element(2, jose_jwk:to_der(AlicePublicJWK)),
            AlicePrivateJWK =:= jose_jwk:from_der(AlicePrivateDER) andalso
                AlicePrivateJWK =:= jose_jwk:from_der(Password, EncryptedAlicePrivateDER) andalso
                AlicePublicJWK =:= jose_jwk:from_der(AlicePublicDER)
        end
    ).

prop_from_map_and_to_map() ->
    ?FORALL(
        {{{AlicePrivateKey, AlicePublicKey}, _}, AlicePrivateJWKMap},
        ?LET(
            {{Keys, JWKMap}, Extras},
            {jwk_map(), binary_map()},
            {Keys, maps:merge(Extras, JWKMap)}
        ),
        begin
            AlicePrivateJWK = jose_jwk:from_map(AlicePrivateJWKMap),
            AlicePublicJWK = jose_jwk:to_public(AlicePrivateJWK),
            AlicePublicJWKMap = element(2, jose_jwk:to_map(AlicePublicJWK)),
            AlicePublicThumbprint = jose_jwk:thumbprint(AlicePublicJWK),
            AlicePrivateJWKMap =:= element(2, jose_jwk:to_map(AlicePrivateJWK)) andalso
                AlicePrivateKey =:= element(2, jose_jwk:to_key(AlicePrivateJWK)) andalso
                AlicePublicKey =:= element(2, jose_jwk:to_public_key(AlicePrivateJWK)) andalso
                AlicePublicJWKMap =:= element(2, jose_jwk:to_public_map(AlicePrivateJWK)) andalso
                AlicePublicThumbprint =:= jose_jwk:thumbprint(AlicePrivateJWK)
        end
    ).

prop_from_pem_and_to_pem() ->
    ?FORALL(
        {_Keys, AlicePrivateJWK, Password},
        ?LET(
            {{Keys, AlicePrivateJWK}, Bytes},
            {jwk_gen(), binary()},
            {Keys, AlicePrivateJWK, jose_jwa_base64url:encode(Bytes)}
        ),
        begin
            AlicePrivatePEM = element(2, jose_jwk:to_pem(AlicePrivateJWK)),
            EncryptedAlicePrivatePEM = element(2, jose_jwk:to_pem(Password, AlicePrivateJWK)),
            AlicePublicJWK = jose_jwk:to_public(AlicePrivateJWK),
            AlicePublicPEM = element(2, jose_jwk:to_pem(AlicePublicJWK)),
            EncryptedAlicePublicPEM = element(2, jose_jwk:to_pem(Password, AlicePublicJWK)),
            AlicePrivateJWK =:= jose_jwk:from_pem(AlicePrivatePEM) andalso
                AlicePrivateJWK =:= jose_jwk:from_pem(Password, EncryptedAlicePrivatePEM) andalso
                AlicePublicJWK =:= jose_jwk:from_pem(AlicePublicPEM) andalso
                AlicePublicJWK =:= jose_jwk:from_pem(Password, EncryptedAlicePublicPEM)
        end
    ).

prop_box_encrypt_and_box_decrypt() ->
    ?FORALL(
        {{{_, {BobPrivateKey, BobPublicKey}}, AlicePrivateJWK}, PlainText},
        {jwk_gen(), binary()},
        begin
            BobPrivateJWK = jose_jwk:from_key(BobPrivateKey),
            BobPublicJWK = jose_jwk:from_key(BobPublicKey),
            Encrypted = jose_jwk:box_encrypt_ecdh_es(PlainText, BobPublicJWK, AlicePrivateJWK),
            CompactEncrypted = jose_jwe:compact(Encrypted),
            Decrypted = {_, JWE} = jose_jwk:box_decrypt_ecdh_es(Encrypted, BobPrivateJWK),
            {PlainText, JWE} =:= Decrypted andalso
                {PlainText, JWE} =:= jose_jwk:block_decrypt(CompactEncrypted, BobPrivateJWK)
        end
    ).
