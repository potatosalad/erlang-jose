%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
-module(jose_jwk_kty_rsa_props).

-include_lib("public_key/include/public_key.hrl").

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

% integer(256, 8192) | pos_integer().
modulus_size() -> integer(1024, 1280).
% pos_integer().
exponent_size() -> return(65537).

rsa_keypair(ModulusSize) ->
    ?LET(
        ExponentSize,
        exponent_size(),
        begin
            case public_key:generate_key({rsa, ModulusSize, ExponentSize}) of
                PrivateKey = #'RSAPrivateKey'{modulus = Modulus, publicExponent = PublicExponent} ->
                    {PrivateKey, #'RSAPublicKey'{modulus = Modulus, publicExponent = PublicExponent}}
            end
        end
    ).

jwk_map() ->
    ?LET(
        {_ModulusSize, Keys = {PrivateKey, _}},
        ?LET(
            ModulusSize,
            modulus_size(),
            {ModulusSize, rsa_keypair(ModulusSize)}
        ),
        begin
            PrivateJWK = jose_jwk:from_key(PrivateKey),
            PrivateJWKMap = element(2, jose_jwk:to_map(PrivateJWK)),
            {Keys, PrivateJWKMap}
        end
    ).

jwk_map_sfm_and_crt() ->
    ?LET(
        {Keys, PrivateJWKMapCRT},
        jwk_map(),
        begin
            PrivateJWKMapSFM = maps:without(
                [
                    <<"dp">>,
                    <<"dq">>,
                    <<"p">>,
                    <<"q">>,
                    <<"qi">>
                ],
                PrivateJWKMapCRT
            ),
            {Keys, PrivateJWKMapCRT, PrivateJWKMapSFM}
        end
    ).

jwk_gen() ->
    ?LET(
        {Keys, PrivateJWKMap},
        jwk_map(),
        {Keys, jose_jwk:from_map(PrivateJWKMap)}
    ).

prop_convert_sfm_to_crt() ->
    ?FORALL(
        {{PrivateKey, PublicKey}, PrivateJWKMapCRT, PrivateJWKMapSFM},
        ?LET(
            {{Keys, JWKMapCRT, JWKMapSFM}, Extras},
            {jwk_map_sfm_and_crt(), binary_map()},
            {Keys, maps:merge(Extras, JWKMapCRT), maps:merge(Extras, JWKMapSFM)}
        ),
        begin
            PrivateJWKCRT = jose_jwk:from_map(PrivateJWKMapCRT),
            PrivateJWKSFM = jose_jwk:from_map(PrivateJWKMapSFM),
            ThumbprintCRT = jose_jwk:thumbprint(PrivateJWKMapCRT),
            ThumbprintSFM = jose_jwk:thumbprint(PrivateJWKMapSFM),
            PrivateJWKCRT =:= PrivateJWKSFM andalso
                PrivateKey =:= element(2, jose_jwk:to_key(PrivateJWKCRT)) andalso
                PrivateKey =:= element(2, jose_jwk:to_key(PrivateJWKSFM)) andalso
                PublicKey =:= element(2, jose_jwk:to_public_key(PrivateJWKCRT)) andalso
                PublicKey =:= element(2, jose_jwk:to_public_key(PrivateJWKSFM)) andalso
                ThumbprintCRT =:= ThumbprintSFM
        end
    ).

prop_from_der_and_to_der() ->
    ?FORALL(
        {{_, PublicKey}, PrivateJWK, Password},
        ?LET(
            {{Keys, PrivateJWK}, Bytes},
            {jwk_gen(), binary()},
            {Keys, PrivateJWK, jose_jwa_base64url:encode(Bytes)}
        ),
        begin
            PublicJWK = jose_jwk:from_key(PublicKey),
            PublicDER = element(2, jose_jwk:to_der(PublicJWK)),
            PrivateDER = element(2, jose_jwk:to_der(PrivateJWK)),
            EncryptedPrivateDER = element(2, jose_jwk:to_der(Password, PrivateJWK)),
            PrivateJWK =:= jose_jwk:from_der(PrivateDER) andalso
                PrivateJWK =:= jose_jwk:from_der(Password, EncryptedPrivateDER) andalso
                PublicJWK =:= jose_jwk:from_der(PublicDER)
        end
    ).

prop_from_map_and_to_map() ->
    ?FORALL(
        {{PrivateKey, PublicKey}, PrivateJWKMap},
        ?LET(
            {{Keys, JWKMap}, Extras},
            {jwk_map(), binary_map()},
            {Keys, maps:merge(Extras, JWKMap)}
        ),
        begin
            PrivateJWK = jose_jwk:from_map(PrivateJWKMap),
            PublicJWK = jose_jwk:to_public(PrivateJWK),
            PublicJWKMap = element(2, jose_jwk:to_map(PublicJWK)),
            PublicThumbprint = jose_jwk:thumbprint(PublicJWK),
            PrivateJWKMap =:= element(2, jose_jwk:to_map(PrivateJWK)) andalso
                PrivateKey =:= element(2, jose_jwk:to_key(PrivateJWK)) andalso
                PublicKey =:= element(2, jose_jwk:to_public_key(PrivateJWK)) andalso
                PublicJWKMap =:= element(2, jose_jwk:to_public_map(PrivateJWK)) andalso
                PublicThumbprint =:= jose_jwk:thumbprint(PrivateJWK)
        end
    ).

prop_from_pem_and_to_pem() ->
    ?FORALL(
        {{_, PublicKey}, PrivateJWK, Password},
        ?LET(
            {{Keys, PrivateJWK}, Bytes},
            {jwk_gen(), binary()},
            {Keys, PrivateJWK, jose_jwa_base64url:encode(Bytes)}
        ),
        begin
            PublicJWK = jose_jwk:from_key(PublicKey),
            PublicPEM = element(2, jose_jwk:to_pem(PublicJWK)),
            EncryptedPublicPEM = element(2, jose_jwk:to_pem(Password, PublicJWK)),
            PrivatePEM = element(2, jose_jwk:to_pem(PrivateJWK)),
            EncryptedPrivatePEM = element(2, jose_jwk:to_pem(Password, PrivateJWK)),
            PrivateJWK =:= jose_jwk:from_pem(PrivatePEM) andalso
                PrivateJWK =:= jose_jwk:from_pem(Password, EncryptedPrivatePEM) andalso
                PublicJWK =:= jose_jwk:from_pem(PublicPEM) andalso
                PublicJWK =:= jose_jwk:from_pem(Password, EncryptedPublicPEM)
        end
    ).

prop_block_encrypt_and_block_decrypt() ->
    ?FORALL(
        {{{_, PublicKey}, PrivateJWK}, PlainText},
        {jwk_gen(), binary()},
        begin
            PublicJWK = jose_jwk:from_key(PublicKey),
            Encrypted = jose_jwk:block_encrypt(PlainText, PublicJWK),
            CompactEncrypted = jose_jwe:compact(Encrypted),
            Decrypted = {_, JWE} = jose_jwk:box_decrypt(Encrypted, PrivateJWK),
            {PlainText, JWE} =:= Decrypted andalso
                {PlainText, JWE} =:= jose_jwk:block_decrypt(CompactEncrypted, PrivateJWK)
        end
    ).

prop_sign_and_verify() ->
    ?FORALL(
        {_Keys, JWK, Message},
        ?LET(
            {Keys, JWK},
            jwk_gen(),
            {Keys, JWK, binary()}
        ),
        begin
            Signed = jose_jwk:sign(Message, JWK),
            CompactSigned = jose_jws:compact(Signed),
            Verified = {_, _, JWS} = jose_jwk:verify(Signed, JWK),
            {true, Message, JWS} =:= Verified andalso
                {true, Message, JWS} =:= jose_jwk:verify(CompactSigned, JWK)
        end
    ).
