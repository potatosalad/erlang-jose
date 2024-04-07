%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
-module(jose_jwt_props).

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

% ec_curve() ->
% 	oneof([
% 		secp256r1,
% 		secp384r1,
% 		secp521r1
% 	]).

% ec_keypair(CurveId) ->
% 	ECPrivateKey = #'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0} = public_key:generate_key({namedCurve, pubkey_cert_records:namedCurves(CurveId)}),
% 	Octets = case Octets0 of
% 		{_, Octets1} ->
% 			Octets1;
% 		_ ->
% 			Octets0
% 	end,
% 	ECPoint = #'ECPoint'{point=Octets},
% 	ECPublicKey = {ECPoint, ECParameters},
% 	{ECPrivateKey, ECPublicKey}.

% jwk_ec() ->
% 	?LET(CurveId,
% 		ec_curve(),
% 		begin
% 			{PrivateKey, PublicKey} = ec_keypair(CurveId),
% 			oneof([jose_jwk:from_key(PrivateKey), jose_jwk:from_key(PublicKey)])
% 		end).

jwk_hmac() ->
    ?LET(
        Key,
        binary(32),
        jose_jwk:from_map(#{
            <<"kty">> => <<"oct">>,
            <<"k">> => jose_jwa_base64url:encode(Key)
        })
    ).

jwk_rsa() ->
    ?LET(
        {_ModulusSize, {PrivateKey, _PublicKey}},
        ?LET(
            ModulusSize,
            modulus_size(),
            {ModulusSize, rsa_keypair(ModulusSize)}
        ),
        return(jose_jwk:from_key(PrivateKey))
    ).

jwk() ->
    frequency([
        {50, jwk_hmac()},
        {1, jwk_rsa()}
    ]).
% oneof([
% 	% jwk_ec(),
% 	jwk_hmac(),
% 	jwk_rsa()
% ]).

jwk_jwt() ->
    ?LET(
        {JWK, JWTMap},
        {jwk(), binary_map()},
        {JWK, jose_jwt:from_map(JWTMap)}
    ).

prop_from_map_and_to_map() ->
    ?FORALL(
        {_JWK, JWTMap},
        {jwk(), binary_map()},
        begin
            JWT = jose_jwt:from_map(JWTMap),
            JWTMap =:= element(2, jose_jwt:to_map(JWT))
        end
    ).

prop_encrypt_and_decrypt() ->
    ?FORALL(
        {JWK, JWT},
        jwk_jwt(),
        begin
            Encrypted = jose_jwt:encrypt(JWK, JWT),
            CompactEncrypted = jose_jwe:compact(Encrypted),
            Decrypted = {JWE, _} = jose_jwt:decrypt(JWK, Encrypted),
            {JWE, JWT} =:= Decrypted andalso
                {JWE, JWT} =:= jose_jwt:decrypt(JWK, CompactEncrypted)
        end
    ).

prop_sign_and_verify() ->
    ?FORALL(
        {JWK, JWT},
        jwk_jwt(),
        begin
            Signed = jose_jwt:sign(JWK, JWT),
            CompactSigned = jose_jws:compact(Signed),
            Verified = {_, _, JWS} = jose_jwt:verify(JWK, Signed),
            {true, JWT, JWS} =:= Verified andalso
                {true, JWT, JWS} =:= jose_jwt:verify(JWK, CompactSigned)
        end
    ).
