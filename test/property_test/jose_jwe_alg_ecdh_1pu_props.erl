%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
-module(jose_jwe_alg_ecdh_1pu_props).

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

alg() ->
    oneof([
        <<"ECDH-1PU">>,
        <<"ECDH-1PU+A128GCMKW">>,
        <<"ECDH-1PU+A192GCMKW">>,
        <<"ECDH-1PU+A256GCMKW">>,
        <<"ECDH-1PU+A128KW">>,
        <<"ECDH-1PU+A192KW">>,
        <<"ECDH-1PU+A256KW">>,
        <<"ECDH-1PU+C20PKW">>,
        <<"ECDH-1PU+XC20PKW">>
    ]).

alg_map() ->
    ?LET(
        {ALG, APU, APV},
        {alg(), binary(), binary()},
        #{
            <<"alg">> => ALG,
            <<"apu">> => jose_jwa_base64url:encode(APU),
            <<"apv">> => jose_jwa_base64url:encode(APV)
        }
    ).

ec_curve() ->
    oneof([
        secp256r1,
        secp384r1,
        secp521r1,
        x25519,
        x448
    ]).

% ec_curve() ->
% 	?SUCHTHAT(CurveId,
% 		oneof(crypto:ec_curves()),
% 		begin
% 			try pubkey_cert_records:namedCurves(CurveId) of
% 				Curve when is_tuple(Curve) ->
% 					true;
% 				_ ->
% 					false
% 			catch
% 				_:_ ->
% 					false
% 			end
% 		end).

% ec_keypair() ->
% 	?LET(CurveId,
% 		ec_curve(),
% 		ec_keypair(CurveId)).

ec_keypair(x25519) ->
    SecretJWK = jose_jwk:generate_key({okp, 'X25519'}),
    {_, SecretKey} = jose_jwk:to_key(SecretJWK),
    {_, PublicKey} = jose_jwk:to_public_key(SecretJWK),
    {SecretKey, PublicKey};
ec_keypair(x448) ->
    SecretJWK = jose_jwk:generate_key({okp, 'X448'}),
    {_, SecretKey} = jose_jwk:to_key(SecretJWK),
    {_, PublicKey} = jose_jwk:to_public_key(SecretJWK),
    {SecretKey, PublicKey};
ec_keypair(CurveId) ->
    ECPrivateKey =
        #'ECPrivateKey'{parameters = ECParameters, publicKey = Octets0} = public_key:generate_key(
            {namedCurve, pubkey_cert_records:namedCurves(CurveId)}
        ),
    Octets =
        case Octets0 of
            {_, Octets1} ->
                Octets1;
            _ ->
                Octets0
        end,
    ECPoint = #'ECPoint'{point = Octets},
    ECPublicKey = {ECPoint, ECParameters},
    {ECPrivateKey, ECPublicKey}.

enc() ->
    oneof([
        <<"A128GCM">>,
        <<"A192GCM">>,
        <<"A256GCM">>,
        <<"C20P">>,
        <<"XC20P">>
    ]).

jwk_jwe_maps() ->
    ?LET(
        {ALGMap, ENC, {VStaticSecret, VStaticPublic}, {UStaticSecret, UStaticPublic},
            {UEphemeralSecret, UEphemeralPublic}},
        ?LET(
            CurveId,
            ec_curve(),
            {alg_map(), enc(), ec_keypair(CurveId), ec_keypair(CurveId), ec_keypair(CurveId)}
        ),
        begin
            VStaticSecretKey = jose_jwk:from_key(VStaticSecret),
            VStaticPublicKey = jose_jwk:from_key(VStaticPublic),
            UStaticSecretKey = jose_jwk:from_key(UStaticSecret),
            UStaticPublicKey = jose_jwk:from_key(UStaticPublic),
            UEphemeralSecretKey = jose_jwk:from_key(UEphemeralSecret),
            UEphemeralPublicKey = jose_jwk:from_key(UEphemeralPublic),
            {_, UEphemeralPublicKeyMap} = jose_jwk:to_public_map(UEphemeralPublicKey),
            VBox = {UStaticPublicKey, VStaticSecretKey},
            UBox = {VStaticPublicKey, UStaticSecretKey, UEphemeralSecretKey},
            JWKs = {VBox, UBox},
            JWEMap = maps:merge(#{<<"enc">> => ENC, <<"epk">> => UEphemeralPublicKeyMap}, ALGMap),
            {JWKs, JWEMap}
        end
    ).

jwk_jwe_gen() ->
    ?LET(
        {JWKs, JWEMap},
        jwk_jwe_maps(),
        {JWKs, jose_jwe:from_map(JWEMap)}
    ).

prop_from_map_and_to_map() ->
    ?FORALL(
        JWEMap,
        ?LET(
            {{_JWKs, JWEMap}, Extras},
            {jwk_jwe_maps(), binary_map()},
            maps:merge(Extras, JWEMap)
        ),
        begin
            JWE = jose_jwe:from_map(JWEMap),
            JWEMap =:= element(2, jose_jwe:to_map(JWE))
        end
    ).

prop_key_encrypt_and_key_decrypt() ->
    ?FORALL(
        {{VBox, UBox}, JWE},
        jwk_jwe_gen(),
        begin
            {DecKey, DecJWE} = jose_jwe:next_cek(UBox, JWE),
            {EncKey, EncJWE} = jose_jwe:key_encrypt(UBox, DecKey, DecJWE),
            DecKey =:= jose_jwe:key_decrypt(VBox, EncKey, EncJWE)
        end
    ).
