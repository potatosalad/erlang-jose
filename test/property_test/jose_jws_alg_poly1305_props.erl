%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
-module(jose_jws_alg_poly1305_props).

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
    return(<<"Poly1305">>).

jwk_jws_maps() ->
    ?LET(
        {ALG, Key, Nonce},
        {alg(), binary(32), binary(12)},
        begin
            JWKMap = #{
                <<"kty">> => <<"oct">>,
                <<"k">> => jose_jwa_base64url:encode(Key)
            },
            JWSMap = #{
                <<"alg">> => ALG
            },
            NonceJWSMap = #{
                <<"alg">> => ALG,
                <<"nonce">> => jose_jwa_base64url:encode(Nonce)
            },
            {Key, JWKMap, JWSMap, NonceJWSMap}
        end
    ).

jwk_jws_gen() ->
    ?LET(
        {Key, JWKMap, JWSMap, NonceJWSMap},
        jwk_jws_maps(),
        {Key, jose_jwk:from_map(JWKMap), jose_jws:from_map(JWSMap), jose_jws:from_map(NonceJWSMap)}
    ).

prop_from_map_and_to_map() ->
    ?FORALL(
        {JWSMap, NonceJWSMap},
        ?LET(
            {{_Key, _JWKMap, JWSMap, NonceJWSMap}, Extras},
            {jwk_jws_maps(), binary_map()},
            {maps:merge(Extras, JWSMap), maps:merge(Extras, NonceJWSMap)}
        ),
        begin
            JWS = jose_jws:from_map(JWSMap),
            NonceJWS = jose_jws:from_map(NonceJWSMap),
            JWSMap == element(2, jose_jws:to_map(JWS)) andalso
                NonceJWSMap == element(2, jose_jws:to_map(NonceJWS))
        end
    ).

prop_sign_and_verify() ->
    ?FORALL(
        {{_Key, JWK, JWS, NonceJWS}, Message},
        {jwk_jws_gen(), binary()},
        begin
            NonceSigned = jose_jws:sign(JWK, Message, NonceJWS),
            NonceCompactSigned = jose_jws:compact(NonceSigned),
            Signed = jose_jws:sign(JWK, Message, JWS),
            CompactSigned = jose_jws:compact(Signed),
            {true, Message, NonceJWS} == jose_jws:verify(JWK, NonceSigned) andalso
                {true, Message, NonceJWS} == jose_jws:verify(JWK, NonceCompactSigned) andalso
                true == element(1, jose_jws:verify(JWK, Signed)) andalso
                true == element(1, jose_jws:verify(JWK, CompactSigned)) andalso
                JWS =/= element(3, jose_jws:verify(JWK, Signed)) andalso
                NonceJWS =/= element(3, jose_jws:verify(JWK, Signed))
        end
    ).
