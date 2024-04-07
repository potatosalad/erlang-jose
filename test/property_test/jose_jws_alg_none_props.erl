%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
-module(jose_jws_alg_none_props).

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

alg() -> return(<<"none">>).

jwk_jws_maps() ->
    ?LET(
        {ALG, Key},
        {alg(), binary()},
        begin
            JWKMap = #{
                <<"kty">> => <<"oct">>,
                <<"k">> => jose_jwa_base64url:encode(Key)
            },
            JWSMap = #{
                <<"alg">> => ALG
            },
            {Key, JWKMap, JWSMap}
        end
    ).

jwk_jws_gen() ->
    ?LET(
        {Key, JWKMap, JWSMap},
        jwk_jws_maps(),
        {Key, jose_jwk:from_map(JWKMap), jose_jws:from_map(JWSMap)}
    ).

prop_from_map_and_to_map() ->
    ?FORALL(
        JWSMap,
        ?LET(
            {{_Key, _JWKMap, JWSMap}, Extras},
            {jwk_jws_maps(), binary_map()},
            maps:merge(Extras, JWSMap)
        ),
        begin
            JWS = jose_jws:from_map(JWSMap),
            JWSMap =:= element(2, jose_jws:to_map(JWS))
        end
    ).

prop_sign_and_verify() ->
    ?FORALL(
        {{_Key, JWK, JWS}, Message},
        {jwk_jws_gen(), binary()},
        begin
            Signed = jose_jws:sign(JWK, Message, JWS),
            CompactSigned = jose_jws:compact(Signed),
            {true, Message, JWS} =:= jose_jws:verify(JWK, Signed) andalso
                {true, Message, JWS} =:= jose_jws:verify(JWK, CompactSigned)
        end
    ).
