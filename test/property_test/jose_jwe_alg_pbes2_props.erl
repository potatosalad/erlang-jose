%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_alg_pbes2_props).

-include_lib("triq/include/triq.hrl").

-compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

alg() ->
	oneof([
		<<"PBES2-HS256+A128KW">>,
		<<"PBES2-HS384+A192KW">>,
		<<"PBES2-HS512+A256KW">>
	]).

alg_map() ->
	?LET({ALG, P2C, P2S},
		{alg(), int(1, 4096), binary()},
		#{
			<<"alg">> => ALG,
			<<"p2c">> => P2C,
			<<"p2s">> => base64url:encode(P2S)
		}).

enc() ->
	oneof([
		<<"A128GCM">>,
		<<"A192GCM">>,
		<<"A256GCM">>
	]).

jwk_jwe_maps() ->
	?LET({ALGMap, ENC, Password},
		{alg_map(), enc(), binary()},
		begin
			JWKMap = #{
				<<"kty">> => <<"oct">>,
				<<"k">> => base64url:encode(Password)
			},
			JWEMap = maps:merge(#{ <<"enc">> => ENC }, ALGMap),
			{Password, JWKMap, JWEMap}
		end).

jwk_jwe_gen() ->
	?LET({Key, JWKMap, JWEMap},
		jwk_jwe_maps(),
		{Key, jose_jwk:from_map(JWKMap), jose_jwe:from_map(JWEMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWEMap,
		?LET({{_Key, _JWKMap, JWEMap}, Extras},
			{jwk_jwe_maps(), binary_map()},
			maps:merge(Extras, JWEMap)),
		begin
			JWE = jose_jwe:from_map(JWEMap),
			JWEMap =:= element(2, jose_jwe:to_map(JWE))
		end).

prop_key_encrypt_and_key_decrypt() ->
	?FORALL({_Key, JWK, JWE},
		?LET({Key, JWK, JWE},
			jwk_jwe_gen(),
			{Key, oneof([Key, JWK]), JWE}),
		begin
			CEK = jose_jwe:next_cek(JWK, JWE),
			{EncKey, EncJWE} = jose_jwe:key_encrypt(JWK, CEK, JWE),
			CEK =:= jose_jwe:key_decrypt(JWK, EncKey, EncJWE)
		end).
