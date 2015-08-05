%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_alg_dir_props).

-include_lib("triq/include/triq.hrl").

-compile(export_all).

binary_map() ->
	?LET(List,
		list({binary(), binary()}),
		maps:from_list(List)).

key_size() -> oneof([128, 192, 256]).

key_gen() ->
	?LET(KeySize,
		key_size(),
		{KeySize, binary(KeySize div 8)}).

jwk_jwe_maps() ->
	?LET({KeySize, Key},
		key_gen(),
		begin
			ALG = <<"dir">>,
			ENC = list_to_binary("A" ++ integer_to_list(KeySize) ++ "GCM"),
			JWKMap = #{
				<<"kty">> => <<"oct">>,
				<<"k">> => base64url:encode(Key)
			},
			JWEMap = #{
				<<"alg">> => ALG,
				<<"enc">> => ENC
			},
			{Key, JWKMap, JWEMap}
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

prop_key_decrypt() ->
	?FORALL({Key, JWK, JWE},
		?LET({Key, JWK, JWE},
			jwk_jwe_gen(),
			{Key, oneof([Key, JWK]), JWE}),
		begin
			CEK = jose_jwe:next_cek(JWK, JWE),
			Key =:= jose_jwe:key_decrypt(JWK, CEK, JWE)
		end).

prop_key_encrypt() ->
	?FORALL({_Key, JWK, JWE},
		?LET({Key, JWK, JWE},
			jwk_jwe_gen(),
			{Key, oneof([Key, JWK]), JWE}),
		begin
			CEK = jose_jwe:next_cek(JWK, JWE),
			{<<>>, JWE} =:= jose_jwe:key_encrypt(JWK, CEK, JWE)
		end).

prop_next_cek() ->
	?FORALL({Key, JWK, JWE},
		?LET({Key, JWK, JWE},
			jwk_jwe_gen(),
			{Key, oneof([Key, JWK]), JWE}),
		begin
			Key =:= jose_jwe:next_cek(JWK, JWE)
		end).
