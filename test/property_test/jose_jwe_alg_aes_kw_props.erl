%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
-module(jose_jwe_alg_aes_kw_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		jose_jwa_base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

key_size() -> oneof([128, 192, 256]).

key_gen() ->
	?LET(KeySize,
		key_size(),
		{KeySize, binary(KeySize div 8)}).

alg_map(128) ->
	oneof([
		#{ <<"alg">> => <<"A128KW">> },
		#{ <<"alg">> => <<"A128GCMKW">> }
	]);
alg_map(192) ->
	oneof([
		#{ <<"alg">> => <<"A192KW">> },
		#{ <<"alg">> => <<"A192GCMKW">> }
	]);
alg_map(256) ->
	oneof([
		#{ <<"alg">> => <<"A256KW">> },
		#{ <<"alg">> => <<"A256GCMKW">> }
	]).

aes_gcm_map(#{ <<"alg">> := << "A", _, _, _, "GCMKW" >> }) ->
	oneof([
		#{},
		#{ <<"iv">> => jose_jwa_base64url:encode(crypto:strong_rand_bytes(12)), <<"tag">> => jose_jwa_base64url:encode(crypto:strong_rand_bytes(8)) }
	]);
aes_gcm_map(_) ->
	#{}.

jwk_jwe_maps() ->
	?LET({KeySize, Key, ALGMap},
		?LET({KeySize, Key},
			key_gen(),
			{KeySize, Key, alg_map(KeySize)}),
		begin
			ENC = list_to_binary("A" ++ integer_to_list(KeySize) ++ "GCM"),
			JWKMap = #{
				<<"kty">> => <<"oct">>,
				<<"k">> => jose_jwa_base64url:encode(Key)
			},
			JWEMap = maps:merge(#{ <<"enc">> => ENC }, ALGMap),
			{Key, JWKMap, JWEMap}
		end).

jwk_jwe_gen() ->
	?LET({Key, JWKMap, JWEMap},
		jwk_jwe_maps(),
		{Key, jose_jwk:from_map(JWKMap), jose_jwe:from_map(JWEMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWEMap,
		?LET({JWEMap, GCMMap, Extras},
			?LET({_Key, _JWKMap, JWEMap},
				jwk_jwe_maps(),
				{JWEMap, aes_gcm_map(JWEMap), binary_map()}),
			maps:merge(maps:merge(Extras, GCMMap), JWEMap)),
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
			{DecKey, DecJWE} = jose_jwe:next_cek(JWK, JWE),
			{EncKey, EncJWE} = jose_jwe:key_encrypt(JWK, DecKey, DecJWE),
			DecKey =:= jose_jwe:key_decrypt(JWK, EncKey, EncJWE)
		end).
