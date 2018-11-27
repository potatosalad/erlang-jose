%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwk_kty_oct_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

jwk_map() ->
	?LET(Key,
		binary(),
		begin
			JWKMap = #{
				<<"kty">> => <<"oct">>,
				<<"k">> => base64url:encode(Key)
			},
			{Key, JWKMap}
		end).

jwk_map(KeySize) ->
	?LET(Key,
		binary(KeySize),
		begin
			JWKMap = #{
				<<"kty">> => <<"oct">>,
				<<"k">> => base64url:encode(Key)
			},
			{Key, JWKMap}
		end).

jwk_gen() ->
	?LET({Key, JWKMap},
		jwk_map(32),
		{Key, jose_jwk:from_map(JWKMap)}).

prop_from_map_and_to_map() ->
	?FORALL({Key, JWKMap},
		?LET({{Key, JWKMap}, Extras},
			{jwk_map(), binary_map()},
			{Key, maps:merge(Extras, JWKMap)}),
		begin
			JWK = jose_jwk:from_map(JWKMap),
			PublicJWK = jose_jwk:to_public(JWK),
			PublicThumbprint = jose_jwk:thumbprint(PublicJWK),
			JWKMap =:= element(2, jose_jwk:to_map(JWK))
			andalso Key =:= element(2, jose_jwk:to_key(JWK))
			andalso JWKMap =:= element(2, jose_jwk:to_public_map(JWK))
			andalso PublicThumbprint =:= jose_jwk:thumbprint(JWK)
		end).

prop_block_encrypt_and_block_decrypt() ->
	?FORALL({{_Key, JWK}, PlainText},
		{jwk_gen(), binary()},
		begin
			Encrypted = jose_jwk:block_encrypt(PlainText, JWK),
			CompactEncrypted = jose_jwe:compact(Encrypted),
			Decrypted = {_, JWE} = jose_jwk:block_decrypt(Encrypted, JWK),
			{PlainText, JWE} =:= Decrypted
			andalso {PlainText, JWE} =:= jose_jwk:block_decrypt(CompactEncrypted, JWK)
		end).

prop_sign_and_verify() ->
	?FORALL({_Key, JWK, Message},
		?LET({Key, JWK},
			jwk_gen(),
			{Key, JWK, binary()}),
		begin
			Signed = jose_jwk:sign(Message, JWK),
			CompactSigned = jose_jws:compact(Signed),
			Verified = {_, _, JWS} = jose_jwk:verify(Signed, JWK),
			{true, Message, JWS} =:= Verified
			andalso {true, Message, JWS} =:= jose_jwk:verify(CompactSigned, JWK)
		end).
