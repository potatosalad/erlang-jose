%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_zip_props).

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

enc() ->
	oneof([
		<<"A128GCM">>,
		<<"A192GCM">>,
		<<"A256GCM">>,
		<<"C20P">>,
		<<"XC20P">>
	]).

jwk_jwe_maps() ->
	?LET(ENC,
		enc(),
		begin
			FakeJWEMap = #{ <<"alg">> => <<"RSA1_5">>, <<"enc">> => ENC },
			FakeJWE = jose_jwe:from_map(FakeJWEMap),
			{Key, _} = jose_jwe:next_cek(undefined, FakeJWE),
			JWKMap = #{
				<<"kty">> => <<"oct">>,
				<<"k">> => jose_jwa_base64url:encode(Key)
			},
			JWEMap = #{
				<<"alg">> => <<"dir">>,
				<<"enc">> => ENC,
				<<"zip">> => <<"DEF">>
			},
			{Key, JWKMap, JWEMap}
		end).

jwk_jwe_gen() ->
	?LET({Key, JWKMap, JWEMap},
		jwk_jwe_maps(),
		{Key, jose_jwk:from_map(JWKMap), jose_jwe:from_map(JWEMap)}).

prop_ghsa_wfpv_qxp8_x5gm() ->
	?FORALL({ZipSizeMaximum, Slack},
		{range(1, 4096), range(1, 4096)},
		begin
			OriginalZipSizeMaximum = jose:zip_size_maximum(),
			try jose:zip_size_maximum(ZipSizeMaximum) of
				ok ->
					%% A run of zero bytes is the classic DEFLATE bomb: it
					%% compresses at roughly 1000:1, so `Greater` is a tiny
					%% input that must not be allowed to inflate past the cap.
					Maximum = binary:copy(<<0>>, ZipSizeMaximum),
					Greater = binary:copy(<<0>>, ZipSizeMaximum + Slack),
					MaximumCompressed = jose_jwe_zip:compress(Maximum, zlib),
					GreaterCompressed = jose_jwe_zip:compress(Greater, zlib),
					MaximumResult =
						try
							jose_jwe_zip:uncompress(MaximumCompressed, zlib)
						catch
							MaximumClass:MaximumReason ->
								{MaximumClass, MaximumReason}
						end,
					GreaterResult =
						try
							jose_jwe_zip:uncompress(GreaterCompressed, zlib)
						catch
							GreaterClass:GreaterReason ->
								{GreaterClass, GreaterReason}
						end,
					conjunction([
						{maximum_uncompress, Maximum =:= MaximumResult},
						{greater_uncompress, {error, badarg} =:= GreaterResult}
					])
			after
				ok = jose:zip_size_maximum(OriginalZipSizeMaximum)
			end
		end).

prop_from_map_and_to_map() ->
	?FORALL(JWEMap,
		?LET({{_Key, _JWKMap, JWEMap}, Extras},
			{jwk_jwe_maps(), binary_map()},
			maps:merge(Extras, JWEMap)),
		begin
			JWE = jose_jwe:from_map(JWEMap),
			JWEMap =:= element(2, jose_jwe:to_map(JWE))
		end).

prop_block_encrypt_and_block_decrypt() ->
	?FORALL({CEK, IV, JWK, JWE, PlainText},
		?LET({CEK, JWK, JWE},
			jwk_jwe_gen(),
			{CEK, jose_jwe:next_iv(JWE), JWK, JWE, binary()}),
		begin
			Encrypted = jose_jwe:block_encrypt(JWK, PlainText, CEK, IV, JWE),
			CompactEncrypted = jose_jwe:compact(Encrypted),
			PlainText =:= element(1, jose_jwe:block_decrypt(JWK, CompactEncrypted))
		end).

prop_compress_and_uncompress() ->
	?FORALL({{_CEK, _JWK, JWE}, PlainText},
		{jwk_jwe_gen(), binary()},
		begin
			CipherText = jose_jwe:compress(PlainText, JWE),
			CipherText =/= PlainText andalso PlainText =:= jose_jwe:uncompress(CipherText, JWE)
		end).
