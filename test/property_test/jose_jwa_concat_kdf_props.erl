%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
-module(jose_jwa_concat_kdf_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

hash_fun() -> oneof([md5, sha, sha224, sha256, sha384, sha512, {hmac, md5, <<>>}, {hmac, sha, <<>>}, {hmac, sha224, <<>>}, {hmac, sha256, <<>>}, {hmac, sha384, <<>>}, {hmac, sha512, <<>>}]).

prop_kdf() ->
	?FORALL({Hash, Z, OtherInfo},
		{hash_fun(), binary(), {binary(), binary(), binary()}},
		begin
			DerivedKey = jose_jwa_concat_kdf:kdf(Hash, Z, OtherInfo),
			DerivedKey =:= jose_jwa_concat_kdf:kdf(Hash, Z, OtherInfo)
		end).

prop_kdf_keylen() ->
	?FORALL({Hash, Z, OtherInfo, KeyDataLen},
		{hash_fun(), binary(), {binary(), binary(), binary()}, integer(0, 1024)},
		begin
			DerivedKey = jose_jwa_concat_kdf:kdf(Hash, Z, OtherInfo, KeyDataLen),
			DerivedKey =:= jose_jwa_concat_kdf:kdf(Hash, Z, OtherInfo, KeyDataLen)
		end).
