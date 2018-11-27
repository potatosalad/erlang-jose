%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_pkcs5_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

hash_fun() -> oneof([md5, sha, sha224, sha256, sha384, sha512, {hmac, md5, <<>>}, {hmac, sha, <<>>}, {hmac, sha224, <<>>}, {hmac, sha256, <<>>}, {hmac, sha384, <<>>}, {hmac, sha512, <<>>}]).
mac_fun()  -> oneof([md5, sha, sha224, sha256, sha384, sha512, {hmac, md5}, {hmac, sha}, {hmac, sha224}, {hmac, sha256}, {hmac, sha384}, {hmac, sha512}]).

prop_pbkdf1() ->
	?FORALL({Hash, Password, Salt},
		{hash_fun(), binary(), binary()},
		begin
			{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf1(Hash, Password, Salt),
			DerivedKey =:= element(2, jose_jwa_pkcs5:pbkdf1(Hash, Password, Salt))
		end).

prop_pbkdf1_iterations() ->
	?FORALL({Hash, Password, Salt, Iterations},
		{hash_fun(), binary(), binary(), integer(1, 4096)},
		begin
			{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf1(Hash, Password, Salt, Iterations),
			DerivedKey =:= element(2, jose_jwa_pkcs5:pbkdf1(Hash, Password, Salt, Iterations))
		end).

prop_pbkdf2() ->
	?FORALL({Mac, Password, Salt},
		{mac_fun(), binary(), binary()},
		begin
			{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt),
			DerivedKey =:= element(2, jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt))
		end).

prop_pbkdf2_iterations() ->
	?FORALL({Mac, Password, Salt, Iterations},
		{mac_fun(), binary(), binary(), integer(1, 4096)},
		begin
			{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt, Iterations),
			DerivedKey =:= element(2, jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt, Iterations))
		end).

prop_pbkdf2_iterations_keylen() ->
	?FORALL({Mac, Password, Salt, Iterations, KeyLen},
		{mac_fun(), binary(), binary(), integer(1, 4096), integer(0, 128)},
		begin
			{ok, DerivedKey} = jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt, Iterations, KeyLen),
			DerivedKey =:= element(2, jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt, Iterations, KeyLen))
		end).
