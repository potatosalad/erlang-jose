%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("jose.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([aes_block_encrypt_and_block_decrypt/1]).
-export([concat_kdf/1]).
-export([concat_kdf_keylen/1]).
-export([constant_time_compare/1]).
-export([pkcs1_rsaes_oaep_encrypt_and_decrypt/1]).
-export([pkcs1_rsaes_oaep_encrypt_and_decrypt_with_label/1]).
-export([pkcs1_rsassa_pss_sign_and_verify/1]).
-export([pkcs1_rsassa_pss_sign_and_verify_with_salt/1]).
-export([pkcs5_pbkdf1/1]).
-export([pkcs5_pbkdf1_iterations/1]).
-export([pkcs5_pbkdf2/1]).
-export([pkcs5_pbkdf2_iterations/1]).
-export([pkcs5_pbkdf2_iterations_keylen/1]).
-export([pkcs7_pad_and_unpad/1]).

all() ->
	[
		constant_time_compare,
		{group, jose_jwa_aes},
		{group, jose_jwa_concat_kdf},
		{group, jose_jwa_pkcs1},
		{group, jose_jwa_pkcs5},
		{group, jose_jwa_pkcs7}
	].

groups() ->
	[
		{jose_jwa_aes, [parallel], [
			aes_block_encrypt_and_block_decrypt
		]},
		{jose_jwa_concat_kdf, [parallel], [
			concat_kdf,
			concat_kdf_keylen
		]},
		{jose_jwa_pkcs1, [parallel], [
			pkcs1_rsaes_oaep_encrypt_and_decrypt,
			pkcs1_rsaes_oaep_encrypt_and_decrypt_with_label,
			pkcs1_rsassa_pss_sign_and_verify,
			pkcs1_rsassa_pss_sign_and_verify_with_salt
		]},
		{jose_jwa_pkcs5, [parallel], [
			pkcs5_pbkdf1,
			pkcs5_pbkdf1_iterations,
			pkcs5_pbkdf2,
			pkcs5_pbkdf2_iterations,
			pkcs5_pbkdf2_iterations_keylen
		]},
		{jose_jwa_pkcs7, [parallel], [
			pkcs7_pad_and_unpad
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(jose),
	_ = application:ensure_all_started(cutkey),
	ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
	_ = application:stop(jose),
	ok.

init_per_group(_Group, Config) ->
	Config.

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

aes_block_encrypt_and_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_block_encrypt_and_block_decrypt(),
		Config).

concat_kdf(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_concat_kdf_props:prop_kdf(),
		Config).

concat_kdf_keylen(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_concat_kdf_props:prop_kdf_keylen(),
		Config).

constant_time_compare(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_props:prop_constant_time_compare(),
		Config).

pkcs1_rsaes_oaep_encrypt_and_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsaes_oaep_encrypt_and_decrypt(),
		Config).

pkcs1_rsaes_oaep_encrypt_and_decrypt_with_label(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsaes_oaep_encrypt_and_decrypt_with_label(),
		Config).

pkcs1_rsassa_pss_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsassa_pss_sign_and_verify(),
		Config).

pkcs1_rsassa_pss_sign_and_verify_with_salt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsassa_pss_sign_and_verify_with_salt(),
		Config).

pkcs5_pbkdf1(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs5_props:prop_pbkdf1(),
		Config).

pkcs5_pbkdf1_iterations(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs5_props:prop_pbkdf1_iterations(),
		Config).

pkcs5_pbkdf2(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs5_props:prop_pbkdf2(),
		Config).

pkcs5_pbkdf2_iterations(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs5_props:prop_pbkdf2_iterations(),
		Config).

pkcs5_pbkdf2_iterations_keylen(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs5_props:prop_pbkdf2_iterations_keylen(),
		Config).

pkcs7_pad_and_unpad(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs7_props:prop_pad_and_unpad(),
		Config).
