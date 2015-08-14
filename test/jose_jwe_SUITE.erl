%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwe_SUITE).

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
-export([alg_aes_kw_from_map_and_to_map/1]).
-export([alg_aes_kw_key_encrypt_and_key_decrypt/1]).
-export([alg_dir_from_map_and_to_map/1]).
-export([alg_dir_key_decrypt/1]).
-export([alg_dir_key_encrypt/1]).
-export([alg_dir_next_cek/1]).
-export([alg_ecdh_es_from_map_and_to_map/1]).
-export([alg_ecdh_es_key_encrypt_and_key_decrypt/1]).
-export([alg_pbes2_from_map_and_to_map/1]).
-export([alg_pbes2_key_encrypt_and_key_decrypt/1]).
-export([alg_rsa_from_map_and_to_map/1]).
-export([alg_rsa_key_encrypt_and_key_decrypt/1]).
-export([enc_aes_from_map_and_to_map/1]).
-export([enc_aes_block_encrypt_and_block_decrypt/1]).
-export([zip_from_map_and_to_map/1]).
-export([zip_block_encrypt_and_block_decrypt/1]).
-export([zip_compress_and_uncompress/1]).

all() ->
	[
		{group, jose_jwe_alg_aes_kw},
		{group, jose_jwe_alg_dir},
		{group, jose_jwe_alg_ecdh_es},
		{group, jose_jwe_alg_pbes2},
		{group, jose_jwe_alg_rsa},
		{group, jose_jwe_enc_aes},
		{group, jose_jwe_zip}
	].

groups() ->
	[
		{jose_jwe_alg_aes_kw, [parallel], [
			alg_aes_kw_from_map_and_to_map,
			alg_aes_kw_key_encrypt_and_key_decrypt
		]},
		{jose_jwe_alg_dir, [parallel], [
			alg_dir_from_map_and_to_map,
			alg_dir_key_decrypt,
			alg_dir_key_encrypt,
			alg_dir_next_cek
		]},
		{jose_jwe_alg_ecdh_es, [parallel], [
			alg_ecdh_es_from_map_and_to_map,
			alg_ecdh_es_key_encrypt_and_key_decrypt
		]},
		{jose_jwe_alg_pbes2, [parallel], [
			alg_pbes2_from_map_and_to_map,
			alg_pbes2_key_encrypt_and_key_decrypt
		]},
		{jose_jwe_alg_rsa, [parallel], [
			alg_rsa_from_map_and_to_map,
			alg_rsa_key_encrypt_and_key_decrypt
		]},
		{jose_jwe_enc_aes, [parallel], [
			enc_aes_from_map_and_to_map,
			enc_aes_block_encrypt_and_block_decrypt
		]},
		{jose_jwe_zip, [parallel], [
			zip_from_map_and_to_map,
			zip_block_encrypt_and_block_decrypt,
			zip_compress_and_uncompress
		]}
	].

init_per_suite(Config) ->
	application:set_env(jose, crypto_fallback, true),
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

alg_aes_kw_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_aes_kw_props:prop_from_map_and_to_map(),
		Config).

alg_aes_kw_key_encrypt_and_key_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_aes_kw_props:prop_key_encrypt_and_key_decrypt(),
		Config).

alg_dir_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_dir_props:prop_from_map_and_to_map(),
		Config).

alg_dir_key_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_dir_props:prop_key_decrypt(),
		Config).

alg_dir_key_encrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_dir_props:prop_key_encrypt(),
		Config).

alg_dir_next_cek(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_dir_props:prop_next_cek(),
		Config).

alg_ecdh_es_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_ecdh_es_props:prop_from_map_and_to_map(),
		Config).

alg_ecdh_es_key_encrypt_and_key_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_ecdh_es_props:prop_key_encrypt_and_key_decrypt(),
		Config).

alg_pbes2_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_pbes2_props:prop_from_map_and_to_map(),
		Config).

alg_pbes2_key_encrypt_and_key_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_pbes2_props:prop_key_encrypt_and_key_decrypt(),
		Config).

alg_rsa_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_rsa_props:prop_from_map_and_to_map(),
		Config).

alg_rsa_key_encrypt_and_key_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_alg_rsa_props:prop_key_encrypt_and_key_decrypt(),
		Config).

enc_aes_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_enc_aes_props:prop_from_map_and_to_map(),
		Config).

enc_aes_block_encrypt_and_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_enc_aes_props:prop_block_encrypt_and_block_decrypt(),
		Config).

zip_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_zip_props:prop_from_map_and_to_map(),
		Config).

zip_block_encrypt_and_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_zip_props:prop_block_encrypt_and_block_decrypt(),
		Config).

zip_compress_and_uncompress(Config) ->
	ct_property_test:quickcheck(
		jose_jwe_zip_props:prop_compress_and_uncompress(),
		Config).
