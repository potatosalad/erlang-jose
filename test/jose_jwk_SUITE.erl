%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwk_SUITE).

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
-export([encrypt_and_decrypt/1]).
-export([kty_ec_from_map_and_to_map/1]).
-export([kty_ec_from_pem_and_to_pem/1]).
-export([kty_ec_box_encrypt_and_box_decrypt/1]).
-export([kty_ec_sign_and_verify/1]).
-export([kty_oct_from_map_and_to_map/1]).
-export([kty_oct_block_encrypt_and_block_decrypt/1]).
-export([kty_oct_sign_and_verify/1]).
-export([kty_rsa_from_map_and_to_map/1]).
-export([kty_rsa_from_pem_and_to_pem/1]).
-export([kty_rsa_block_encrypt_and_block_decrypt/1]).
-export([kty_rsa_sign_and_verify/1]).
-export([set_from_map_and_to_map/1]).

all() ->
	[
		{group, jose_jwk},
		{group, jose_jwk_kty_ec},
		{group, jose_jwk_kty_oct},
		{group, jose_jwk_kty_rsa},
		{group, jose_jwk_set}
	].

groups() ->
	[
		{jose_jwk, [parallel], [
			encrypt_and_decrypt
		]},
		{jose_jwk_kty_ec, [parallel], [
			kty_ec_from_map_and_to_map,
			kty_ec_from_pem_and_to_pem,
			kty_ec_box_encrypt_and_box_decrypt,
			kty_ec_sign_and_verify
		]},
		{jose_jwk_kty_oct, [parallel], [
			kty_oct_from_map_and_to_map,
			kty_oct_block_encrypt_and_block_decrypt,
			kty_oct_sign_and_verify
		]},
		{jose_jwk_kty_rsa, [parallel], [
			kty_rsa_from_map_and_to_map,
			kty_rsa_from_pem_and_to_pem,
			kty_rsa_block_encrypt_and_block_decrypt,
			kty_rsa_sign_and_verify
		]},
		{jose_jwk_set, [parallel], [
			set_from_map_and_to_map
		]}
	].

init_per_suite(Config) ->
	application:set_env(jose, crypto_fallback, true),
	application:set_env(jose, unsecured_signing, true),
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

encrypt_and_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_props:prop_encrypt_and_decrypt(),
		Config).

kty_ec_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_ec_props:prop_from_map_and_to_map(),
		Config).

kty_ec_from_pem_and_to_pem(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_ec_props:prop_from_pem_and_to_pem(),
		Config).

kty_ec_box_encrypt_and_box_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_ec_props:prop_box_encrypt_and_box_decrypt(),
		Config).

kty_ec_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_ec_props:prop_sign_and_verify(),
		Config).

kty_oct_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_oct_props:prop_from_map_and_to_map(),
		Config).

kty_oct_block_encrypt_and_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_oct_props:prop_block_encrypt_and_block_decrypt(),
		Config).

kty_oct_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_oct_props:prop_sign_and_verify(),
		Config).

kty_rsa_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_rsa_props:prop_from_map_and_to_map(),
		Config).

kty_rsa_from_pem_and_to_pem(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_rsa_props:prop_from_pem_and_to_pem(),
		Config).

kty_rsa_block_encrypt_and_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_rsa_props:prop_block_encrypt_and_block_decrypt(),
		Config).

kty_rsa_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_kty_rsa_props:prop_sign_and_verify(),
		Config).

set_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jwk_set_props:prop_from_map_and_to_map(),
		Config).
