%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jws_SUITE).

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
-export([alg_ecdsa_from_map_and_to_map/1]).
-export([alg_ecdsa_sign_and_verify/1]).
-export([alg_ed25519_from_map_and_to_map/1]).
-export([alg_ed25519_sign_and_verify/1]).
-export([alg_ed25519ph_from_map_and_to_map/1]).
-export([alg_ed25519ph_sign_and_verify/1]).
-export([alg_ed448_from_map_and_to_map/1]).
-export([alg_ed448_sign_and_verify/1]).
-export([alg_ed448ph_from_map_and_to_map/1]).
-export([alg_ed448ph_sign_and_verify/1]).
-export([alg_hmac_from_map_and_to_map/1]).
-export([alg_hmac_sign_and_verify/1]).
-export([alg_none_from_map_and_to_map/1]).
-export([alg_none_sign_and_verify/1]).
-export([alg_rsa_pkcs1_v1_5_from_map_and_to_map/1]).
-export([alg_rsa_pkcs1_v1_5_sign_and_verify/1]).
-export([alg_rsa_pss_from_map_and_to_map/1]).
-export([alg_rsa_pss_sign_and_verify/1]).

all() ->
	[
		{group, jose_jws_alg_ecdsa},
		{group, jose_jws_alg_ed25519},
		{group, jose_jws_alg_ed25519ph},
		{group, jose_jws_alg_ed448},
		{group, jose_jws_alg_ed448ph},
		{group, jose_jws_alg_hmac},
		{group, jose_jws_alg_none},
		{group, jose_jws_alg_rsa_pkcs1_v1_5},
		{group, jose_jws_alg_rsa_pss}
	].

groups() ->
	[
		{jose_jws_alg_ecdsa, [parallel], [
			alg_ecdsa_from_map_and_to_map,
			alg_ecdsa_sign_and_verify
		]},
		{jose_jws_alg_ed25519, [parallel], [
			alg_ed25519_from_map_and_to_map,
			alg_ed25519_sign_and_verify
		]},
		{jose_jws_alg_ed25519ph, [parallel], [
			alg_ed25519ph_from_map_and_to_map,
			alg_ed25519ph_sign_and_verify
		]},
		{jose_jws_alg_ed448, [parallel], [
			alg_ed448_from_map_and_to_map,
			alg_ed448_sign_and_verify
		]},
		{jose_jws_alg_ed448ph, [parallel], [
			alg_ed448ph_from_map_and_to_map,
			alg_ed448ph_sign_and_verify
		]},
		{jose_jws_alg_hmac, [parallel], [
			alg_hmac_from_map_and_to_map,
			alg_hmac_sign_and_verify
		]},
		{jose_jws_alg_none, [parallel], [
			alg_none_from_map_and_to_map,
			alg_none_sign_and_verify
		]},
		{jose_jws_alg_rsa_pkcs1_v1_5, [parallel], [
			alg_rsa_pkcs1_v1_5_from_map_and_to_map,
			alg_rsa_pkcs1_v1_5_sign_and_verify
		]},
		{jose_jws_alg_rsa_pss, [parallel], [
			alg_rsa_pss_from_map_and_to_map,
			alg_rsa_pss_sign_and_verify
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

alg_ecdsa_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ecdsa_props:prop_from_map_and_to_map(),
		Config).

alg_ecdsa_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ecdsa_props:prop_sign_and_verify(),
		Config).

alg_ed25519_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed25519_props:prop_from_map_and_to_map(),
		Config).

alg_ed25519_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed25519_props:prop_sign_and_verify(),
		Config).

alg_ed25519ph_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed25519ph_props:prop_from_map_and_to_map(),
		Config).

alg_ed25519ph_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed25519ph_props:prop_sign_and_verify(),
		Config).

alg_ed448_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed448_props:prop_from_map_and_to_map(),
		Config).

alg_ed448_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed448_props:prop_sign_and_verify(),
		Config).

alg_ed448ph_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed448ph_props:prop_from_map_and_to_map(),
		Config).

alg_ed448ph_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_ed448ph_props:prop_sign_and_verify(),
		Config).

alg_hmac_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_hmac_props:prop_from_map_and_to_map(),
		Config).

alg_hmac_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_hmac_props:prop_sign_and_verify(),
		Config).

alg_none_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_none_props:prop_from_map_and_to_map(),
		Config).

alg_none_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_none_props:prop_sign_and_verify(),
		Config).

alg_rsa_pkcs1_v1_5_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_rsa_pkcs1_v1_5_props:prop_from_map_and_to_map(),
		Config).

alg_rsa_pkcs1_v1_5_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_rsa_pkcs1_v1_5_props:prop_sign_and_verify(),
		Config).

alg_rsa_pss_from_map_and_to_map(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_rsa_pss_props:prop_from_map_and_to_map(),
		Config).

alg_rsa_pss_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jws_alg_rsa_pss_props:prop_sign_and_verify(),
		Config).
