%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
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
-export([aes_cbc_block_encrypt_and_cbc_block_decrypt/1]).
-export([aes_cbc_block_encrypt_and_jwa_block_decrypt/1]).
-export([aes_jwa_block_encrypt_and_cbc_block_decrypt/1]).
-export([aes_jwa_block_encrypt_and_ecb_block_decrypt/1]).
-export([aes_jwa_block_encrypt_and_gcm_block_decrypt/1]).
-export([aes_ecb_block_encrypt_and_ecb_block_decrypt/1]).
-export([aes_ecb_block_encrypt_and_jwa_block_decrypt/1]).
-export([aes_gcm_block_encrypt_and_gcm_block_decrypt/1]).
-export([aes_gcm_block_encrypt_and_jwa_block_decrypt/1]).
-export([aes_kw_128_128/1]).
-export([aes_kw_128_192/1]).
-export([aes_kw_128_256/1]).
-export([aes_kw_192_192/1]).
-export([aes_kw_192_256/1]).
-export([aes_kw_256_256/1]).
-export([aes_kw_wrap_and_unwrap/1]).
-export([concat_kdf/1]).
-export([concat_kdf_keylen/1]).
-export([constant_time_compare/1]).
-export([curve25519_eddsa_secret_to_public/1]).
-export([curve448_eddsa_secret_to_public/1]).
-export([ed25519_sign_and_verify/1]).
-export([ed25519ph_sign_and_verify/1]).
-export([ed448_sign_and_verify/1]).
-export([ed448ph_sign_and_verify/1]).
-export([pkcs1_rsaes_oaep_encrypt_and_decrypt/1]).
-export([pkcs1_rsaes_oaep_encrypt_and_decrypt_with_label/1]).
-export([pkcs1_rsaes_pkcs1_encrypt_and_decrypt/1]).
-export([pkcs1_rsassa_pkcs1_sign_and_verify/1]).
-export([pkcs1_rsassa_pss_sign_and_verify/1]).
-export([pkcs1_rsassa_pss_sign_and_verify_with_salt/1]).
-export([pkcs5_pbkdf1/1]).
-export([pkcs5_pbkdf1_iterations/1]).
-export([pkcs5_pbkdf2/1]).
-export([pkcs5_pbkdf2_iterations/1]).
-export([pkcs5_pbkdf2_iterations_keylen/1]).
-export([pkcs7_pad_and_unpad/1]).
-export([x25519_secret_to_public/1]).
-export([x25519_shared_secret/1]).
-export([x448_secret_to_public/1]).
-export([x448_shared_secret/1]).

all() ->
	[
		constant_time_compare,
		{group, jose_jwa_aes},
		{group, jose_jwa_aes_kw},
		{group, jose_jwa_concat_kdf},
		{group, jose_jwa_curve25519},
		{group, jose_jwa_curve448},
		{group, jose_jwa_pkcs1},
		% {group, jose_jwa_pkcs5},
		{group, jose_jwa_pkcs7}
	].

groups() ->
	[
		{jose_jwa_aes, [parallel], [
			aes_cbc_block_encrypt_and_cbc_block_decrypt,
			aes_cbc_block_encrypt_and_jwa_block_decrypt,
			aes_jwa_block_encrypt_and_cbc_block_decrypt,
			aes_jwa_block_encrypt_and_ecb_block_decrypt,
			aes_jwa_block_encrypt_and_gcm_block_decrypt,
			aes_ecb_block_encrypt_and_ecb_block_decrypt,
			aes_ecb_block_encrypt_and_jwa_block_decrypt,
			aes_gcm_block_encrypt_and_gcm_block_decrypt,
			aes_gcm_block_encrypt_and_jwa_block_decrypt
		]},
		{jose_jwa_aes_kw, [parallel], [
			aes_kw_128_128,
			aes_kw_128_192,
			aes_kw_128_256,
			aes_kw_192_192,
			aes_kw_192_256,
			aes_kw_256_256,
			aes_kw_wrap_and_unwrap
		]},
		{jose_jwa_concat_kdf, [parallel], [
			concat_kdf,
			concat_kdf_keylen
		]},
		{jose_jwa_curve25519, [parallel], [
			curve25519_eddsa_secret_to_public,
			ed25519_sign_and_verify,
			ed25519ph_sign_and_verify,
			x25519_secret_to_public,
			x25519_shared_secret
		]},
		{jose_jwa_curve448, [parallel], [
			curve448_eddsa_secret_to_public,
			ed448_sign_and_verify,
			ed448ph_sign_and_verify,
			x448_secret_to_public,
			x448_shared_secret
		]},
		{jose_jwa_pkcs1, [parallel], [
			pkcs1_rsaes_oaep_encrypt_and_decrypt,
			pkcs1_rsaes_oaep_encrypt_and_decrypt_with_label,
			pkcs1_rsaes_pkcs1_encrypt_and_decrypt,
			pkcs1_rsassa_pkcs1_sign_and_verify,
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
	application:set_env(jose, crypto_fallback, true),
	application:set_env(jose, unsecured_signing, true),
	_ = application:ensure_all_started(jose),
	ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
	_ = application:stop(jose),
	ok.

init_per_group(Group, Config) ->
	jose_ct:start(Group, Config).

end_per_group(_Group, Config) ->
	jose_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

aes_cbc_block_encrypt_and_cbc_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_cbc_block_encrypt_and_cbc_block_decrypt(),
		Config).

aes_cbc_block_encrypt_and_jwa_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_cbc_block_encrypt_and_jwa_block_decrypt(),
		Config).

aes_jwa_block_encrypt_and_cbc_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_jwa_block_encrypt_and_cbc_block_decrypt(),
		Config).

aes_jwa_block_encrypt_and_ecb_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_jwa_block_encrypt_and_ecb_block_decrypt(),
		Config).

aes_jwa_block_encrypt_and_gcm_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_jwa_block_encrypt_and_gcm_block_decrypt(),
		Config).

aes_ecb_block_encrypt_and_ecb_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_ecb_block_encrypt_and_ecb_block_decrypt(),
		Config).

aes_ecb_block_encrypt_and_jwa_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_ecb_block_encrypt_and_jwa_block_decrypt(),
		Config).

aes_gcm_block_encrypt_and_gcm_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_gcm_block_encrypt_and_gcm_block_decrypt(),
		Config).

aes_gcm_block_encrypt_and_jwa_block_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_props:prop_gcm_block_encrypt_and_jwa_block_decrypt(),
		Config).

%% See [https://tools.ietf.org/html/rfc3394#section-4.1]
aes_kw_128_128(_Config) ->
	KEK = << 16#000102030405060708090A0B0C0D0E0F:1/unsigned-big-integer-unit:128 >>,
	KeyData = << 16#00112233445566778899AABBCCDDEEFF:1/unsigned-big-integer-unit:128 >>,
	CipherText = << 16#1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5:1/unsigned-big-integer-unit:192 >>,
	CipherText = jose_jwa_aes_kw:wrap(KeyData, KEK),
	KeyData = jose_jwa_aes_kw:unwrap(CipherText, KEK),
	true.

%% See [https://tools.ietf.org/html/rfc3394#section-4.2]
aes_kw_128_192(_Config) ->
	KEK = << 16#000102030405060708090A0B0C0D0E0F1011121314151617:1/unsigned-big-integer-unit:192 >>,
	KeyData = << 16#00112233445566778899AABBCCDDEEFF:1/unsigned-big-integer-unit:128 >>,
	CipherText = << 16#96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D:1/unsigned-big-integer-unit:192 >>,
	CipherText = jose_jwa_aes_kw:wrap(KeyData, KEK),
	KeyData = jose_jwa_aes_kw:unwrap(CipherText, KEK),
	true.

%% See [https://tools.ietf.org/html/rfc3394#section-4.3]
aes_kw_128_256(_Config) ->
	KEK = << 16#000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F:1/unsigned-big-integer-unit:256 >>,
	KeyData = << 16#00112233445566778899AABBCCDDEEFF:1/unsigned-big-integer-unit:128 >>,
	CipherText = << 16#64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7:1/unsigned-big-integer-unit:192 >>,
	CipherText = jose_jwa_aes_kw:wrap(KeyData, KEK),
	KeyData = jose_jwa_aes_kw:unwrap(CipherText, KEK),
	true.

%% See [https://tools.ietf.org/html/rfc3394#section-4.4]
aes_kw_192_192(_Config) ->
	KEK = << 16#000102030405060708090A0B0C0D0E0F1011121314151617:1/unsigned-big-integer-unit:192 >>,
	KeyData = << 16#00112233445566778899AABBCCDDEEFF0001020304050607:1/unsigned-big-integer-unit:192 >>,
	CipherText = << 16#031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2:1/unsigned-big-integer-unit:256 >>,
	CipherText = jose_jwa_aes_kw:wrap(KeyData, KEK),
	KeyData = jose_jwa_aes_kw:unwrap(CipherText, KEK),
	true.

%% See [https://tools.ietf.org/html/rfc3394#section-4.5]
aes_kw_192_256(_Config) ->
	KEK = << 16#000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F:1/unsigned-big-integer-unit:256 >>,
	KeyData = << 16#00112233445566778899AABBCCDDEEFF0001020304050607:1/unsigned-big-integer-unit:192 >>,
	CipherText = << 16#A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1:1/unsigned-big-integer-unit:256 >>,
	CipherText = jose_jwa_aes_kw:wrap(KeyData, KEK),
	KeyData = jose_jwa_aes_kw:unwrap(CipherText, KEK),
	true.

%% See [https://tools.ietf.org/html/rfc3394#section-4.6]
aes_kw_256_256(_Config) ->
	KEK = << 16#000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F:1/unsigned-big-integer-unit:256 >>,
	KeyData = << 16#00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F:1/unsigned-big-integer-unit:256 >>,
	CipherText = << 16#28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21:2/unsigned-big-integer-unit:160 >>,
	CipherText = jose_jwa_aes_kw:wrap(KeyData, KEK),
	KeyData = jose_jwa_aes_kw:unwrap(CipherText, KEK),
	true.

aes_kw_wrap_and_unwrap(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_aes_kw_props:prop_wrap_and_unwrap(),
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

curve25519_eddsa_secret_to_public(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve25519_props:prop_eddsa_secret_to_public(),
		Config).

curve448_eddsa_secret_to_public(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve448_props:prop_eddsa_secret_to_public(),
		Config).

ed25519_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve25519_props:prop_ed25519_sign_and_verify(),
		Config).

ed25519ph_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve25519_props:prop_ed25519ph_sign_and_verify(),
		Config).

ed448_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve448_props:prop_ed448_sign_and_verify(),
		Config).

ed448ph_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve448_props:prop_ed448ph_sign_and_verify(),
		Config).

pkcs1_rsaes_oaep_encrypt_and_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsaes_oaep_encrypt_and_decrypt(),
		Config).

pkcs1_rsaes_oaep_encrypt_and_decrypt_with_label(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsaes_oaep_encrypt_and_decrypt_with_label(),
		Config).

pkcs1_rsaes_pkcs1_encrypt_and_decrypt(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsaes_pkcs1_encrypt_and_decrypt(),
		Config).

pkcs1_rsassa_pkcs1_sign_and_verify(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_pkcs1_props:prop_rsassa_pkcs1_sign_and_verify(),
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

x25519_secret_to_public(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve25519_props:prop_x25519_secret_to_public(),
		Config).

x25519_shared_secret(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve25519_props:prop_x25519_shared_secret(),
		Config).

x448_secret_to_public(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve448_props:prop_x448_secret_to_public(),
		Config).

x448_shared_secret(Config) ->
	ct_property_test:quickcheck(
		jose_jwa_curve448_props:prop_x448_shared_secret(),
		Config).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
