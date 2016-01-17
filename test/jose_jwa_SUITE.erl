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
-export([curve25519/1]).
-export([curve448/1]).
-export([ed25519/1]).
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
-export([x25519/1]).
-export([x448/1]).

all() ->
	[
		constant_time_compare,
		{group, jose_jwa_aes},
		{group, jose_jwa_aes_kw},
		{group, jose_jwa_concat_kdf},
		{group, jose_jwa_curve25519},
		{group, jose_jwa_curve448},
		{group, jose_jwa_pkcs1},
		{group, jose_jwa_pkcs5},
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
			curve25519,
			ed25519,
			x25519
		]},
		{jose_jwa_curve448, [parallel], [
			curve448,
			% ed448,
			x448
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
	_ = application:ensure_all_started(cutkey),
	ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
	_ = application:stop(jose),
	ok.

init_per_group(jose_jwa_curve25519, Config) ->
	[
		{curve25519, [
			{
				31029842492115040904895560451863089656472772604678260265531221036453811406496,  % Input scalar
				34426434033919594451155107781188821651316167215306631574996226621102155684838,  % Input u-coordinate
				hexstr2lint("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552") % Output u-coordinate
			},
			{
				35156891815674817266734212754503633747128614016119564763269015315466259359304,  % Input scalar
				8883857351183929894090759386610649319417338800022198945255395922347792736741,   % Input u-coordinate
				hexstr2lint("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957") % Output u-coordinate
			}
		]},
		{ed25519, [
			{ % TEST 1
				hexstr2bin(
					"9d61b19deffd5a60ba844af492ec2cc4"
					"4449c5697b326919703bac031cae7f60"), % SECRET KEY
				hexstr2bin(
					"d75a980182b10ab7d54bfed3c964073a"
					"0ee172f3daa62325af021a68f707511a"), % PUBLIC KEY
				<<>>, % MESSAGE
				hexstr2bin(
					"e5564300c360ac729086e2cc806e828a"
					"84877f1eb8e5d974d873e06522490155"
					"5fb8821590a33bacc61e39701cf9b46b"
					"d25bf5f0595bbe24655141438e7a100b") % SIGNATURE
			},
			{ % TEST 2
				hexstr2bin(
					"4ccd089b28ff96da9db6c346ec114e0f"
					"5b8a319f35aba624da8cf6ed4fb8a6fb"), % SECRET KEY
				hexstr2bin(
					"3d4017c3e843895a92b70aa74d1b7ebc"
					"9c982ccf2ec4968cc0cd55f12af4660c"), % PUBLIC KEY
				hexstr2bin("72"), % MESSAGE
				hexstr2bin(
					"92a009a9f0d4cab8720e820b5f642540"
					"a2b27b5416503f8fb3762223ebdb69da"
					"085ac1e43e15996e458f3613d0f11d8c"
					"387b2eaeb4302aeeb00d291612bb0c00") % SIGNATURE
			},
			{ % TEST 3
				hexstr2bin(
					"c5aa8df43f9f837bedb7442f31dcb7b1"
					"66d38535076f094b85ce3a2e0b4458f7"), % SECRET KEY
				hexstr2bin(
					"fc51cd8e6218a1a38da47ed00230f058"
					"0816ed13ba3303ac5deb911548908025"), % PUBLIC KEY
				hexstr2bin("af82"), % MESSAGE
				hexstr2bin(
					"6291d657deec24024827e69c3abe01a3"
					"0ce548a284743a445e3680d7db5ac3ac"
					"18ff9b538d16f290ae67f760984dc659"
					"4a7c15e9716ed28dc027beceea1ec40a") % SIGNATURE
			},
			{ % TEST 1024
				hexstr2bin(
					"f5e5767cf153319517630f226876b86c"
					"8160cc583bc013744c6bf255f5cc0ee5"), % SECRET KEY
				hexstr2bin(
					"278117fc144c72340f67d0f2316e8386"
					"ceffbf2b2428c9c51fef7c597f1d426e"), % PUBLIC KEY
				hexstr2bin(
					"08b8b2b733424243760fe426a4b54908"
					"632110a66c2f6591eabd3345e3e4eb98"
					"fa6e264bf09efe12ee50f8f54e9f77b1"
					"e355f6c50544e23fb1433ddf73be84d8"
					"79de7c0046dc4996d9e773f4bc9efe57"
					"38829adb26c81b37c93a1b270b20329d"
					"658675fc6ea534e0810a4432826bf58c"
					"941efb65d57a338bbd2e26640f89ffbc"
					"1a858efcb8550ee3a5e1998bd177e93a"
					"7363c344fe6b199ee5d02e82d522c4fe"
					"ba15452f80288a821a579116ec6dad2b"
					"3b310da903401aa62100ab5d1a36553e"
					"06203b33890cc9b832f79ef80560ccb9"
					"a39ce767967ed628c6ad573cb116dbef"
					"efd75499da96bd68a8a97b928a8bbc10"
					"3b6621fcde2beca1231d206be6cd9ec7"
					"aff6f6c94fcd7204ed3455c68c83f4a4"
					"1da4af2b74ef5c53f1d8ac70bdcb7ed1"
					"85ce81bd84359d44254d95629e9855a9"
					"4a7c1958d1f8ada5d0532ed8a5aa3fb2"
					"d17ba70eb6248e594e1a2297acbbb39d"
					"502f1a8c6eb6f1ce22b3de1a1f40cc24"
					"554119a831a9aad6079cad88425de6bd"
					"e1a9187ebb6092cf67bf2b13fd65f270"
					"88d78b7e883c8759d2c4f5c65adb7553"
					"878ad575f9fad878e80a0c9ba63bcbcc"
					"2732e69485bbc9c90bfbd62481d9089b"
					"eccf80cfe2df16a2cf65bd92dd597b07"
					"07e0917af48bbb75fed413d238f5555a"
					"7a569d80c3414a8d0859dc65a46128ba"
					"b27af87a71314f318c782b23ebfe808b"
					"82b0ce26401d2e22f04d83d1255dc51a"
					"ddd3b75a2b1ae0784504df543af8969b"
					"e3ea7082ff7fc9888c144da2af58429e"
					"c96031dbcad3dad9af0dcbaaaf268cb8"
					"fcffead94f3c7ca495e056a9b47acdb7"
					"51fb73e666c6c655ade8297297d07ad1"
					"ba5e43f1bca32301651339e22904cc8c"
					"42f58c30c04aafdb038dda0847dd988d"
					"cda6f3bfd15c4b4c4525004aa06eeff8"
					"ca61783aacec57fb3d1f92b0fe2fd1a8"
					"5f6724517b65e614ad6808d6f6ee34df"
					"f7310fdc82aebfd904b01e1dc54b2927"
					"094b2db68d6f903b68401adebf5a7e08"
					"d78ff4ef5d63653a65040cf9bfd4aca7"
					"984a74d37145986780fc0b16ac451649"
					"de6188a7dbdf191f64b5fc5e2ab47b57"
					"f7f7276cd419c17a3ca8e1b939ae49e4"
					"88acba6b965610b5480109c8b17b80e1"
					"b7b750dfc7598d5d5011fd2dcc5600a3"
					"2ef5b52a1ecc820e308aa342721aac09"
					"43bf6686b64b2579376504ccc493d97e"
					"6aed3fb0f9cd71a43dd497f01f17c0e2"
					"cb3797aa2a2f256656168e6c496afc5f"
					"b93246f6b1116398a346f1a641f3b041"
					"e989f7914f90cc2c7fff357876e506b5"
					"0d334ba77c225bc307ba537152f3f161"
					"0e4eafe595f6d9d90d11faa933a15ef1"
					"369546868a7f3a45a96768d40fd9d034"
					"12c091c6315cf4fde7cb68606937380d"
					"b2eaaa707b4c4185c32eddcdd306705e"
					"4dc1ffc872eeee475a64dfac86aba41c"
					"0618983f8741c5ef68d3a101e8a3b8ca"
					"c60c905c15fc910840b94c00a0b9d0"), % MESSAGE
				hexstr2bin(
					"0aab4c900501b3e24d7cdf4663326a3a"
					"87df5e4843b2cbdb67cbf6e460fec350"
					"aa5371b1508f9f4528ecea23c436d94b"
					"5e8fcd4f681e30a6ac00a9704a188a03") % SIGNATURE
			}
		]},
		{x25519, [
			{
				hexstr2bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), % Alice's private key, f
				hexstr2bin("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), % Alice's public key, X25519(f, 9)
				hexstr2bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"), % Bob's private key, g
				hexstr2bin("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), % Bob's public key, X25519(g, 9)
				hexstr2bin("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")  % Their shared secret, K
			}
		]} | Config
	];
init_per_group(jose_jwa_curve448, Config) ->
	[
		{curve448, [
			{
				599189175373896402783756016145213256157230856085026129926891459468622403380588640249457727683869421921443004045221642549886377526240828, % Input scalar
				382239910814107330116229961234899377031416365240571325148346555922438025162094455820962429142971339584360034337310079791515452463053830, % Input u-coordinate
				hexstr2lint("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")          % Output u-coordinate
			},
			{
				633254335906970592779259481534862372382525155252028961056404001332122152890562527156973881968934311400345568203929409663925541994577184, % Input scalar
				622761797758325444462922068431234180649590390024811299761625153767228042600197997696167956134770744996690267634159427999832340166786063, % Input u-coordinate
				hexstr2lint("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")          % Output u-coordinate
			}
		]},
		{x448, [
			{
				hexstr2bin("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"), % Alice's private key, f
				hexstr2bin("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"), % Alice's public key, X448(f, 9)
				hexstr2bin("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"), % Bob's private key, g
				hexstr2bin("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"), % Bob's public key, X448(g, 9)
				hexstr2bin("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")  % Their shared secret, K
			}
		]} | Config
	];
init_per_group(_Group, Config) ->
	Config.

end_per_group(_Group, _Config) ->
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

curve25519(Config) ->
	Vectors = proplists:get_value(curve25519, Config),
	lists:foreach(fun curve25519_vector/1, Vectors).

ed25519(Config) ->
	Vectors = proplists:get_value(ed25519, Config),
	lists:foreach(fun ed25519_vector/1, Vectors).

x25519(Config) ->
	Vectors = proplists:get_value(x25519, Config),
	lists:foreach(fun x25519_vector/1, Vectors).

curve448(Config) ->
	Vectors = proplists:get_value(curve448, Config),
	lists:foreach(fun curve448_vector/1, Vectors).

x448(Config) ->
	Vectors = proplists:get_value(x448, Config),
	lists:foreach(fun x448_vector/1, Vectors).

%%%-------------------------------------------------------------------
%%% Vector functions
%%%-------------------------------------------------------------------

%% @private
curve25519_vector({InputK, InputU, OutputU}) ->
	case jose_jwa_x25519:curve25519(InputK, InputU) of
		OutputU ->
			ok;
		Other ->
			ct:fail({{jose_jwa_x25519, curve25519, [InputK, InputU]}, {expected, OutputU}, {got, Other}})
	end.

%% @private
curve448_vector({InputK, InputU, OutputU}) ->
	case jose_jwa_x448:curve448(InputK, InputU) of
		OutputU ->
			ok;
		Other ->
			ct:fail({{jose_jwa_x448, curve448, [InputK, InputU]}, {expected, OutputU}, {got, Other}})
	end.

%% @private
ed25519_vector({Secret, PK, Message, Signature}) ->
	case jose_jwa_ed25519:secret_to_pk(Secret) of
		PK ->
			ok;
		Other0 ->
			ct:fail({{jose_jwa_ed25519, secret_to_pk, [Secret]}, {expected, PK}, {got, Other0}})
	end,
	SK = << Secret/binary, PK/binary >>,
	case jose_jwa_ed25519:sign(Message, SK) of
		Signature ->
			ok;
		Other1 ->
			ct:fail({{jose_jwa_ed25519, sign, [Message, SK]}, {expected, Signature}, {got, Other1}})
	end,
	case jose_jwa_ed25519:verify(Signature, Message, PK) of
		true ->
			ok;
		Other2 ->
			ct:fail({{jose_jwa_ed25519, verify, [Signature, Message, PK]}, {expected, true}, {got, Other2}})
	end.

%% @private
x25519_vector({AliceSK, AlicePK, BobSK, BobPK, Shared}) ->
	case jose_jwa_x25519:x25519_base(AliceSK) of
		AlicePK ->
			ok;
		Other0 ->
			ct:fail({{jose_jwa_x25519, x25519_base, [AliceSK]}, {expected, AlicePK}, {got, Other0}})
	end,
	case jose_jwa_x25519:x25519_base(BobSK) of
		BobPK ->
			ok;
		Other1 ->
			ct:fail({{jose_jwa_x25519, x25519_base, [BobSK]}, {expected, BobPK}, {got, Other1}})
	end,
	case jose_jwa_x25519:x25519(AliceSK, BobPK) of
		Shared ->
			ok;
		Other2 ->
			ct:fail({{jose_jwa_x25519, x25519, [AliceSK, BobPK]}, {expected, Shared}, {got, Other2}})
	end,
	case jose_jwa_x25519:x25519(BobSK, AlicePK) of
		Shared ->
			ok;
		Other3 ->
			ct:fail({{jose_jwa_x25519, x25519, [BobSK, AlicePK]}, {expected, Shared}, {got, Other3}})
	end.

%% @private
x448_vector({AliceSK, AlicePK, BobSK, BobPK, Shared}) ->
	case jose_jwa_x448:x448_base(AliceSK) of
		AlicePK ->
			ok;
		Other0 ->
			ct:fail({{jose_jwa_x448, x448_base, [AliceSK]}, {expected, AlicePK}, {got, Other0}})
	end,
	case jose_jwa_x448:x448_base(BobSK) of
		BobPK ->
			ok;
		Other1 ->
			ct:fail({{jose_jwa_x448, x448_base, [BobSK]}, {expected, BobPK}, {got, Other1}})
	end,
	case jose_jwa_x448:x448(AliceSK, BobPK) of
		Shared ->
			ok;
		Other2 ->
			ct:fail({{jose_jwa_x448, x448, [AliceSK, BobPK]}, {expected, Shared}, {got, Other2}})
	end,
	case jose_jwa_x448:x448(BobSK, AlicePK) of
		Shared ->
			ok;
		Other3 ->
			ct:fail({{jose_jwa_x448, x448, [BobSK, AlicePK]}, {expected, Shared}, {got, Other3}})
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
hexstr2bin(S) ->
	list_to_binary(hexstr2list(S)).

%% @private
hexstr2lint(S) ->
	Bin = hexstr2bin(S),
	Size = byte_size(Bin),
	<< Int:Size/unsigned-little-integer-unit:8 >> = Bin,
	Int.

%% @private
hexstr2list([X,Y|T]) ->
	[mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
	[].

%% @private
mkint(C) when $0 =< C, C =< $9 ->
	C - $0;
mkint(C) when $A =< C, C =< $F ->
	C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
	C - $a + 10.
