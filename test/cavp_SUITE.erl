%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  11 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(cavp_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([concatenation_kdf/1]).
-export([curve25519/1]).
-export([curve448/1]).
-export([ed25519/1]).
-export([ed25519ph/1]).
-export([ed448/1]).
-export([ed448ph/1]).
-export([emc_rsa_oaep_encrypt_and_decrypt/1]).
-export([emc_rsa_pss_sign_and_verify/1]).
-export([fips_aes_encrypt_and_decrypt/1]).
-export([fips_aes_gcm_encrypt_and_decrypt/1]).
-export([fips_aeskw_unwrap/1]).
-export([fips_aeskw_wrap/1]).
-export([fips_rsa_pss_sign/1]).
-export([fips_rsa_pss_verify/1]).
-export([fips_sha3/1]).
-export([pbkdf1/1]).
-export([pbkdf2/1]).
-export([pkcs7_pad_and_unpad/1]).
-export([x25519/1]).
-export([x448/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, '186-3rsatestvectors'},
		{group, 'aesmmt'},
		{group, 'curve25519'},
		{group, 'curve448'},
		{group, 'gcmtestvectors'},
		{group, 'KAT_AES'},
		{group, 'keccaktestvectors'},
		{group, 'kwtestvectors'},
		{group, 'nist-800-56A'},
		{group, 'pkcs-1v2-1-vec'},
		{group, 'pkcs-5'},
		{group, 'pkcs-7'}
	].

groups() ->
	[
		{'186-3rsatestvectors', [parallel], [
			fips_rsa_pss_sign,
			fips_rsa_pss_verify
		]},
		{'aesmmt', [], [
			fips_aes_encrypt_and_decrypt
		]},
		{'curve25519', [parallel], [
			curve25519,
			ed25519,
			ed25519ph,
			x25519
		]},
		{'curve448', [parallel], [
			curve448,
			ed448,
			ed448ph,
			x448
		]},
		{'gcmtestvectors', [], [
			fips_aes_gcm_encrypt_and_decrypt
		]},
		{'KAT_AES', [], [
			fips_aes_encrypt_and_decrypt
		]},
		{'keccaktestvectors', [], [
			fips_sha3
		]},
		{'kwtestvectors', [parallel], [
			fips_aeskw_unwrap,
			fips_aeskw_wrap
		]},
		{'nist-800-56A', [], [
			concatenation_kdf
		]},
		{'pkcs-1v2-1-vec', [parallel], [
			emc_rsa_oaep_encrypt_and_decrypt,
			emc_rsa_pss_sign_and_verify
		]},
		{'pkcs-5', [parallel], [
			pbkdf1,
			pbkdf2
		]},
		{'pkcs-7', [], [
			pkcs7_pad_and_unpad
		]}
	].

init_per_suite(Config) ->
	application:set_env(jose, crypto_fallback, true),
	application:set_env(jose, unsecured_signing, true),
	_ = application:ensure_all_started(jose),
	data_setup(Config).

end_per_suite(_Config) ->
	_ = application:stop(jose),
	ok.

init_per_group(G='186-3rsatestvectors', Config) ->
	SigGenFile = data_file("186-3rsatestvectors/SigGenPSS_186-3.txt", Config),
	SigVerFile = data_file("186-3rsatestvectors/SigVerPSS_186-3.rsp", Config),
	[{sig_gen_file, SigGenFile}, {sig_ver_file, SigVerFile} | jose_ct:start(G, Config)];
init_per_group(G='aesmmt', Config) ->
	Folder = data_file("aesmmt", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aes_files, Files} | jose_ct:start(G, Config)];
init_per_group(G='curve25519', Config) ->
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
			},
			{ % TEST SHA(abc)
				hexstr2bin(
					"833fe62409237b9d62ec77587520911e"
					"9a759cec1d19755b7da901b96dca3d42"), % SECRET KEY
				hexstr2bin(
					"ec172b93ad5e563bf4932c70e1245034"
					"c35467ef2efd4d64ebf819683467e2bf"), % PUBLIC KEY
				hexstr2bin(
					"ddaf35a193617abacc417349ae204131"
					"12e6fa4e89a97ea20a9eeee64b55d39a"
					"2192992a274fc1a836ba3c23a3feebbd"
					"454d4423643ce80e2a9ac94fa54ca49f"), % MESSAGE
				hexstr2bin(
					"dc2a4459e7369633a52b1bf277839a00"
					"201009a3efbf3ecb69bea2186c26b589"
					"09351fc9ac90b3ecfdfbc7c66431e030"
					"3dca179c138ac17ad9bef1177331a704") % SIGNATURE
			}
		]},
		{ed25519ph, [
			{ % TEST abc
				hexstr2bin(
					"833fe62409237b9d62ec77587520911e"
					"9a759cec1d19755b7da901b96dca3d42"), % SECRET KEY
				hexstr2bin(
					"ec172b93ad5e563bf4932c70e1245034"
					"c35467ef2efd4d64ebf819683467e2bf"), % PUBLIC KEY
				hexstr2bin("616263"), % MESSAGE
				hexstr2bin(
					"dc2a4459e7369633a52b1bf277839a00"
					"201009a3efbf3ecb69bea2186c26b589"
					"09351fc9ac90b3ecfdfbc7c66431e030"
					"3dca179c138ac17ad9bef1177331a704") % SIGNATURE
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
		]} | jose_ct:start(G, Config)
	];
init_per_group(G='curve448', Config) ->
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
		{ed448, [
			{ % Blank
				hexstr2bin(
					"6c82a562cb808d10d632be89c8513ebf"
					"6c929f34ddfa8c9f63c9960ef6e348a3"
					"528c8a3fcc2f044e39a3fc5b94492f8f"
					"032e7549a20098f95b"), % SECRET KEY
				hexstr2bin(
					"5fd7449b59b461fd2ce787ec616ad46a"
					"1da1342485a70e1f8a0ea75d80e96778"
					"edf124769b46c7061bd6783df1e50f6c"
					"d1fa1abeafe8256180"), % PUBLIC KEY
				<<>>, % MESSAGE
				hexstr2bin(
					"533a37f6bbe457251f023c0d88f976ae"
					"2dfb504a843e34d2074fd823d41a591f"
					"2b233f034f628281f2fd7a22ddd47d78"
					"28c59bd0a21bfd3980ff0d2028d4b18a"
					"9df63e006c5d1c2d345b925d8dc00b41"
					"04852db99ac5c7cdda8530a113a0f4db"
					"b61149f05a7363268c71d95808ff2e65"
					"2600") % SIGNATURE
			},
			{ % 1 octet
				hexstr2bin(
					"c4eab05d357007c632f3dbb48489924d"
					"552b08fe0c353a0d4a1f00acda2c463a"
					"fbea67c5e8d2877c5e3bc397a659949e"
					"f8021e954e0a12274e"), % SECRET KEY
				hexstr2bin(
					"43ba28f430cdff456ae531545f7ecd0a"
					"c834a55d9358c0372bfa0c6c6798c086"
					"6aea01eb00742802b8438ea4cb82169c"
					"235160627b4c3a9480"), % PUBLIC KEY
				hexstr2bin("03"), % MESSAGE
				hexstr2bin(
					"26b8f91727bd62897af15e41eb43c377"
					"efb9c610d48f2335cb0bd0087810f435"
					"2541b143c4b981b7e18f62de8ccdf633"
					"fc1bf037ab7cd779805e0dbcc0aae1cb"
					"cee1afb2e027df36bc04dcecbf154336"
					"c19f0af7e0a6472905e799f1953d2a0f"
					"f3348ab21aa4adafd1d234441cf807c0"
					"3a00") % SIGNATURE
			},
			{ % 1 octet (with context)
				hexstr2bin(
					"c4eab05d357007c632f3dbb48489924d"
					"552b08fe0c353a0d4a1f00acda2c463a"
					"fbea67c5e8d2877c5e3bc397a659949e"
					"f8021e954e0a12274e"), % SECRET KEY
				hexstr2bin(
					"43ba28f430cdff456ae531545f7ecd0a"
					"c834a55d9358c0372bfa0c6c6798c086"
					"6aea01eb00742802b8438ea4cb82169c"
					"235160627b4c3a9480"), % PUBLIC KEY
				hexstr2bin("03"), % MESSAGE
				hexstr2bin("666f6f"), % CONTEXT
				hexstr2bin(
					"d4f8f6131770dd46f40867d6fd5d5055"
					"de43541f8c5e35abbcd001b32a89f7d2"
					"151f7647f11d8ca2ae279fb842d60721"
					"7fce6e042f6815ea000c85741de5c8da"
					"1144a6a1aba7f96de42505d7a7298524"
					"fda538fccbbb754f578c1cad10d54d0d"
					"5428407e85dcbc98a49155c13764e66c"
					"3c00") % SIGNATURE
			},
			{ % 11 octets
				hexstr2bin(
					"cd23d24f714274e744343237b93290f5"
					"11f6425f98e64459ff203e8985083ffd"
					"f60500553abc0e05cd02184bdb89c4cc"
					"d67e187951267eb328"), % SECRET KEY
				hexstr2bin(
					"dcea9e78f35a1bf3499a831b10b86c90"
					"aac01cd84b67a0109b55a36e9328b1e3"
					"65fce161d71ce7131a543ea4cb5f7e9f"
					"1d8b00696447001400"), % PUBLIC KEY
				hexstr2bin("0c3e544074ec63b0265e0c"), % MESSAGE
				hexstr2bin(
					"1f0a8888ce25e8d458a21130879b840a"
					"9089d999aaba039eaf3e3afa090a09d3"
					"89dba82c4ff2ae8ac5cdfb7c55e94d5d"
					"961a29fe0109941e00b8dbdeea6d3b05"
					"1068df7254c0cdc129cbe62db2dc957d"
					"bb47b51fd3f213fb8698f064774250a5"
					"028961c9bf8ffd973fe5d5c206492b14"
					"0e00") % SIGNATURE
			},
			{ % 12 octets
				hexstr2bin(
					"258cdd4ada32ed9c9ff54e63756ae582"
					"fb8fab2ac721f2c8e676a72768513d93"
					"9f63dddb55609133f29adf86ec9929dc"
					"cb52c1c5fd2ff7e21b"), % SECRET KEY
				hexstr2bin(
					"3ba16da0c6f2cc1f30187740756f5e79"
					"8d6bc5fc015d7c63cc9510ee3fd44adc"
					"24d8e968b6e46e6f94d19b945361726b"
					"d75e149ef09817f580"), % PUBLIC KEY
				hexstr2bin("64a65f3cdedcdd66811e2915"), % MESSAGE
				hexstr2bin(
					"7eeeab7c4e50fb799b418ee5e3197ff6"
					"bf15d43a14c34389b59dd1a7b1b85b4a"
					"e90438aca634bea45e3a2695f1270f07"
					"fdcdf7c62b8efeaf00b45c2c96ba457e"
					"b1a8bf075a3db28e5c24f6b923ed4ad7"
					"47c3c9e03c7079efb87cb110d3a99861"
					"e72003cbae6d6b8b827e4e6c143064ff"
					"3c00") % SIGNATURE
			},
			{ % 13 octets
				hexstr2bin(
					"7ef4e84544236752fbb56b8f31a23a10"
					"e42814f5f55ca037cdcc11c64c9a3b29"
					"49c1bb60700314611732a6c2fea98eeb"
					"c0266a11a93970100e"), % SECRET KEY
				hexstr2bin(
					"b3da079b0aa493a5772029f0467baebe"
					"e5a8112d9d3a22532361da294f7bb381"
					"5c5dc59e176b4d9f381ca0938e13c6c0"
					"7b174be65dfa578e80"), % PUBLIC KEY
				hexstr2bin("64a65f3cdedcdd66811e2915e7"), % MESSAGE
				hexstr2bin(
					"6a12066f55331b6c22acd5d5bfc5d712"
					"28fbda80ae8dec26bdd306743c5027cb"
					"4890810c162c027468675ecf645a8317"
					"6c0d7323a2ccde2d80efe5a1268e8aca"
					"1d6fbc194d3f77c44986eb4ab4177919"
					"ad8bec33eb47bbb5fc6e28196fd1caf5"
					"6b4e7e0ba5519234d047155ac727a105"
					"3100") % SIGNATURE
			},
			{ % 64 octets
				hexstr2bin(
					"d65df341ad13e008567688baedda8e9d"
					"cdc17dc024974ea5b4227b6530e339bf"
					"f21f99e68ca6968f3cca6dfe0fb9f4fa"
					"b4fa135d5542ea3f01"), % SECRET KEY
				hexstr2bin(
					"df9705f58edbab802c7f8363cfe5560a"
					"b1c6132c20a9f1dd163483a26f8ac53a"
					"39d6808bf4a1dfbd261b099bb03b3fb5"
					"0906cb28bd8a081f00"), % PUBLIC KEY
				hexstr2bin(
					"bd0f6a3747cd561bdddf4640a332461a"
					"4a30a12a434cd0bf40d766d9c6d458e5"
					"512204a30c17d1f50b5079631f64eb31"
					"12182da3005835461113718d1a5ef944"), % MESSAGE
				hexstr2bin(
					"554bc2480860b49eab8532d2a533b7d5"
					"78ef473eeb58c98bb2d0e1ce488a98b1"
					"8dfde9b9b90775e67f47d4a1c3482058"
					"efc9f40d2ca033a0801b63d45b3b722e"
					"f552bad3b4ccb667da350192b61c508c"
					"f7b6b5adadc2c8d9a446ef003fb05cba"
					"5f30e88e36ec2703b349ca229c267083"
					"3900") % SIGNATURE
			},
			{ % 64 octets
				hexstr2bin(
					"d65df341ad13e008567688baedda8e9d"
					"cdc17dc024974ea5b4227b6530e339bf"
					"f21f99e68ca6968f3cca6dfe0fb9f4fa"
					"b4fa135d5542ea3f01"), % SECRET KEY
				hexstr2bin(
					"df9705f58edbab802c7f8363cfe5560a"
					"b1c6132c20a9f1dd163483a26f8ac53a"
					"39d6808bf4a1dfbd261b099bb03b3fb5"
					"0906cb28bd8a081f00"), % PUBLIC KEY
				hexstr2bin(
					"bd0f6a3747cd561bdddf4640a332461a"
					"4a30a12a434cd0bf40d766d9c6d458e5"
					"512204a30c17d1f50b5079631f64eb31"
					"12182da3005835461113718d1a5ef944"), % MESSAGE
				hexstr2bin(
					"554bc2480860b49eab8532d2a533b7d5"
					"78ef473eeb58c98bb2d0e1ce488a98b1"
					"8dfde9b9b90775e67f47d4a1c3482058"
					"efc9f40d2ca033a0801b63d45b3b722e"
					"f552bad3b4ccb667da350192b61c508c"
					"f7b6b5adadc2c8d9a446ef003fb05cba"
					"5f30e88e36ec2703b349ca229c267083"
					"3900") % SIGNATURE
			},
			{ % 256 octets
				hexstr2bin(
					"2ec5fe3c17045abdb136a5e6a913e32a"
					"b75ae68b53d2fc149b77e504132d3756"
					"9b7e766ba74a19bd6162343a21c8590a"
					"a9cebca9014c636df5"), % SECRET KEY
				hexstr2bin(
					"79756f014dcfe2079f5dd9e718be4171"
					"e2ef2486a08f25186f6bff43a9936b9b"
					"fe12402b08ae65798a3d81e22e9ec80e"
					"7690862ef3d4ed3a00"), % PUBLIC KEY
				hexstr2bin(
					"15777532b0bdd0d1389f636c5f6b9ba7"
					"34c90af572877e2d272dd078aa1e567c"
					"fa80e12928bb542330e8409f31745041"
					"07ecd5efac61ae7504dabe2a602ede89"
					"e5cca6257a7c77e27a702b3ae39fc769"
					"fc54f2395ae6a1178cab4738e543072f"
					"c1c177fe71e92e25bf03e4ecb72f47b6"
					"4d0465aaea4c7fad372536c8ba516a60"
					"39c3c2a39f0e4d832be432dfa9a706a6"
					"e5c7e19f397964ca4258002f7c0541b5"
					"90316dbc5622b6b2a6fe7a4abffd9610"
					"5eca76ea7b98816af0748c10df048ce0"
					"12d901015a51f189f3888145c03650aa"
					"23ce894c3bd889e030d565071c59f409"
					"a9981b51878fd6fc110624dcbcde0bf7"
					"a69ccce38fabdf86f3bef6044819de11"), % MESSAGE
				hexstr2bin(
					"c650ddbb0601c19ca11439e1640dd931"
					"f43c518ea5bea70d3dcde5f4191fe53f"
					"00cf966546b72bcc7d58be2b9badef28"
					"743954e3a44a23f880e8d4f1cfce2d7a"
					"61452d26da05896f0a50da66a239a8a1"
					"88b6d825b3305ad77b73fbac0836ecc6"
					"0987fd08527c1a8e80d5823e65cafe2a"
					"3d00") % SIGNATURE
			},
			{ % 1023 octets
				hexstr2bin(
					"872d093780f5d3730df7c212664b37b8"
					"a0f24f56810daa8382cd4fa3f77634ec"
					"44dc54f1c2ed9bea86fafb7632d8be19"
					"9ea165f5ad55dd9ce8"), % SECRET KEY
				hexstr2bin(
					"a81b2e8a70a5ac94ffdbcc9badfc3feb"
					"0801f258578bb114ad44ece1ec0e799d"
					"a08effb81c5d685c0c56f64eecaef8cd"
					"f11cc38737838cf400"), % PUBLIC KEY
				hexstr2bin(
					"6ddf802e1aae4986935f7f981ba3f035"
					"1d6273c0a0c22c9c0e8339168e675412"
					"a3debfaf435ed651558007db4384b650"
					"fcc07e3b586a27a4f7a00ac8a6fec2cd"
					"86ae4bf1570c41e6a40c931db27b2faa"
					"15a8cedd52cff7362c4e6e23daec0fbc"
					"3a79b6806e316efcc7b68119bf46bc76"
					"a26067a53f296dafdbdc11c77f7777e9"
					"72660cf4b6a9b369a6665f02e0cc9b6e"
					"dfad136b4fabe723d2813db3136cfde9"
					"b6d044322fee2947952e031b73ab5c60"
					"3349b307bdc27bc6cb8b8bbd7bd32321"
					"9b8033a581b59eadebb09b3c4f3d2277"
					"d4f0343624acc817804728b25ab79717"
					"2b4c5c21a22f9c7839d64300232eb66e"
					"53f31c723fa37fe387c7d3e50bdf9813"
					"a30e5bb12cf4cd930c40cfb4e1fc6225"
					"92a49588794494d56d24ea4b40c89fc0"
					"596cc9ebb961c8cb10adde976a5d602b"
					"1c3f85b9b9a001ed3c6a4d3b1437f520"
					"96cd1956d042a597d561a596ecd3d173"
					"5a8d570ea0ec27225a2c4aaff26306d1"
					"526c1af3ca6d9cf5a2c98f47e1c46db9"
					"a33234cfd4d81f2c98538a09ebe76998"
					"d0d8fd25997c7d255c6d66ece6fa56f1"
					"1144950f027795e653008f4bd7ca2dee"
					"85d8e90f3dc315130ce2a00375a318c7"
					"c3d97be2c8ce5b6db41a6254ff264fa6"
					"155baee3b0773c0f497c573f19bb4f42"
					"40281f0b1f4f7be857a4e59d416c06b4"
					"c50fa09e1810ddc6b1467baeac5a3668"
					"d11b6ecaa901440016f389f80acc4db9"
					"77025e7f5924388c7e340a732e554440"
					"e76570f8dd71b7d640b3450d1fd5f041"
					"0a18f9a3494f707c717b79b4bf75c984"
					"00b096b21653b5d217cf3565c9597456"
					"f70703497a078763829bc01bb1cbc8fa"
					"04eadc9a6e3f6699587a9e75c94e5bab"
					"0036e0b2e711392cff0047d0d6b05bd2"
					"a588bc109718954259f1d86678a579a3"
					"120f19cfb2963f177aeb70f2d4844826"
					"262e51b80271272068ef5b3856fa8535"
					"aa2a88b2d41f2a0e2fda7624c2850272"
					"ac4a2f561f8f2f7a318bfd5caf969614"
					"9e4ac824ad3460538fdc25421beec2cc"
					"6818162d06bbed0c40a387192349db67"
					"a118bada6cd5ab0140ee273204f628aa"
					"d1c135f770279a651e24d8c14d75a605"
					"9d76b96a6fd857def5e0b354b27ab937"
					"a5815d16b5fae407ff18222c6d1ed263"
					"be68c95f32d908bd895cd76207ae7264"
					"87567f9a67dad79abec316f683b17f2d"
					"02bf07e0ac8b5bc6162cf94697b3c27c"
					"d1fea49b27f23ba2901871962506520c"
					"392da8b6ad0d99f7013fbc06c2c17a56"
					"9500c8a7696481c1cd33e9b14e40b82e"
					"79a5f5db82571ba97bae3ad3e0479515"
					"bb0e2b0f3bfcd1fd33034efc6245eddd"
					"7ee2086ddae2600d8ca73e214e8c2b0b"
					"db2b047c6a464a562ed77b73d2d841c4"
					"b34973551257713b753632efba348169"
					"abc90a68f42611a40126d7cb21b58695"
					"568186f7e569d2ff0f9e745d0487dd2e"
					"b997cafc5abf9dd102e62ff66cba87"), % MESSAGE
				hexstr2bin(
					"e301345a41a39a4d72fff8df69c98075"
					"a0cc082b802fc9b2b6bc503f926b65bd"
					"df7f4c8f1cb49f6396afc8a70abe6d8a"
					"ef0db478d4c6b2970076c6a0484fe76d"
					"76b3a97625d79f1ce240e7c576750d29"
					"5528286f719b413de9ada3e8eb78ed57"
					"3603ce30d8bb761785dc30dbc320869e"
					"1a00") % SIGNATURE
			}
		]},
		{ed448ph, [
			{ % TEST abc
				hexstr2bin(
					"833fe62409237b9d62ec77587520911e"
					"9a759cec1d19755b7da901b96dca3d42"), % SECRET KEY
				hexstr2bin(
					"55ab69e205b6c7b344711f9576dfe48e"
					"963e39e03f0fc0374465ff6b7eaa1d7d"
					"0c95c1c36c1f4a7dc89e74fdd0dc9b34"
					"187e1ee702b303f000"), % PUBLIC KEY
				hexstr2bin("616263"), % MESSAGE
				hexstr2bin(
					"c61f474654ce82432a6cc5c43f295b49"
					"b5a8a256047f1edc09fe69588f75cc3b"
					"c8bee6eaf6dc52ecac585583780fa238"
					"2059416759a11d938079e3d0a7ed873d"
					"4f99cdde00a35a6698e9e1763071e698"
					"5eee73682dc91448b9058e31c1483719"
					"f44a0d59b7d398c82c6db48c32d60db2"
					"3e00") % SIGNATURE
			},
			{ % TEST abc (with context)
				hexstr2bin(
					"833fe62409237b9d62ec77587520911e"
					"9a759cec1d19755b7da901b96dca3d42"), % SECRET KEY
				hexstr2bin(
					"55ab69e205b6c7b344711f9576dfe48e"
					"963e39e03f0fc0374465ff6b7eaa1d7d"
					"0c95c1c36c1f4a7dc89e74fdd0dc9b34"
					"187e1ee702b303f000"), % PUBLIC KEY
				hexstr2bin("616263"), % MESSAGE
				hexstr2bin("666f6f"), % CONTEXT
				hexstr2bin(
					"b0820f1ea13b9118d41c59de9637e92d"
					"45878b88c72fc813a42468d90f2f323b"
					"130e3104c9fb4746fcace1b0454cffaa"
					"a420a405474fae5180f43b5d975e579c"
					"059ecece8c6cbbc621baf0586db0747f"
					"0b2a7728a6606dc86d0f157b5628e20d"
					"e93c98afa9d5b1d4b6ba6994690db4fc"
					"2f00") % SIGNATURE
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
		]} | jose_ct:start(G, Config)
	];
init_per_group(G='gcmtestvectors', Config) ->
	Folder = data_file("gcmtestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aes_gcm_files, Files}, {one_in, 10} | jose_ct:start(G, Config)];
init_per_group(G='KAT_AES', Config) ->
	Folder = data_file("KAT_AES", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aes_files, Files} | jose_ct:start(G, Config)];
init_per_group(G='keccaktestvectors', Config) ->
	Folder = data_file("keccaktestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{sha3_files, Files} | jose_ct:start(G, Config)];
init_per_group(G='kwtestvectors', Config) ->
	Folder = data_file("kwtestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aeskw_files, Files}, {one_in, 5} | jose_ct:start(G, Config)];
init_per_group(G='nist-800-56A', Config) ->
	Vectors = [
		%% See [https://tools.ietf.org/html/rfc7518#appendix-C]
		{sha256,
			<<158,86,217,29,129,113,53,211,114,131,66,131,191,132,38,156,251,49,110,163,218,128,106,72,246,218,167,121,140,254,144,196>>,
			{<<"A128GCM">>,
				<<"Alice">>,
				<<"Bob">>,
				<< 0, 0, 0, 128 >>,
				<<>>},
			128,
			<<86,170,141,234,248,35,109,32,92,34,40,205,113,167,16,26>>},
		%% See [https://bitbucket.org/b_c/jose4j/src/cb968fdb10bdef6ecedf279b030f9b3af59f5e8e/src/test/java/org/jose4j/jwe/kdf/ConcatKeyDerivationFunctionTest.java]
		{sha256,
			base64url:decode(<<"Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0">>),
			{<<"A256CBC-HS512">>,
				<<>>,
				<<>>,
				<< 0, 0, 2, 0 >>,
				<<>>},
			512,
			base64url:decode(<<"pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA">>)},
		{sha256,
			base64url:decode(<<"LfkHot2nGTVlmfxbgxQfMg">>),
			{<<"A128CBC-HS256">>,
				<<>>,
				<<>>,
				<< 0, 0, 1, 0 >>,
				<<>>},
			256,
			base64url:decode(<<"vphyobtvExGXF7TaOvAkx6CCjHQNYamP2ET8xkhTu-0">>)},
		{sha256,
			base64url:decode(<<"KSDnQpf2iurUsAbcuI4YH-FKfk2gecN6cWHTYlBzrd8">>),
			{<<"meh">>,
				<<"Alice">>,
				<<"Bob">>,
				<< 0, 0, 4, 0 >>,
				<<>>},
			1024,
			base64url:decode(<<"yRbmmZJpxv3H1aq3FgzESa453frljIaeMz6pt5rQZ4Q5Hs-4RYoFRXFh_qBsbTjlsj8JxIYTWj-cp5LKtgi1fBRsf_5yTEcLDv4pKH2fNxjbEOKuVVDWA1_Qv2IkEC0_QSi3lSSELcJaNX-hDG8occ7oQv-w8lg6lLJjg58kOes">>)},
		{sha256,
			base64url:decode(<<"zp9Hot2noTVlmfxbkXqfn1">>),
			{<<"A192CBC-HS384">>,
				<<>>,
				<<>>,
				<< 0, 0, 1, 128 >>,
				<<>>},
			384,
			base64url:decode(<<"SNOvl6h5iSYWJ_EhlnvK8o6om9iyR8HkKMQtQYGkYKkVY0HFMleoUm-H6-kLz8sW">>)}
	],
	[{vectors, Vectors} | jose_ct:start(G, Config)];
init_per_group(G='pkcs-1v2-1-vec', Config) ->
	OAEPVectFile = data_file("pkcs-1v2-1-vec/oaep-vect.txt", Config),
	PSSVectFile = data_file("pkcs-1v2-1-vec/pss-vect.txt", Config),
	[{oaep_vect_file, OAEPVectFile}, {pss_vect_file, PSSVectFile} | jose_ct:start(G, Config)];
init_per_group(G='pkcs-5', Config) ->
	PBKDF1Vectors = [
		%% See [https://github.com/erlang/otp/blob/OTP-18.0/lib/public_key/test/pbe_SUITE.erl]
		{sha,
			<<"password">>,
			<<16#78,16#57,16#8E,16#5A,16#5D,16#63,16#CB,16#06>>,
			1000,
			16,
			<<
				16#DC, 16#19, 16#84, 16#7E,
				16#05, 16#C6, 16#4D, 16#2F,
				16#AF, 16#10, 16#EB, 16#FB,
				16#4A, 16#3D, 16#2A, 16#20
			>>}
	],
	PBKDF2Vectors = [
		%% See [https://tools.ietf.org/html/rfc6070]
		{sha,
			<<"password">>,
			<<"salt">>,
			1,
			20,
			hex:hex_to_bin(<<"0c60c80f961f0e71f3a9b524af6012062fe037a6">>)},
		{sha,
			<<"password">>,
			<<"salt">>,
			2,
			20,
			hex:hex_to_bin(<<"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957">>)},
		{sha,
			<<"password">>,
			<<"salt">>,
			4096,
			20,
			hex:hex_to_bin(<<"4b007901b765489abead49d926f721d065a429c1">>)},
		{sha,
			<<"password">>,
			<<"salt">>,
			16777216,
			20,
			hex:hex_to_bin(<<"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984">>)},
		{sha,
			<<"passwordPASSWORDpassword">>,
			<<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,
			4096,
			25,
			hex:hex_to_bin(<<"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038">>)},
		{sha,
			<<"pass\0word">>,
			<<"sa\0lt">>,
			4096,
			16,
			hex:hex_to_bin(<<"56fa6aa75548099dcc37d7f03425e0c3">>)},
		%% See [http://stackoverflow.com/a/5136918/818187]
		{sha256,
			<<"password">>,
			<<"salt">>,
			1,
			32,
			hex:hex_to_bin(<<"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b">>)},
		{sha256,
			<<"password">>,
			<<"salt">>,
			2,
			32,
			hex:hex_to_bin(<<"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43">>)},
		{sha256,
			<<"password">>,
			<<"salt">>,
			4096,
			32,
			hex:hex_to_bin(<<"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a">>)},
		{sha256,
			<<"password">>,
			<<"salt">>,
			16777216,
			32,
			hex:hex_to_bin(<<"cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46">>)},
		{sha256,
			<<"passwordPASSWORDpassword">>,
			<<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,
			4096,
			40,
			hex:hex_to_bin(<<"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9">>)},
		{sha256,
			<<"pass\0word">>,
			<<"sa\0lt">>,
			4096,
			16,
			hex:hex_to_bin(<<"89b69d0516f829893c696226650a8687">>)}
	],
	[{pbkdf1_vectors, PBKDF1Vectors}, {pbkdf2_vectors, PBKDF2Vectors} | jose_ct:start(G, Config)];
init_per_group(G='pkcs-7', Config) ->
	Vectors = [begin
		{hex:hex_to_bin(K), hex:hex_to_bin(V)}
	end || {K, V} <- [
		{<<                                  >>, <<"10101010101010101010101010101010">>},
		{<<"00"                              >>, <<"000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f">>},
		{<<"0000"                            >>, <<"00000e0e0e0e0e0e0e0e0e0e0e0e0e0e">>},
		{<<"000000"                          >>, <<"0000000d0d0d0d0d0d0d0d0d0d0d0d0d">>},
		{<<"00000000"                        >>, <<"000000000c0c0c0c0c0c0c0c0c0c0c0c">>},
		{<<"0000000000"                      >>, <<"00000000000b0b0b0b0b0b0b0b0b0b0b">>},
		{<<"000000000000"                    >>, <<"0000000000000a0a0a0a0a0a0a0a0a0a">>},
		{<<"00000000000000"                  >>, <<"00000000000000090909090909090909">>},
		{<<"0000000000000000"                >>, <<"00000000000000000808080808080808">>},
		{<<"000000000000000000"              >>, <<"00000000000000000007070707070707">>},
		{<<"00000000000000000000"            >>, <<"00000000000000000000060606060606">>},
		{<<"0000000000000000000000"          >>, <<"00000000000000000000000505050505">>},
		{<<"000000000000000000000000"        >>, <<"00000000000000000000000004040404">>},
		{<<"00000000000000000000000000"      >>, <<"00000000000000000000000000030303">>},
		{<<"0000000000000000000000000000"    >>, <<"00000000000000000000000000000202">>},
		{<<"000000000000000000000000000000"  >>, <<"00000000000000000000000000000001">>},
		{<<"00000000000000000000000000000000">>, <<"0000000000000000000000000000000010101010101010101010101010101010">>}
	]],
	[{vectors, Vectors} | jose_ct:start(G, Config)].

end_per_group(_Group, Config) ->
	jose_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

concatenation_kdf(Config) ->
	Vectors = ?config(vectors, Config),
	concatenation_kdf(Vectors, Config).

curve25519(Config) ->
	Vectors = ?config(curve25519, Config),
	lists:foreach(fun curve25519_vector/1, Vectors).

curve448(Config) ->
	Vectors = ?config(curve448, Config),
	lists:foreach(fun curve448_vector/1, Vectors).

ed25519(Config) ->
	Vectors = ?config(ed25519, Config),
	lists:foreach(fun ed25519_vector/1, Vectors).

ed25519ph(Config) ->
	Vectors = ?config(ed25519ph, Config),
	lists:foreach(fun ed25519ph_vector/1, Vectors).

ed448(Config) ->
	Vectors = ?config(ed448, Config),
	lists:foreach(fun ed448_vector/1, Vectors).

ed448ph(Config) ->
	Vectors = ?config(ed448ph, Config),
	lists:foreach(fun ed448ph_vector/1, Vectors).

emc_rsa_oaep_encrypt_and_decrypt(Config) ->
	Vectors = emc_testvector:from_file(?config(oaep_vect_file, Config)),
	emc_rsa_oaep_encrypt_and_decrypt(Vectors, Config).

emc_rsa_pss_sign_and_verify(Config) ->
	Vectors = emc_testvector:from_file(?config(pss_vect_file, Config)),
	emc_rsa_pss_sign_and_verify(Vectors, Config).

fips_aes_encrypt_and_decrypt(Config) ->
	Files = ?config(aes_files, Config),
	lists:foldl(fun fips_aes_encrypt_and_decrypt/2, Config, Files).

fips_aes_gcm_encrypt_and_decrypt(Config) ->
	Files = ?config(aes_gcm_files, Config),
	lists:foldl(fun fips_aes_gcm_encrypt_and_decrypt/2, Config, Files).

fips_aeskw_unwrap(Config) ->
	Filter = fun(File) ->
		case filename:basename(File) of
			"KW_AD_" ++ _ ->
				true;
			_ ->
				false
		end
	end,
	Files = [File || File <- ?config(aeskw_files, Config), Filter(File)],
	lists:foldl(fun fips_aeskw_unwrap/2, Config, Files).

fips_aeskw_wrap(Config) ->
	Filter = fun(File) ->
		case filename:basename(File) of
			"KW_AE_" ++ _ ->
				true;
			_ ->
				false
		end
	end,
	Files = [File || File <- ?config(aeskw_files, Config), Filter(File)],
	lists:foldl(fun fips_aeskw_wrap/2, Config, Files).

fips_rsa_pss_sign(Config) ->
	Vectors = fips_testvector:from_file(?config(sig_gen_file, Config)),
	fips_rsa_pss_sign(Vectors, Config).

fips_rsa_pss_verify(Config) ->
	Vectors = fips_testvector:from_file(?config(sig_ver_file, Config)),
	fips_rsa_pss_verify(Vectors, Config).

fips_sha3(Config) ->
	Files = [File || File <- ?config(sha3_files, Config)],
	lists:foldl(fun fips_sha3/2, Config, Files).

pbkdf1(Config) ->
	Vectors = ?config(pbkdf1_vectors, Config),
	pbkdf1(Vectors, Config).

pbkdf2(Config) ->
	Vectors = ?config(pbkdf2_vectors, Config),
	pbkdf2(Vectors, Config).

pkcs7_pad_and_unpad(Config) ->
	Vectors = ?config(vectors, Config),
	pkcs7_pad_and_unpad(Vectors, Config).

x25519(Config) ->
	Vectors = ?config(x25519, Config),
	lists:foreach(fun x25519_vector/1, Vectors).

x448(Config) ->
	Vectors = ?config(x448, Config),
	lists:foreach(fun x448_vector/1, Vectors).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
concatenation_kdf([{Hash, Z, OtherInfo, KeyDataLen, DerivedKey} | Vectors], Config) ->
	case jose_jwa_concat_kdf:kdf(Hash, Z, OtherInfo, KeyDataLen) of
		DerivedKey ->
			concatenation_kdf(Vectors, Config);
		Other ->
			ct:fail({{jose_jwa_concat_kdf, kdf, [Hash, Z, OtherInfo, KeyDataLen]}, {expected, DerivedKey}, {got, Other}})
	end;
concatenation_kdf([], _Config) ->
	ok.

%% @private
curve25519_vector({InputK, InputU, OutputU}) ->
	?tv_ok(T0, jose_jwa_x25519, curve25519, [InputK, InputU], OutputU).

%% @private
curve448_vector({InputK, InputU, OutputU}) ->
	?tv_ok(T0, jose_jwa_x448, curve448, [InputK, InputU], OutputU).

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
data_setup(Config) ->
	lists:foldl(fun(F, C) ->
		data_setup(F, C)
	end, Config, [
		"186-3rsatestvectors.zip",
		"aesmmt.zip",
		"gcmtestvectors.zip",
		"KAT_AES.zip",
		"keccaktestvectors",
		"kwtestvectors.zip",
		"pkcs-1v2-1-vec.zip"
	]).

%% @private
data_setup(F = "186-3rsatestvectors.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("186-3rsatestvectors", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3rsatestvectors.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "SigGenPSS_186-3.txt"}) ->
			true;
		(#zip_file{name = "SigVerPSS_186-3.rsp"}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "SigGenPSS_186-3.txt", Filter),
	Config;
data_setup(F = "aesmmt.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("aesmmt", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmmt.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "CBC" ++ _}) ->
			true;
		(#zip_file{name = "ECB" ++ _}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "CBCMMT128.rsp", Filter),
	Config;
data_setup(F = "gcmtestvectors.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("gcmtestvectors", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip",
	ok = data_setup(Zip, Dir, URL),
	case filelib:is_file(filename:join([Dir, "gcmDecrypt128.rsp"])) of
		true ->
			ok;
		false ->
			{ok, FileList} = zip:unzip(Zip, [
				{cwd, Dir}
			]),
			_ = [begin
				file:change_mode(File, 8#00644)
			end || File <- FileList],
			ok
	end,
	Config;
data_setup(F = "KAT_AES.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("KAT_AES", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "CBC" ++ _}) ->
			true;
		(#zip_file{name = "ECB" ++ _}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "CBCGFSbox128.rsp", Filter),
	Config;
data_setup(F = "keccaktestvectors", Config) ->
	BaseURL = "https://raw.githubusercontent.com/gvanas/KeccakCodePackage/1893f17c8029d0e6423f1fa4de4d15f76b188a27/TestVectors/",
	Files = [
		"ShortMsgKAT_SHA3-224.txt",
		"ShortMsgKAT_SHA3-256.txt",
		"ShortMsgKAT_SHA3-384.txt",
		"ShortMsgKAT_SHA3-512.txt",
		"ShortMsgKAT_SHAKE128.txt",
		"ShortMsgKAT_SHAKE256.txt"
	],
	URLs = [BaseURL ++ File || File <- Files],
	Directory = data_file(F, Config),
	DataFiles = [data_file(filename:join(F, File), Config) || File <- Files],
	ok = data_setup_multiple(DataFiles, Directory, URLs),
	Config;
data_setup(F = "kwtestvectors.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("kwtestvectors", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/mac/kwtestvectors.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "KW_" ++ Name}) ->
			case lists:reverse(Name) of
				"txt.vni_" ++ _ ->
					false;
				_ ->
					true
			end;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "KW_AD_128.txt", Filter),
	Config;
data_setup(F = "pkcs-1v2-1-vec.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("pkcs-1v2-1-vec", Config),
	URL = "ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "oaep-vect.txt"}) ->
			true;
		(#zip_file{name = "pss-vect.txt"}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "oaep-vect.txt", Filter),
	Config.

%% @private
data_setup(Zip, Directory, URL) ->
	case filelib:is_file(Zip) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(URL, Zip)
	end,
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end,
	ok.

%% @private
data_setup(Zip, Dir, Check, Filter) ->
	case filelib:is_file(filename:join([Dir, Check])) of
		true ->
			ok;
		false ->
			Options = case is_function(Filter, 1) of
				false ->
					[{cwd, Dir}];
				true ->
					[{cwd, Dir}, {file_filter, Filter}]
			end,
			{ok, FileList} = zip:unzip(Zip, Options),
			_ = [begin
				file:change_mode(File, 8#00644)
			end || File <- FileList],
			ok
	end.

%% @private
data_setup_multiple([DataFile | DataFiles], Directory, [URL | URLs]) ->
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end,
	case filelib:is_file(DataFile) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(URL, DataFile)
	end,
	data_setup_multiple(DataFiles, Directory, URLs);
data_setup_multiple([], _Directory, []) ->
	ok.

%% @private
ed25519_vector({Secret, PK, Message, Signature}) ->
	SK = << Secret/binary, PK/binary >>,
	?tv_ok(T0, jose_jwa_curve25519, ed25519_secret_to_public, [Secret], PK),
	?tv_ok(T1, jose_jwa_curve25519, ed25519_sign, [Message, SK], Signature),
	?tv_ok(T2, jose_jwa_curve25519, ed25519_verify, [Signature, Message, PK], true).

%% @private
ed25519ph_vector({Secret, PK, Message, Signature}) ->
	SK = << Secret/binary, PK/binary >>,
	?tv_ok(T0, jose_jwa_curve25519, ed25519ph_secret_to_public, [Secret], PK),
	?tv_ok(T1, jose_jwa_curve25519, ed25519ph_sign, [Message, SK], Signature),
	?tv_ok(T2, jose_jwa_curve25519, ed25519ph_verify, [Signature, Message, PK], true).

%% @private
ed448_vector({Secret, PK, Message, Signature}) ->
	SK = << Secret/binary, PK/binary >>,
	?tv_ok(T0, jose_jwa_curve448, ed448_secret_to_public, [Secret], PK),
	?tv_ok(T1, jose_jwa_curve448, ed448_sign, [Message, SK], Signature),
	?tv_ok(T2, jose_jwa_curve448, ed448_verify, [Signature, Message, PK], true);
ed448_vector({Secret, PK, Message, Context, Signature}) ->
	SK = << Secret/binary, PK/binary >>,
	?tv_ok(T0, jose_jwa_curve448, ed448_secret_to_public, [Secret], PK),
	?tv_ok(T1, jose_jwa_curve448, ed448_sign, [{Context, Message}, SK], Signature),
	?tv_ok(T2, jose_jwa_curve448, ed448_verify, [Signature, {Context, Message}, PK], true).

%% @private
ed448ph_vector({Secret, PK, Message, Signature}) ->
	SK = << Secret/binary, PK/binary >>,
	?tv_ok(T0, jose_jwa_curve448, ed448ph_secret_to_public, [Secret], PK),
	?tv_ok(T1, jose_jwa_curve448, ed448ph_sign, [Message, SK], Signature),
	?tv_ok(T2, jose_jwa_curve448, ed448ph_verify, [Signature, Message, PK], true);
ed448ph_vector({Secret, PK, Message, Context, Signature}) ->
	SK = << Secret/binary, PK/binary >>,
	?tv_ok(T0, jose_jwa_curve448, ed448ph_secret_to_public, [Secret], PK),
	?tv_ok(T1, jose_jwa_curve448, ed448ph_sign, [{Context, Message}, SK], Signature),
	?tv_ok(T2, jose_jwa_curve448, ed448ph_verify, [Signature, {Context, Message}, PK], true).

%% @private
emc_rsa_oaep_encrypt_and_decrypt([
			divider,
			{example, Example},
			{component, <<"Components of the RSA Key Pair">>},
			{vector, {<<"RSA modulus n">>, N}},
			{vector, {<<"RSA public exponent e">>, E}},
			{vector, {<<"RSA private exponent d">>, D}},
			{vector, {<<"Prime p">>, P}},
			{vector, {<<"Prime q">>, Q}},
			{vector, {<<"p's CRT exponent dP">>, DP}},
			{vector, {<<"q's CRT exponent dQ">>, DQ}},
			{vector, {<<"CRT coefficient qInv">>, QI}}
			| Vectors
		], Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		version = 'two-prime',
		otherPrimeInfos = 'asn1_NOVALUE',
		privateExponent = crypto:bytes_to_integer(D),
		exponent1 = crypto:bytes_to_integer(DP),
		exponent2 = crypto:bytes_to_integer(DQ),
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q),
		coefficient = crypto:bytes_to_integer(QI)
	},
	RSAPublicKey = #'RSAPublicKey'{
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N)
	},
	io:format("~s", [Example]),
	emc_rsa_oaep_encrypt_and_decrypt(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
emc_rsa_oaep_encrypt_and_decrypt([divider], _Config) ->
	ok;
emc_rsa_oaep_encrypt_and_decrypt([], _Config) ->
	ok.

%% @private
emc_rsa_oaep_encrypt_and_decrypt([
			{component, Component},
			{vector, {<<"Message to be encrypted">>, Message}},
			{vector, {<<"Seed">>, Seed}},
			{vector, {<<"Encryption">>, Encryption}}
			| Vectors
		], {RSAPrivateKey, RSAPublicKey}, Config) ->
	io:format("\t~s", [Component]),
	HashFun = sha,
	Label = <<>>,
	case jose_jwa_pkcs1:rsaes_oaep_encrypt(HashFun, Message, Label, Seed, RSAPublicKey) of
		{ok, Encryption} ->
			ok;
		EncryptError ->
			ct:fail({{jose_jwa_pkcs1, rsaes_oaep_encrypt, [HashFun, Message, Label, Seed, RSAPublicKey]}, {expected, {ok, Encryption}}, {got, EncryptError}})
	end,
	case jose_jwa_pkcs1:rsaes_oaep_decrypt(HashFun, Encryption, Label, RSAPrivateKey) of
		Message ->
			emc_rsa_oaep_encrypt_and_decrypt(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
		DecryptError ->
			ct:fail({{jose_jwa_pkcs1, rsaes_oaep_decrypt, [HashFun, Encryption, Label, RSAPrivateKey]}, {expected, Message}, {got, DecryptError}})
	end;
emc_rsa_oaep_encrypt_and_decrypt(Vectors = [divider | _], _RSAKeyPair, Config) ->
	emc_rsa_oaep_encrypt_and_decrypt(Vectors, Config).

%% @private
emc_rsa_pss_sign_and_verify([
			divider,
			{example, Example},
			{component, <<"Components of the RSA Key Pair">>},
			{vector, {<<"RSA modulus n">>, N}},
			{vector, {<<"RSA public exponent e">>, E}},
			{vector, {<<"RSA private exponent d">>, D}},
			{vector, {<<"Prime p">>, P}},
			{vector, {<<"Prime q">>, Q}},
			{vector, {<<"p's CRT exponent dP">>, DP}},
			{vector, {<<"q's CRT exponent dQ">>, DQ}},
			{vector, {<<"CRT coefficient qInv">>, QI}}
			| Vectors
		], Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		version = 'two-prime',
		otherPrimeInfos = 'asn1_NOVALUE',
		privateExponent = crypto:bytes_to_integer(D),
		exponent1 = crypto:bytes_to_integer(DP),
		exponent2 = crypto:bytes_to_integer(DQ),
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q),
		coefficient = crypto:bytes_to_integer(QI)
	},
	RSAPublicKey = #'RSAPublicKey'{
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N)
	},
	io:format("~s", [Example]),
	emc_rsa_pss_sign_and_verify(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
emc_rsa_pss_sign_and_verify([divider], _Config) ->
	ok;
emc_rsa_pss_sign_and_verify([], _Config) ->
	ok.

%% @private
emc_rsa_pss_sign_and_verify([
			{component, Component},
			{vector, {<<"Message to be signed">>, Message}},
			{vector, {<<"Salt">>, Salt}},
			{vector, {<<"Signature">>, Signature}}
			| Vectors
		], {RSAPrivateKey, RSAPublicKey}, Config) ->
	io:format("\t~s", [Component]),
	HashFun = sha,
	case jose_jwa_pkcs1:rsassa_pss_sign(HashFun, Message, Salt, RSAPrivateKey) of
		{ok, Signature} ->
			ok;
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_sign, [HashFun, Message, Salt, RSAPrivateKey]}, {expected, {ok, Signature}}, {got, Other}})
	end,
	SaltLen = byte_size(Salt),
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Message, Signature, SaltLen, RSAPublicKey) of
		true ->
			emc_rsa_pss_sign_and_verify(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
		false ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Message, Signature, SaltLen, RSAPublicKey]}, {expected, true}, {got, false}})
	end;
emc_rsa_pss_sign_and_verify(Vectors = [divider | _], _RSAKeyPair, Config) ->
	emc_rsa_pss_sign_and_verify(Vectors, Config).

%% @private
fips_aes_encrypt_and_decrypt(File, Config) ->
	VectorsName = iolist_to_binary(filename:basename(File)),
	Algorithm = case VectorsName of
		<< "CBC", _/binary >> ->
			aes_cbc;
		<< "ECB", _/binary >> ->
			aes_ecb
	end,
	{Pos, 3} = binary:match(VectorsName, [<<"128">>, <<"192">>, <<"256">>]),
	Bits = binary_to_integer(binary:part(VectorsName, Pos, 3)),
	Cipher = {Algorithm, Bits},
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [VectorsName]),
	fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config).

%% @private
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tENCRYPT = ~w", [Count]),
	case jose_jwa_aes:block_encrypt(Cipher, Key, PlainText) of
		CipherText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		EncryptError ->
			ct:fail({{jose_jwa_aes, block_encrypt, [Cipher, Key, PlainText]}, {expected, CipherText}, {got, EncryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tDECRYPT = ~w", [Count]),
	case jose_jwa_aes:block_decrypt(Cipher, Key, CipherText) of
		PlainText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		DecryptError ->
			ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, CipherText]}, {expected, PlainText}, {got, DecryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tENCRYPT = ~w", [Count]),
	case jose_jwa_aes:block_encrypt(Cipher, Key, IV, PlainText) of
		CipherText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		EncryptError ->
			ct:fail({{jose_jwa_aes, block_encrypt, [Cipher, Key, IV, PlainText]}, {expected, CipherText}, {got, EncryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tDECRYPT = ~w", [Count]),
	case jose_jwa_aes:block_decrypt(Cipher, Key, IV, CipherText) of
		PlainText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		DecryptError ->
			ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, IV, CipherText]}, {expected, PlainText}, {got, DecryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{flag, Flag}
			| Vectors
		], Cipher, Config)
			when Flag =:= <<"DECRYPT">>
			orelse Flag =:= <<"ENCRYPT">> ->
	fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
fips_aes_encrypt_and_decrypt([], _Cipher, Config) ->
	Config.

%% @private
fips_aes_gcm_encrypt_and_decrypt(File, Config) ->
	VectorsName = iolist_to_binary(filename:basename(File)),
	{Algorithm, Mode} = case VectorsName of
		<< "gcmDecrypt", _/binary >> ->
			{aes_gcm, decrypt};
		<< "gcmEncrypt", _/binary >> ->
			{aes_gcm, encrypt}
	end,
	{Pos, 3} = binary:match(VectorsName, [<<"128">>, <<"192">>, <<"256">>]),
	Bits = binary_to_integer(binary:part(VectorsName, Pos, 3)),
	Cipher = {Algorithm, Bits},
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [VectorsName]),
	fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, undefined}, Config).

%% @private
fips_aes_gcm_encrypt_and_decrypt([
			{vector, {<<"Count">>, Count}, _},
			{vector, {<<"Key">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"CT">>, CT}, _},
			{vector, {<<"AAD">>, AAD}, _},
			{vector, {<<"Tag">>, Tag}, _},
			{token, <<"FAIL">>}
			| Vectors
		], {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, Counts}}, Config)
			when bit_size(Key) =:= Keylen
			andalso bit_size(IV) =:= IVlen
			andalso bit_size(CT) =:= PTlen
			andalso bit_size(AAD) =:= AADlen
			andalso bit_size(Tag) =:= Taglen ->
	case crypto:rand_uniform(0, ?config(one_in, Config)) of
		0 ->
			case jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, Tag}) of
				error ->
					fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config);
				OtherDecrypt ->
					io:format("\t\tCounts = ~s", [<< Counts/binary, (integer_to_binary(Count))/binary, "..." >>]),
					ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, IV, {AAD, CT, Tag}]}, {expected, error}, {got, OtherDecrypt}})
			end;
		_ ->
			fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config)
	end;
fips_aes_gcm_encrypt_and_decrypt([
			{vector, {<<"Count">>, Count}, _},
			{vector, {<<"Key">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"CT">>, CT}, _},
			{vector, {<<"AAD">>, AAD}, _},
			{vector, {<<"Tag">>, Tag}, _},
			{vector, {<<"PT">>, PT}, _}
			| Vectors
		], {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, Counts}}, Config)
			when bit_size(Key) =:= Keylen
			andalso bit_size(IV) =:= IVlen
			andalso bit_size(CT) =:= PTlen
			andalso bit_size(AAD) =:= AADlen
			andalso bit_size(Tag) =:= Taglen
			andalso bit_size(PT) =:= PTlen ->
	case crypto:rand_uniform(0, ?config(one_in, Config)) of
		0 ->
			case jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, Tag}) of
				PT ->
					fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config);
				OtherDecrypt ->
					io:format("\t\tCounts = ~s", [<< Counts/binary, (integer_to_binary(Count))/binary, "..." >>]),
					io:format("{Cipher, Key, IV, CT, AAD, Tag, PT} = ~w~n", [{Cipher, Key, IV, CT, AAD, Tag, PT}]),
					ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, IV, {AAD, CT, Tag}]}, {expected, PT}, {got, OtherDecrypt}})
			end;
		_ ->
			fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config)
	end;
fips_aes_gcm_encrypt_and_decrypt([
			{vector, {<<"Count">>, Count}, _},
			{vector, {<<"Key">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"PT">>, PT}, _},
			{vector, {<<"AAD">>, AAD}, _},
			{vector, {<<"CT">>, CT}, _},
			{vector, {<<"Tag">>, Tag}, _}
			| Vectors
		], {Cipher, encrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, Counts}}, Config)
			when bit_size(Key) =:= Keylen
			andalso bit_size(IV) =:= IVlen
			andalso bit_size(PT) =:= PTlen
			andalso bit_size(AAD) =:= AADlen
			andalso bit_size(CT) =:= PTlen
			andalso bit_size(Tag) =:= Taglen ->
	case crypto:rand_uniform(0, ?config(one_in, Config)) of
		0 ->
			case jose_jwa_aes:block_encrypt(Cipher, Key, IV, {AAD, PT}) of
				{CT, << Tag:Taglen/bitstring, _/bitstring >>} ->
					fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, encrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config);
				OtherEncrypt ->
					io:format("\t\tCounts = ~s", [<< Counts/binary, (integer_to_binary(Count))/binary, "..." >>]),
					ct:fail({{jose_jwa_aes, block_encrypt, [Cipher, Key, IV, {AAD, PT}]}, {expected, {CT, Tag}}, {got, OtherEncrypt}})
			end;
		_ ->
			fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, encrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config)
	end;
fips_aes_gcm_encrypt_and_decrypt([
			{option, {<<"Keylen">>, Keylen}},
			{option, {<<"IVlen">>, IVlen}},
			{option, {<<"PTlen">>, PTlen}},
			{option, {<<"AADlen">>, AADlen}},
			{option, {<<"Taglen">>, Taglen}}
			| Vectors
		], {Cipher, Mode, undefined}, Config) ->
	Options = {
		binary_to_integer(Keylen),
		binary_to_integer(IVlen),
		binary_to_integer(PTlen),
		binary_to_integer(AADlen),
		binary_to_integer(Taglen),
		<<>>
	},
	fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, Options}, Config);
fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, {_Keylen, _IVlen, _PTlen, _AADlen, _Taglen, _Counts}}, Config) ->
	fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, undefined}, Config);
fips_aes_gcm_encrypt_and_decrypt([], _Cipher, Config) ->
	Config.

%% @private
fips_aeskw_unwrap(File, Config) ->
	<< "KW_AD_", BitsBin:3/binary, _/binary >> = iolist_to_binary(filename:basename(File)),
	Bits = binary_to_integer(BitsBin),
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [filename:basename(File)]),
	fips_aeskw_unwrap(Vectors, {Bits, undefined}, Config).

%% @private
fips_aeskw_unwrap([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"K">>, K}, _},
			{vector, {<<"C">>, C}, _},
			{vector, {<<"P">>, P}, _}
			| Vectors
		], {Bits, Len}, Config)
			when is_integer(Len)
			andalso bit_size(K) =:= Bits
			andalso bit_size(P) =:= Len ->
	case crypto:rand_uniform(0, ?config(one_in, Config)) of
		0 ->
			case jose_jwa_aes_kw:unwrap(C, K) of
				P ->
					fips_aeskw_unwrap(Vectors, {Bits, Len}, Config);
				Other ->
					io:format("\t\tCOUNT = ~w", [Count]),
					ct:fail({{jose_jwa_aes_kw, unwrap, [C, K]}, {expected, P}, {got, Other}})
			end;
		_ ->
			fips_aeskw_unwrap(Vectors, {Bits, Len}, Config)
	end;
fips_aeskw_unwrap([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"K">>, K}, _},
			{vector, {<<"C">>, C}, _},
			{token, <<"FAIL">>}
			| Vectors
		], {Bits, Len}, Config)
			when is_integer(Len)
			andalso bit_size(K) =:= Bits ->
	case crypto:rand_uniform(0, ?config(one_in, Config)) of
		0 ->
			try jose_jwa_aes_kw:unwrap(C, K) of
				Other ->
					io:format("\t\tCOUNT = ~w", [Count]),
					ct:fail({{jose_jwa_aes_kw, unwrap, [C, K]}, {expected, badarg}, {got, Other}})
			catch
				_:_ ->
					fips_aeskw_unwrap(Vectors, {Bits, Len}, Config)
			end;
		_ ->
			fips_aeskw_unwrap(Vectors, {Bits, Len}, Config)
	end;
fips_aeskw_unwrap([{option, {<<"PLAINTEXTLENGTH">>, LenBin}} | Vectors], {Bits, _}, Config) ->
	Len = binary_to_integer(LenBin),
	io:format("\tPLAINTEXTLENGTH = ~w", [Len]),
	fips_aeskw_unwrap(Vectors, {Bits, Len}, Config);
fips_aeskw_unwrap([], _, Config) ->
	Config.

%% @private
fips_aeskw_wrap(File, Config) ->
	<< "KW_AE_", BitsBin:3/binary, _/binary >> = iolist_to_binary(filename:basename(File)),
	Bits = binary_to_integer(BitsBin),
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [filename:basename(File)]),
	fips_aeskw_wrap(Vectors, {Bits, undefined}, Config).

%% @private
fips_aeskw_wrap([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"K">>, K}, _},
			{vector, {<<"P">>, P}, _},
			{vector, {<<"C">>, C}, _}
			| Vectors
		], {Bits, Len}, Config)
			when is_integer(Len)
			andalso bit_size(K) =:= Bits
			andalso bit_size(P) =:= Len ->
	case crypto:rand_uniform(0, ?config(one_in, Config)) of
		0 ->
			case jose_jwa_aes_kw:wrap(P, K) of
				C ->
					fips_aeskw_wrap(Vectors, {Bits, Len}, Config);
				Other ->
					io:format("\t\tCOUNT = ~w", [Count]),
					ct:fail({{jose_jwa_aes_kw, wrap, [P, K]}, {expected, C}, {got, Other}})
			end;
		_ ->
			fips_aeskw_wrap(Vectors, {Bits, Len}, Config)
	end;
fips_aeskw_wrap([{option, {<<"PLAINTEXTLENGTH">>, LenBin}} | Vectors], {Bits, _}, Config) ->
	Len = binary_to_integer(LenBin),
	io:format("\tPLAINTEXTLENGTH = ~w", [Len]),
	fips_aeskw_wrap(Vectors, {Bits, Len}, Config);
fips_aeskw_wrap([], _, Config) ->
	Config.

%% @private
fips_rsa_pss_sign([
			{option, {<<"mod">>, ModVal}},
			{vector, {<<"n">>, N}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _}
			| Vectors
		], Config) ->
	ModulusSize = binary_to_integer(ModVal),
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	fips_rsa_pss_sign(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_sign([], _Config) ->
	ok.

%% @private
fips_rsa_pss_sign([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey, Config) ->
	HashFun = shaalg_to_hash_fun(SHAAlg),
	case jose_jwa_pkcs1:rsassa_pss_sign(HashFun, Msg, SaltVal, RSAPrivateKey) of
		{ok, S} ->
			ok;
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_sign, [HashFun, Msg, SaltVal, RSAPrivateKey]}, {expected, {ok, S}}, {got, Other}})
	end,
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = byte_size(SaltVal),
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		true ->
			fips_rsa_pss_sign(Vectors, ModulusSize, RSAPrivateKey, Config);
		false ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, true}, {got, false}})
	end;
fips_rsa_pss_sign(Vectors, _ModulusSize, _RSAPrivateKey, Config) ->
	fips_rsa_pss_sign(Vectors, Config).

%% @private
fips_rsa_pss_verify([
			{option, {<<"mod">>, ModVal}},
			{vector, {<<"n">>, N}, _},
			{vector, {<<"p">>, P}, _},
			{vector, {<<"q">>, Q}, _}
			| Vectors
		], Config) ->
	ModulusSize = binary_to_integer(ModVal),
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q)
	},
	fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_verify([], _Config) ->
	ok.

%% @private
fips_rsa_pss_verify([
			{vector, {<<"n">>, N}, _},
			{vector, {<<"p">>, P}, _},
			{vector, {<<"q">>, Q}, _}
			| Vectors
		], ModulusSize, Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q)
	},
	fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_verify(Vectors, _ModulusSize, Config) ->
	fips_rsa_pss_verify(Vectors, Config).

%% @private
fips_rsa_pss_verify([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _},
			{vector, {<<"EM", _/binary>>, _}, _},
			{vector, {<<"Result">>, << R, _/binary >>}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey0, Config) ->
	Expected = case R of
		$F ->
			false;
		$P ->
			true
	end,
	HashFun = shaalg_to_hash_fun(SHAAlg),
	RSAPrivateKey = RSAPrivateKey0#'RSAPrivateKey'{
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = case SaltVal of
		<< 0 >> ->
			0;
		_ ->
			byte_size(SaltVal)
	end,
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		Expected ->
			fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey0, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, Expected}, {got, Other}})
	end;
fips_rsa_pss_verify([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _},
			{vector, {<<"Result">>, << R, _/binary >>}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey0, Config) ->
	Expected = case R of
		$F ->
			false;
		$P ->
			true
	end,
	HashFun = shaalg_to_hash_fun(SHAAlg),
	RSAPrivateKey = RSAPrivateKey0#'RSAPrivateKey'{
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = case SaltVal of
		<< 0 >> ->
			0;
		_ ->
			byte_size(SaltVal)
	end,
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		Expected ->
			fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey0, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, Expected}, {got, Other}})
	end;
fips_rsa_pss_verify(Vectors, ModulusSize, _RSAPrivateKey, Config) ->
	fips_rsa_pss_verify(Vectors, ModulusSize, Config).

%% @private
fips_sha3(File, Config) ->
	Options = case iolist_to_binary(filename:basename(File)) of
		<< "ShortMsgKAT_SHA3-", BitsBin:3/binary, _/binary >> ->
			Bits = binary_to_integer(BitsBin),
			Bytes = (Bits + 7) div 8,
			Function = list_to_atom("sha3_" ++ integer_to_list(Bits)),
			Arity = 1,
			{Function, Arity, Bytes};
		<< "ShortMsgKAT_SHAKE", BitsBin:3/binary, _/binary >> ->
			Bits = binary_to_integer(BitsBin),
			Bytes = 512,
			Function = list_to_atom("shake" ++ integer_to_list(Bits)),
			Arity = 2,
			{Function, Arity, Bytes}
	end,
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [filename:basename(File)]),
	fips_sha3(Vectors, Options, Config).

%% @private
fips_sha3([
			{vector, {<<"Len">>, Len}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"MD">>, MD}, _}
			| Vectors
		], {Function, Arity=1, OutputByteLen}, Config) when Len rem 8 =:= 0 ->
	InputBytes = binary:part(Msg, 0, Len div 8),
	case jose_jwa_sha3:Function(InputBytes) of
		MD ->
			fips_sha3(Vectors, {Function, Arity, OutputByteLen}, Config);
		Other ->
			ct:fail({{jose_jwa_sha3, Function, [InputBytes]}, {expected, MD}, {got, Other}})
	end;
fips_sha3([
			{vector, {<<"Len">>, Len}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"Squeezed">>, Squeezed}, _}
			| Vectors
		], {Function, Arity=2, OutputByteLen}, Config) when Len rem 8 =:= 0 ->
	InputBytes = binary:part(Msg, 0, Len div 8),
	case jose_jwa_sha3:Function(InputBytes, OutputByteLen) of
		Squeezed ->
			fips_sha3(Vectors, {Function, Arity, OutputByteLen}, Config);
		Other ->
			ct:fail({{jose_jwa_sha3, Function, [InputBytes, OutputByteLen]}, {expected, Squeezed}, {got, Other}})
	end;
fips_sha3([
			{vector, {<<"Len">>, _Len}, _},
			{vector, {<<"Msg">>, _Msg}, _},
			{vector, {<<"MD">>, _MD}, _}
			| Vectors
		], Options, Config) ->
	fips_sha3(Vectors, Options, Config);
fips_sha3([
			{vector, {<<"Len">>, _Len}, _},
			{vector, {<<"Msg">>, _Msg}, _},
			{vector, {<<"Squeezed">>, _Squeezed}, _}
			| Vectors
		], Options, Config) ->
	fips_sha3(Vectors, Options, Config);
fips_sha3([], _Opts, _Config) ->
	ok.

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

%% @private
pbkdf1([{Hash, Password, Salt, Iterations, DerivedKeyLen, DerivedKey} | Vectors], Config) ->
	case jose_jwa_pkcs5:pbkdf1(Hash, Password, Salt, Iterations, DerivedKeyLen) of
		{ok, DerivedKey} ->
			pbkdf1(Vectors, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs5, pbkdf1, [Hash, Password, Salt, Iterations, DerivedKeyLen]}, {expected, {ok, DerivedKey}}, {got, Other}})
	end;
pbkdf1([], _Config) ->
	ok.

%% @private
pbkdf2([{Mac, Password, Salt, Iterations, DerivedKeyLen, DerivedKey} | Vectors], Config) ->
	case jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt, Iterations, DerivedKeyLen) of
		{ok, DerivedKey} ->
			pbkdf2(Vectors, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs5, pbkdf2, [Mac, Password, Salt, Iterations, DerivedKeyLen]}, {expected, {ok, DerivedKey}}, {got, Other}})
	end;
pbkdf2([], _Config) ->
	ok.

%% @private
pkcs7_pad_and_unpad([{Unpadded, Padded} | Vectors], Config) ->
	case jose_jwa_pkcs7:pad(Unpadded) of
		Padded ->
			ok;
		PadOther ->
			ct:fail({{jose_jwa_pkcs7, pad, [Unpadded]}, {expected, Padded}, {got, PadOther}})
	end,
	case jose_jwa_pkcs7:unpad(Padded) of
		Unpadded ->
			pkcs7_pad_and_unpad(Vectors, Config);
		UnpadOther ->
			ct:fail({{jose_jwa_pkcs7, unpad, [Padded]}, {expected, Unpadded}, {got, UnpadOther}})
	end;
pkcs7_pad_and_unpad([], _Config) ->
	ok.

%% @private
rsa_private_to_public(#'RSAPrivateKey'{ modulus = Modulus, publicExponent = PublicExponent }) ->
	#'RSAPublicKey'{ modulus = Modulus, publicExponent = PublicExponent }.

%% @private
shaalg_to_hash_fun(<<"SHA1">>)   -> sha;
shaalg_to_hash_fun(<<"SHA224">>) -> sha224;
shaalg_to_hash_fun(<<"SHA256">>) -> sha256;
shaalg_to_hash_fun(<<"SHA384">>) -> sha384;
shaalg_to_hash_fun(<<"SHA512">>) -> sha512.

%% @private
x25519_vector({AliceSK, AlicePK, BobSK, BobPK, Shared}) ->
	?tv_ok(T0, jose_jwa_curve25519, x25519_secret_to_public, [AliceSK], AlicePK),
	?tv_ok(T1, jose_jwa_curve25519, x25519_secret_to_public, [BobSK], BobPK),
	?tv_ok(T2, jose_jwa_curve25519, x25519_shared_secret, [AliceSK, BobPK], Shared),
	?tv_ok(T3, jose_jwa_curve25519, x25519_shared_secret, [BobSK, AlicePK], Shared).

%% @private
x448_vector({AliceSK, AlicePK, BobSK, BobPK, Shared}) ->
	?tv_ok(T0, jose_jwa_curve448, x448_secret_to_public, [AliceSK], AlicePK),
	?tv_ok(T1, jose_jwa_curve448, x448_secret_to_public, [BobSK], BobPK),
	?tv_ok(T2, jose_jwa_curve448, x448_shared_secret, [AliceSK, BobPK], Shared),
	?tv_ok(T3, jose_jwa_curve448, x448_shared_secret, [BobSK, AlicePK], Shared).
