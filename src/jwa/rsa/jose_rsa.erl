%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_rsa).

-include("jose_rsa.hrl").
-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type message() :: binary().
-type maybe_invalid_signature(T) :: binary() | T.
-type plain_text() :: binary().
-type cipher_text() :: binary().
-type rsa_integer() :: <<_:8, _:_*8>>.
-type rsa_modulus_size() :: pos_integer().

-type rsa_public_exponent() :: rsa_integer().
-type rsa_modulus() :: rsa_integer().
-type rsa_private_exponent() :: rsa_integer().
-type rsa_first_prime_factor() :: rsa_integer().
-type rsa_second_prime_factor() :: rsa_integer().
-type rsa_first_factor_crt_exponent() :: rsa_integer().
-type rsa_second_factor_crt_exponent() :: rsa_integer().
-type rsa_first_crt_coefficient() :: rsa_integer().
-type rsa_prime_factor() :: rsa_integer().
-type rsa_factor_crt_exponent() :: rsa_integer().
-type rsa_factor_crt_coefficient() :: rsa_integer().

-type rsa_other_prime_info() :: #jose_rsa_other_prime_info{}.
-type rsa_private_key() :: #jose_rsa_private_key{}.
-type rsa_public_key() :: #jose_rsa_public_key{}.

-type rsassa_pkcs1_v1_5_sha1_signature() :: binary().
-type rsassa_pkcs1_v1_5_sha256_signature() :: binary().
-type rsassa_pkcs1_v1_5_sha384_signature() :: binary().
-type rsassa_pkcs1_v1_5_sha512_signature() :: binary().
-type rsassa_pss_sha256_mgf1_sha256_signature() :: binary().
-type rsassa_pss_sha384_mgf1_sha384_signature() :: binary().
-type rsassa_pss_sha512_mgf1_sha512_signature() :: binary().

-export_type([
	message/0,
	maybe_invalid_signature/1,
	plain_text/0,
	cipher_text/0,
	rsa_integer/0,
	rsa_modulus_size/0,

	rsa_public_exponent/0,
	rsa_modulus/0,
	rsa_private_exponent/0,
	rsa_first_prime_factor/0,
	rsa_second_prime_factor/0,
	rsa_first_factor_crt_exponent/0,
	rsa_second_factor_crt_exponent/0,
	rsa_first_crt_coefficient/0,
	rsa_prime_factor/0,
	rsa_factor_crt_exponent/0,
	rsa_factor_crt_coefficient/0,

	rsa_other_prime_info/0,
	rsa_private_key/0,
	rsa_public_key/0,

	rsassa_pkcs1_v1_5_sha1_signature/0,
	rsassa_pkcs1_v1_5_sha256_signature/0,
	rsassa_pkcs1_v1_5_sha384_signature/0,
	rsassa_pkcs1_v1_5_sha512_signature/0,
	rsassa_pss_sha256_mgf1_sha256_signature/0,
	rsassa_pss_sha384_mgf1_sha384_signature/0,
	rsassa_pss_sha512_mgf1_sha512_signature/0
]).

-callback rsa_keypair() -> {PublicKey, PrivateKey} when
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
-callback rsa_keypair(ModulusSize) -> {PublicKey, PrivateKey} when
	ModulusSize :: jose_rsa:rsa_modulus_size(),
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
-callback rsa_keypair(ModulusSize, PublicExponent) -> {PublicKey, PrivateKey} when
	ModulusSize :: jose_rsa:rsa_modulus_size(),
	PublicExponent :: jose_rsa:rsa_public_exponent(),
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
-callback rsa_private_to_public(PrivateKey) -> PublicKey when
	PrivateKey :: jose_rsa:rsa_private_key(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
-callback rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
-callback rsaes_oaep_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
-callback rsaes_oaep_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
-callback rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
-callback rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
-callback rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
-callback rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
-callback rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
-callback rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
-callback rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha1_signature().
-callback rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha1_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha256_signature().
-callback rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha256_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha384_signature().
-callback rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha384_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha512_signature().
-callback rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha512_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature().
-callback rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature().
-callback rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
-callback rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature().
-callback rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().

-optional_callbacks([
	rsa_keypair/0,
	rsa_keypair/1,
	rsa_keypair/2,
	rsa_private_to_public/1,
	rsaes_pkcs1_v1_5_private_decrypt/2,
	rsaes_pkcs1_v1_5_public_encrypt/2,
	rsaes_oaep_private_decrypt/2,
	rsaes_oaep_public_encrypt/2,
	rsaes_oaep_sha256_mgf1_sha256_private_decrypt/2,
	rsaes_oaep_sha256_mgf1_sha256_public_encrypt/2,
	rsaes_oaep_sha384_mgf1_sha384_private_decrypt/2,
	rsaes_oaep_sha384_mgf1_sha384_public_encrypt/2,
	rsaes_oaep_sha512_mgf1_sha512_private_decrypt/2,
	rsaes_oaep_sha512_mgf1_sha512_public_encrypt/2,
	rsassa_pkcs1_v1_5_sha1_sign/2,
	rsassa_pkcs1_v1_5_sha1_verify/3,
	rsassa_pkcs1_v1_5_sha256_sign/2,
	rsassa_pkcs1_v1_5_sha256_verify/3,
	rsassa_pkcs1_v1_5_sha384_sign/2,
	rsassa_pkcs1_v1_5_sha384_verify/3,
	rsassa_pkcs1_v1_5_sha512_sign/2,
	rsassa_pkcs1_v1_5_sha512_verify/3,
	rsassa_pss_sha256_mgf1_sha256_sign/2,
	rsassa_pss_sha256_mgf1_sha256_verify/3,
	rsassa_pss_sha384_mgf1_sha384_sign/2,
	rsassa_pss_sha384_mgf1_sha384_verify/3,
	rsassa_pss_sha512_mgf1_sha512_sign/2,
	rsassa_pss_sha512_mgf1_sha512_verify/3
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_rsa callbacks
-export([
	rsa_keypair/0,
	rsa_keypair/1,
	rsa_keypair/2,
	rsa_private_to_public/1,
	rsaes_pkcs1_v1_5_private_decrypt/2,
	rsaes_pkcs1_v1_5_public_encrypt/2,
	rsaes_oaep_private_decrypt/2,
	rsaes_oaep_public_encrypt/2,
	rsaes_oaep_sha256_mgf1_sha256_private_decrypt/2,
	rsaes_oaep_sha256_mgf1_sha256_public_encrypt/2,
	rsaes_oaep_sha384_mgf1_sha384_private_decrypt/2,
	rsaes_oaep_sha384_mgf1_sha384_public_encrypt/2,
	rsaes_oaep_sha512_mgf1_sha512_private_decrypt/2,
	rsaes_oaep_sha512_mgf1_sha512_public_encrypt/2,
	rsassa_pkcs1_v1_5_sha1_sign/2,
	rsassa_pkcs1_v1_5_sha1_verify/3,
	rsassa_pkcs1_v1_5_sha256_sign/2,
	rsassa_pkcs1_v1_5_sha256_verify/3,
	rsassa_pkcs1_v1_5_sha384_sign/2,
	rsassa_pkcs1_v1_5_sha384_verify/3,
	rsassa_pkcs1_v1_5_sha512_sign/2,
	rsassa_pkcs1_v1_5_sha512_verify/3,
	rsassa_pss_sha256_mgf1_sha256_sign/2,
	rsassa_pss_sha256_mgf1_sha256_verify/3,
	rsassa_pss_sha384_mgf1_sha384_sign/2,
	rsassa_pss_sha384_mgf1_sha384_verify/3,
	rsassa_pss_sha512_mgf1_sha512_sign/2,
	rsassa_pss_sha512_mgf1_sha512_verify/3
]).

%% Macros
-define(TV_Message(), <<"abc">>).
-define(TV_PlainText(), <<"abc">>).
-define(TV_RSA_ModulusSize(), 2048).
-define(TV_RSA_PublicExponent(), ?b16d("010001")).
-define(TV_RSA_2048_PrivateKey(), #jose_rsa_private_key{
	e = ?b16d("010001"),
	n = ?b16d("d4196e002d137091b81382541f5b6e5e2dbdb732736a6840bd054c266da764181c68fe6e9067cb77581f296d2cb8f93652ffd2b8653b3fd778e54936179041f08388759cc2063ea616e2f20ef2ca9591614fa9c92151b1a5ce0b5060070d85af454938a184cd1d40b2b4b0f9b570701ef624572cc4c3994df454af4283ec427654df05eb6abbea34e3825e4988f7bf426671927ef321061e4d4778550c137e0ec61c586113596d59b65c7ac6a6312a7bc81c74121862f298e1275ea79372e416cb7eca1fb0f99898b7b1bdac1f37a9ca9aaba58c45eee8fe7e55c3c5d28535759adbb6171b9a5978ede1a7a00da403fc437585277db89e80ff0991f7fe5ab641"),
	d = ?b16d("8b09347bb710c43d31ced02376fec7a5c3145750222a81b6d671ef8e4d596a9b079ca81530626a158cd5b8a151acdbe909959bbbb6d8952c199b2c57e23075994590219125fb53fc2a8a90a4cdf19104612708a4c94bb5497c7d1c2e26d16d6e0cdc47dc51a2e7e72e7e9678cac0af2f0ca99bdfc40878a98a5e2d194c4386f8bb7eb1f11f947af2c9114bddb217b6d3cd132ba725e3bb9012b505bd8b6b71fd0db37574bab61b12b3a074a6f240803d16425d4a0e44269cacf817c5e6eb27e59d6445339ba49b3484f34a64295a4a468aeb31ac167b4b262303acc9881d877994b1cb87852d10557b784d2d0a990ba7ac0156daed8f21626059f13a1cc30631"),
	p = ?b16d("ea189bdd48f9d6b0c89e6495c193145c37fd3c3cb09929aac2888a5a6b6e7c3bb327f18f51267e73746a91cdd41a548bb4224ed39a99b0e7022ae532beedfeef4b69e163b7a7ceab1dd71ab5a88a5453b7ab0b01de1b7e18abee14d2431afdac8f40ed4892647d24098b3ea23a01d1daba7750d7ecf436973d4067254a51422d"),
	q = ?b16d("e7f1ec6b42a2bc3a84c177c4c61d9722ea42d37d30aaaa11ef07079028b5c151076d592da7d800749afcdde5df384dca9e1260854aa6d3ad42e804e376fced1c5c8690c512f59675de3731ab69b0a19ebb9166b86e5f55a6d764cb65dec7f2a1b8b9e1ed76e2211502008ffd8c4801a836ced0688aeee012382cd9a386db14e5"),
	dp = ?b16d("494ce55937e58b3515cc8b005d7999717ad29f8efd592833e0eff22a77e343a149eae2f796587055e4890e189e26947c9e2df3f2cc40fda48808387658549b74007029f41868c20cd0ae2f1ddca55bdc4ef18ee3c9d15ffd87b067f2a2b28be601813a0b745364dfe8e121fe981d43c1b28b73d3f8cd4b5eb5fe398df2a4590d"),
	dq = ?b16d("739ed00863ce3560425f22b1ef443edbc3c50e21c0c9c23f7054a3bb83df9e7f22e1aa6bacd86ad9b58cc99c561a7e04bba9537dfe498d093869ea4ded398584f6c6899203b2728f4cf75c8623084e788eed9b33e2a9194c32e0e6d7602771d695fbeb187183a594104c717aa59c1b5f5bfada3ed2cae2dd922d214c77e3ebd5"),
	qi = ?b16d("b6f1d19b03c179b834a716a1bda1477aff901d93c034bb76f24fa77a0fd870ccfcf3c709ae9fe3d9cb2b55efef0ce389d8c48f3879abef92c7af8f87dffe09c61b4d11ae20dabb80931ed31950bfbd76f5cd3dd50271f65bd6e6cae4363dba55aa4e4eb070aa14f32cf1a28ac90dbe34567e1f88947987b3caee9539a485bf0f"),
	oth = []
}).
-define(TV_RSA_2048_PublicKey(), #jose_rsa_public_key{
	e = ?b16d("010001"),
	n = ?b16d("d4196e002d137091b81382541f5b6e5e2dbdb732736a6840bd054c266da764181c68fe6e9067cb77581f296d2cb8f93652ffd2b8653b3fd778e54936179041f08388759cc2063ea616e2f20ef2ca9591614fa9c92151b1a5ce0b5060070d85af454938a184cd1d40b2b4b0f9b570701ef624572cc4c3994df454af4283ec427654df05eb6abbea34e3825e4988f7bf426671927ef321061e4d4778550c137e0ec61c586113596d59b65c7ac6a6312a7bc81c74121862f298e1275ea79372e416cb7eca1fb0f99898b7b1bdac1f37a9ca9aaba58c45eee8fe7e55c3c5d28535759adbb6171b9a5978ede1a7a00da403fc437585277db89e80ff0991f7fe5ab641")
}).
-define(TV_RSA_2048_rsaes_pkcs1_v1_5_CipherText(), ?b16d("24edaa5dc842b66609092a1afb2e069ca953cd0109e7e701563f13f4c7225f9bf7c530c6ffe6cba91d83dc36973ca0c8ce5ea4e35ca88053121d03b1a701f00e156a67eaa2aec2afbd10f0825b2be8624a512179aa91d18da2d8da37da85eef68bf609f938f3e20953606f6c3b42064c211ee7e5c45b209039fa63f0b58f5f051513676a418915cf3e5415ef053cff4896b967b3efa3483958ba1dd385cfaecd936eb82cd490f2cb8ec0557151c50f1ab26adbf438136ae28917ca4dc3a0f8094074b2d22eb1711c2a0da95601407c26559d6193ff77796ff2244ce2339811cfdf97a576a3c4239e46349ae164bee3cfa158430bfcba06fae8d124c519ac53d2")).
-define(TV_RSA_2048_rsaes_oaep_CipherText(), ?b16d("71a431ec534287a9e91893ba6f77ba7f0e8a631ea80f9c8e87e7773286cc92413405b328ffd87d269c608f92813d68d6f999444e84eeb4b3ef601aa05c0965a85647f0a094b57c7dd1e88746212bc247f4fad29fa2fc74ea6267392eb657be62fed03ae0b1ec48d91963e870c943d27ddb4022c1360cb0f7ea8347c4dd3a59495b9aeb382a8ee0a813fdcd823265043a8eca6c04b602a09d100fe385dccfb5d0e4867064da5412bff992adbab254f25d82575f0744a18552e44c8e5bc379cee266574dba0c50621819b99682777119e4895f800a6a31456b7ecce14484b74b7f7728b3d3a570603a2b2b24e4f2b175b13f5d554b601fd47902fb539d42caac28")).
-define(TV_RSA_2048_rsaes_oaep_sha256_mgf1_sha256_CipherText(), ?b16d("9b2cfed48debb738553bdd017dbb1ee847e4bc9a3a3bc9e669ccdfe4c5ceec56ba9d896511b9877f48c0d9b1947889dfcd7988b2c78db3ecbb28b6835a4f49b375f69fe31172801f65688d3bdc4a65b5e11c95eb9ab0adc20f1514d180a9021ae62eee8ffdb4acf1ef0998f05c0d61bf44cc8b14f490df1d9fab62a9d7221ff2c076ecc363da8a46295fbdee1d943029eee38a485b19cf8cd95e9b8664faa9629411016fe582c70e067343d765987a926ba088bf2f461e52209714e13ff8f72bb44902d849bb8e4ae3956592d2b8f97c4f1809614948f1f361e3efb54c3453e242e18443e439a5f887a55d29153a6c028fd2183f5d633f8fb547cd80a5fdd0f0")).
-define(TV_RSA_2048_rsaes_oaep_sha384_mgf1_sha384_CipherText(), ?b16d("9f9219f3ce07a804405a86b1c24c41e28c988739f51f11d0793486d32722265036d6c48f0440a51327267e1e825fb506c41f744657d5b76a19ada92acf7d02ebe2937cfaa783c0e50b06cb0a642a41a202c3cbb4019725733df7689894c2f9607167492aaa91999eb849d3189c451fd619fdca4919ded530db964a627e2169d2df4ed6b15887bc42842d3d37411301c030ea4440c4b20ccbf8bd7ef4806789b34e775588559774459f66bcbc48eb4391060eb65a16d6b68377773de77d9113157576784fab27bff953e0b912c2cd5dc895a5c27785642edb04b9ff7a22fa2787a40ed3fdac30044a4729189ea1fcdec081f242488fba3b42213b80bf62d5e810")).
-define(TV_RSA_2048_rsaes_oaep_sha512_mgf1_sha512_CipherText(), ?b16d("0f1e2a31958c21355a4046fd97ada9ed4d5cf3e549870297c7d239249847f3cbdb470dbbb35b15fd48057bbf7647cc83ebb9f9b1b36f49fdbe5b97b650ec2d0b0f4248785474d0c0ac478d0bf99e9e1971f14b1bdddf26a1d56aa828e31f6d5a78ca6327699ec9ea78c418dc287a1960f7aab22002d7aac014e061a501cf420d80cfe12d0ed33bd1fd1cdac943e941e14342acaf2b864e70dea44fe0390ad5296f218788f6c44fbb1d65545659a95a4ab7ddc6dfe7c9ffc6d344c2a7d2177780d0cd83267476e4a0edecb38ac675572b53c0d193b1a0d030ca532f64baf00ca6145b096c51f9ff67fd262c5b018e7070465976cbf8a2bc9c4ded0eacb99e3105")).
-define(TV_RSA_2048_rsassa_pkcs1_v1_5_sha1_Sig(), ?b16d("1b224f92087a6ec7912a5c9cb62192e062332c03fea8d0fbe89f3ebdc9bd0601548aa42d995ff169c7c8928a8d387eaa6baf299522297ce059cea422df64e7fc454699a5040f89c760edba79ec65c956e21c25a4926aafb74f7bc371ba9f52249b4d38fcf636fb0e528630c99d0434de5bf5a0d386568cd67170edf6ca890dfbe8311fbcf7b36054633dee4dbe82e613f561f019bcab99f665d20c51d0d42f36a6c9df3cf6cc0be29bbdd2abdc875f35b16ee0dced7220b5643ebf7eb28c8c593cb8b8df93de2301fa8cdb3f729b617071c61dd07325cdf0401c8d25dc9ced53f5a8c2bab397d5272be6ddccd231a8d4b656749bf4a99f2def0a1ac841e1554d")).
-define(TV_RSA_2048_rsassa_pkcs1_v1_5_sha256_Sig(), ?b16d("269246180158065b58583866c78ef4a301ce22ada2323f25e90c335d93d19b8d1a763d2d281518d8d7af415040b4d85184877f7a046996a704fa708788c911b51ea646a12c53ee8547d74569f5bb0c1850116b7299e7822e9a4570abe2556497c3037c56cd500c2d3efc13e1dcae56969bcb056ebc930481eb9fa1f209e00f60e57a20d1b31e1931c305a2924bdaa0961b88c17a720ee778eb14a4b56410c58a89baee2171b7075a2b147edb34b4c23985ab20b204cdd2641b36d9e07afd08246ed889dadc1e50e68b8c3ed1c07f3ad44b4ff3b76359cc0b865e55d919e78d8929201336cdd9c700c4998e98cea476267214e9cc8b843642811be396c532b81c")).
-define(TV_RSA_2048_rsassa_pkcs1_v1_5_sha384_Sig(), ?b16d("788cfc602a3eab509a9f1ccdc2a13866888ae55bb358bd0cd83bbcbaf95aa0cdd466145ba3bc32b263c94846dadc8edbbd08bbaf3a54c7e961fb39cf3091fa9486a9a1a42b432b3fdff78f9a459ebacd527d05427b3eaa56d0cad72b2f5b80f8d0e5f077124c48d27ba494b8c73e55f8035b13e7f56e6ff2a0a163d044c4fb5269b4bcc3336143de24b688733d5e3698cac6402b3fb7d1a86629d1be926ba1a763b2d41c8940d0d3b4b321fcfca9fe608d5180f75055ff34cfc54bb0fca0cf8e4df8402896d36f32f77618a18d9138b7cd5ae5809a1247ca1e2184d8ccf455b9aa8d411e5604b14a92b46f4882abed4c725b2420c0ff2577c71aec30aa66caf2")).
-define(TV_RSA_2048_rsassa_pkcs1_v1_5_sha512_Sig(), ?b16d("7ab69d8adbb38c7924a5673e5d77d52eb67d7692a7ecc07a1773e8e4556eb5d32d4eb53562a2496c38e4184cc20f3376983f00fb0fa2db019288dd1e30de417b0c7b65e669c654a05c3a7c38a6eba70154dc8c1acfa4e4722234b1498138336211955a91a475fffdcebf3ca045ce417b660ef7ccb6a6e7a968d120571b44a74c86453860c6fb87bf8a578485300f73d95a073192ef76307dd28d2b2f5bd35b43f6577d5b3b81719b3ee9300875a36221db102419bafca771fdffcf7d6aed3f7a59b08906181e44f510486cb5893e6e216207c9a5546ec649f73b27b36d342d01c2318fca465c315c92d838e22b62298abd9f60bca2b919ee4e1b59ef8664987c")).
-define(TV_RSA_2048_rsassa_pss_sha256_mgf1_sha256_Sig(), ?b16d("61b9652b4d588927c2c717521b7d7edd34963ea4ed48bb90f847f4b3ac82acfe4cbad25e99c94ff636465374349d2b33acc14bbf0a96e0a8b03d384ad7d2303169e683d3067464b0afe50cdc65318cbbee8cbfd4c9cc30eec543d3d56567825ed7e06abaa5617e9578e796f5913192cc07c0d8fe622216edbdee10106be59cedc20a624e66467f2ffc7127371d5d1e40fd18425c7d67889483616f6370a18aa653db80e4cc1c643de34e5df3f6d88162e18cd8699c126b2864e40e727d2f97b074943dab239015bce4aaa7bfb8db4d520e1b147f84f4e3fce37660f1445b8b3a330c3bbf71ce1db435fe1ce5de41a7599f4899a55845e2c86879bd26d20f56ff")).
-define(TV_RSA_2048_rsassa_pss_sha384_mgf1_sha384_Sig(), ?b16d("b2ae8ac4099023c38cd42dad1f0c9c4d8c652641366737a44a138f36e4391ae957f999f2dcd30950c956b8f245190a9bdeeb9c21749ced1b6391a4ec7a82487495b20de3bd5f8a99ae6a877323e0f421008c7775255a5a64f1bba1fbbc2642051c16770768f8bf666ec15f32e1f99704d03946fbfb9541b3e9b07870af01181ad49f35735c5f93280941873e795aa9991967fb92a3f7a3af6515fb6ec7821c512d01d5ef2857d13975e603810f225eae8e5b2befb1156bd2f1f63b09185d394baa652d7b375fb34c30757f03ea58f0e0017525f5eeb67a36f96846b51f3d32965606f8a8aa9fe3682c5fffabaa167ff11c2468dcb07af884f42431fe89701099")).
-define(TV_RSA_2048_rsassa_pss_sha512_mgf1_sha512_Sig(), ?b16d("c0bf9508672fad08f5ea221049a4ffa5654663ca3a6dd17a9ec73a15271cfa6f5d59f1db0e5001b91e11734beb948d481ae66e2c45898a6670cbd3fdd0daca6d8921fc2e615cd2c9246ab8426215262838c23ab703191b881d4afdfaeab7253fd5faf0733bb45b3bfddae067450af2f463fc0ba7c0a56306d1092d3f39a8975d54b844a9c6e48e41795ec1729c480ceab2960d356597b214335f95d498f184b7b89ccb32f359b2c8df595a07fc5cd03d51589917ab8a8ce2f7ca2ed3513b3053e9d364c9a76dc73ab7e3862f485f91fe63f670b62da1361f6fa3df7d50795ad91daefd36b52add3fb75971d04818f0e9ab8d155adedf75548b9847bc1eae302a")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [],
		callbacks => [
			{{rsa_keypair, 0}, []},
			{{rsa_keypair, 1}, []},
			{{rsa_keypair, 2}, []},
			{{rsa_private_to_public, 1}, []},
			{{rsaes_pkcs1_v1_5_private_decrypt, 2}, []},
			{{rsaes_pkcs1_v1_5_public_encrypt, 2}, []},
			{{rsaes_oaep_private_decrypt, 2}, []},
			{{rsaes_oaep_public_encrypt, 2}, []},
			{{rsaes_oaep_sha256_mgf1_sha256_private_decrypt, 2}, []},
			{{rsaes_oaep_sha256_mgf1_sha256_public_encrypt, 2}, []},
			{{rsaes_oaep_sha384_mgf1_sha384_private_decrypt, 2}, []},
			{{rsaes_oaep_sha384_mgf1_sha384_public_encrypt, 2}, []},
			{{rsaes_oaep_sha512_mgf1_sha512_private_decrypt, 2}, []},
			{{rsaes_oaep_sha512_mgf1_sha512_public_encrypt, 2}, []},
			{{rsassa_pkcs1_v1_5_sha1_sign, 2}, []},
			{{rsassa_pkcs1_v1_5_sha1_verify, 3}, []},
			{{rsassa_pkcs1_v1_5_sha256_sign, 2}, []},
			{{rsassa_pkcs1_v1_5_sha256_verify, 3}, []},
			{{rsassa_pkcs1_v1_5_sha384_sign, 2}, []},
			{{rsassa_pkcs1_v1_5_sha384_verify, 3}, []},
			{{rsassa_pkcs1_v1_5_sha512_sign, 2}, []},
			{{rsassa_pkcs1_v1_5_sha512_verify, 3}, []},
			{{rsassa_pss_sha256_mgf1_sha256_sign, 2}, []},
			{{rsassa_pss_sha256_mgf1_sha256_verify, 3}, []},
			{{rsassa_pss_sha384_mgf1_sha384_sign, 2}, []},
			{{rsassa_pss_sha384_mgf1_sha384_verify, 3}, []},
			{{rsassa_pss_sha512_mgf1_sha512_sign, 2}, []},
			{{rsassa_pss_sha512_mgf1_sha512_verify, 3}, []}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, rsa_keypair, 0) ->
	case Module:rsa_keypair() of
		{#jose_rsa_public_key{}, #jose_rsa_private_key{}} ->
			ok;
		Actual ->
			{error, ?expect_report(Module, rsa_keypair, [], Actual, {badmatch, "PublicKey must be #jose_rsa_public_key{}, PrivateKey must be #jose_rsa_private_key{}"})}
	end;
support_check(Module, rsa_keypair, 1) ->
	ModulusSize = ?TV_RSA_ModulusSize(),
	case Module:rsa_keypair(ModulusSize) of
		{#jose_rsa_public_key{}, #jose_rsa_private_key{}} ->
			ok;
		Actual ->
			{error, ?expect_report(Module, rsa_keypair, [ModulusSize], Actual, {badmatch, "PublicKey must be #jose_rsa_public_key{}, PrivateKey must be #jose_rsa_private_key{}"})}
	end;
support_check(Module, rsa_keypair, 2) ->
	ModulusSize = ?TV_RSA_ModulusSize(),
	PublicExponent = ?TV_RSA_PublicExponent(),
	case Module:rsa_keypair(ModulusSize, PublicExponent) of
		{#jose_rsa_public_key{}, #jose_rsa_private_key{}} ->
			ok;
		Actual ->
			{error, ?expect_report(Module, rsa_keypair, [ModulusSize, PublicExponent], Actual, {badmatch, "PublicKey must be #jose_rsa_public_key{}, PrivateKey must be #jose_rsa_private_key{}"})}
	end;
support_check(Module, rsa_private_to_public, 1) ->
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(PK, Module, rsa_private_to_public, [SK]);
support_check(Module, rsaes_pkcs1_v1_5_private_decrypt, 2) ->
	CipherText = ?TV_RSA_2048_rsaes_pkcs1_v1_5_CipherText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, rsaes_pkcs1_v1_5_private_decrypt, [CipherText, SK]);
support_check(Module, rsaes_pkcs1_v1_5_public_encrypt, 2) ->
	PlainText = ?TV_PlainText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	CipherText = ?TV_RSA_2048_rsaes_pkcs1_v1_5_CipherText(),
	CipherTextSize = byte_size(CipherText),
	case Module:rsaes_pkcs1_v1_5_public_encrypt(PlainText, PK) of
		<<ActualCipherText:CipherTextSize/binary>> ->
			case Module:rsaes_pkcs1_v1_5_private_decrypt(ActualCipherText, SK) of
				PlainText when is_binary(PlainText) ->
					ok;
				_ActualPlainText ->
					{error, ?expect_report(Module, rsaes_pkcs1_v1_5_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText is invalid and cannot be decrypted", []))})}
			end;
		ActualCipherText ->
			{error, ?expect_report(Module, rsaes_pkcs1_v1_5_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText should have been ~w-bytes, but was ~w-bytes", [CipherTextSize, byte_size(ActualCipherText)]))})}
	end;
support_check(Module, rsaes_oaep_private_decrypt, 2) ->
	CipherText = ?TV_RSA_2048_rsaes_oaep_CipherText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, rsaes_oaep_private_decrypt, [CipherText, SK]);
support_check(Module, rsaes_oaep_public_encrypt, 2) ->
	PlainText = ?TV_PlainText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	CipherText = ?TV_RSA_2048_rsaes_oaep_CipherText(),
	CipherTextSize = byte_size(CipherText),
	case Module:rsaes_oaep_public_encrypt(PlainText, PK) of
		<<ActualCipherText:CipherTextSize/binary>> ->
			case Module:rsaes_oaep_private_decrypt(ActualCipherText, SK) of
				PlainText when is_binary(PlainText) ->
					ok;
				_ActualPlainText ->
					{error, ?expect_report(Module, rsaes_oaep_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText is invalid and cannot be decrypted", []))})}
			end;
		ActualCipherText ->
			{error, ?expect_report(Module, rsaes_oaep_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText should have been ~w-bytes, but was ~w-bytes", [CipherTextSize, byte_size(ActualCipherText)]))})}
	end;
support_check(Module, rsaes_oaep_sha256_mgf1_sha256_private_decrypt, 2) ->
	CipherText = ?TV_RSA_2048_rsaes_oaep_sha256_mgf1_sha256_CipherText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, rsaes_oaep_sha256_mgf1_sha256_private_decrypt, [CipherText, SK]);
support_check(Module, rsaes_oaep_sha256_mgf1_sha256_public_encrypt, 2) ->
	PlainText = ?TV_PlainText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	CipherText = ?TV_RSA_2048_rsaes_oaep_sha256_mgf1_sha256_CipherText(),
	CipherTextSize = byte_size(CipherText),
	case Module:rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PK) of
		<<ActualCipherText:CipherTextSize/binary>> ->
			case Module:rsaes_oaep_sha256_mgf1_sha256_private_decrypt(ActualCipherText, SK) of
				PlainText when is_binary(PlainText) ->
					ok;
				_ActualPlainText ->
					{error, ?expect_report(Module, rsaes_oaep_sha256_mgf1_sha256_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText is invalid and cannot be decrypted", []))})}
			end;
		ActualCipherText ->
			{error, ?expect_report(Module, rsaes_oaep_sha256_mgf1_sha256_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText should have been ~w-bytes, but was ~w-bytes", [CipherTextSize, byte_size(ActualCipherText)]))})}
	end;
support_check(Module, rsaes_oaep_sha384_mgf1_sha384_private_decrypt, 2) ->
	CipherText = ?TV_RSA_2048_rsaes_oaep_sha384_mgf1_sha384_CipherText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, rsaes_oaep_sha384_mgf1_sha384_private_decrypt, [CipherText, SK]);
support_check(Module, rsaes_oaep_sha384_mgf1_sha384_public_encrypt, 2) ->
	PlainText = ?TV_PlainText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	CipherText = ?TV_RSA_2048_rsaes_oaep_sha384_mgf1_sha384_CipherText(),
	CipherTextSize = byte_size(CipherText),
	case Module:rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PK) of
		<<ActualCipherText:CipherTextSize/binary>> ->
			case Module:rsaes_oaep_sha384_mgf1_sha384_private_decrypt(ActualCipherText, SK) of
				PlainText when is_binary(PlainText) ->
					ok;
				_ActualPlainText ->
					{error, ?expect_report(Module, rsaes_oaep_sha384_mgf1_sha384_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText is invalid and cannot be decrypted", []))})}
			end;
		ActualCipherText ->
			{error, ?expect_report(Module, rsaes_oaep_sha384_mgf1_sha384_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText should have been ~w-bytes, but was ~w-bytes", [CipherTextSize, byte_size(ActualCipherText)]))})}
	end;
support_check(Module, rsaes_oaep_sha512_mgf1_sha512_private_decrypt, 2) ->
	CipherText = ?TV_RSA_2048_rsaes_oaep_sha512_mgf1_sha512_CipherText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, rsaes_oaep_sha512_mgf1_sha512_private_decrypt, [CipherText, SK]);
support_check(Module, rsaes_oaep_sha512_mgf1_sha512_public_encrypt, 2) ->
	PlainText = ?TV_PlainText(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	CipherText = ?TV_RSA_2048_rsaes_oaep_sha512_mgf1_sha512_CipherText(),
	CipherTextSize = byte_size(CipherText),
	case Module:rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PK) of
		<<ActualCipherText:CipherTextSize/binary>> ->
			case Module:rsaes_oaep_sha512_mgf1_sha512_private_decrypt(ActualCipherText, SK) of
				PlainText when is_binary(PlainText) ->
					ok;
				_ActualPlainText ->
					{error, ?expect_report(Module, rsaes_oaep_sha512_mgf1_sha512_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText is invalid and cannot be decrypted", []))})}
			end;
		ActualCipherText ->
			{error, ?expect_report(Module, rsaes_oaep_sha512_mgf1_sha512_public_encrypt, [PlainText, PK], ActualCipherText, {badmatch, lists:flatten(io_lib:format("CipherText should have been ~w-bytes, but was ~w-bytes", [CipherTextSize, byte_size(ActualCipherText)]))})}
	end;
support_check(Module, rsassa_pkcs1_v1_5_sha1_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha1_Sig(),
	?expect(Sig, Module, rsassa_pkcs1_v1_5_sha1_sign, [Message, SK]);
support_check(Module, rsassa_pkcs1_v1_5_sha1_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha1_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pkcs1_v1_5_sha1_verify, [Sig, Message, PK]);
support_check(Module, rsassa_pkcs1_v1_5_sha256_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha256_Sig(),
	?expect(Sig, Module, rsassa_pkcs1_v1_5_sha256_sign, [Message, SK]);
support_check(Module, rsassa_pkcs1_v1_5_sha256_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha256_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pkcs1_v1_5_sha256_verify, [Sig, Message, PK]);
support_check(Module, rsassa_pkcs1_v1_5_sha384_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha384_Sig(),
	?expect(Sig, Module, rsassa_pkcs1_v1_5_sha384_sign, [Message, SK]);
support_check(Module, rsassa_pkcs1_v1_5_sha384_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha384_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pkcs1_v1_5_sha384_verify, [Sig, Message, PK]);
support_check(Module, rsassa_pkcs1_v1_5_sha512_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha512_Sig(),
	?expect(Sig, Module, rsassa_pkcs1_v1_5_sha512_sign, [Message, SK]);
support_check(Module, rsassa_pkcs1_v1_5_sha512_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pkcs1_v1_5_sha512_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pkcs1_v1_5_sha512_verify, [Sig, Message, PK]);
support_check(Module, rsassa_pss_sha256_mgf1_sha256_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	Sig = ?TV_RSA_2048_rsassa_pss_sha256_mgf1_sha256_Sig(),
	SigSize = byte_size(Sig),
	case Module:rsassa_pss_sha256_mgf1_sha256_sign(Message, SK) of
		<<ActualSig:SigSize/binary>> ->
			case Module:rsassa_pss_sha256_mgf1_sha256_verify(ActualSig, Message, PK) of
				true ->
					ok;
				false ->
					{error, ?expect_report(Module, rsassa_pss_sha256_mgf1_sha256_sign, [Message, SK], ActualSig, {badmatch, lists:flatten(io_lib:format("Signature is invalid and cannot be verified", []))})}
			end;
		ActualSig ->
			{error, ?expect_report(Module, rsassa_pss_sha256_mgf1_sha256_sign, [Message, SK], ActualSig, {badmatch, lists:flatten(io_lib:format("Signature should have been ~w-bytes, but was ~w-bytes", [SigSize, byte_size(ActualSig)]))})}
	end;
support_check(Module, rsassa_pss_sha256_mgf1_sha256_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pss_sha256_mgf1_sha256_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pss_sha256_mgf1_sha256_verify, [Sig, Message, PK]);
support_check(Module, rsassa_pss_sha384_mgf1_sha384_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	Sig = ?TV_RSA_2048_rsassa_pss_sha384_mgf1_sha384_Sig(),
	SigSize = byte_size(Sig),
	case Module:rsassa_pss_sha384_mgf1_sha384_sign(Message, SK) of
		<<ActualSig:SigSize/binary>> ->
			case Module:rsassa_pss_sha384_mgf1_sha384_verify(ActualSig, Message, PK) of
				true ->
					ok;
				false ->
					{error, ?expect_report(Module, rsassa_pss_sha384_mgf1_sha384_sign, [Message, SK], ActualSig, {badmatch, lists:flatten(io_lib:format("Signature is invalid and cannot be verified", []))})}
			end;
		ActualSig ->
			{error, ?expect_report(Module, rsassa_pss_sha384_mgf1_sha384_sign, [Message, SK], ActualSig, {badmatch, lists:flatten(io_lib:format("Signature should have been ~w-bytes, but was ~w-bytes", [SigSize, byte_size(ActualSig)]))})}
	end;
support_check(Module, rsassa_pss_sha384_mgf1_sha384_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pss_sha384_mgf1_sha384_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pss_sha384_mgf1_sha384_verify, [Sig, Message, PK]);
support_check(Module, rsassa_pss_sha512_mgf1_sha512_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_RSA_2048_PrivateKey(),
	PK = ?TV_RSA_2048_PublicKey(),
	Sig = ?TV_RSA_2048_rsassa_pss_sha512_mgf1_sha512_Sig(),
	SigSize = byte_size(Sig),
	case Module:rsassa_pss_sha512_mgf1_sha512_sign(Message, SK) of
		<<ActualSig:SigSize/binary>> ->
			case Module:rsassa_pss_sha512_mgf1_sha512_verify(ActualSig, Message, PK) of
				true ->
					ok;
				false ->
					{error, ?expect_report(Module, rsassa_pss_sha512_mgf1_sha512_sign, [Message, SK], ActualSig, {badmatch, lists:flatten(io_lib:format("Signature is invalid and cannot be verified", []))})}
			end;
		ActualSig ->
			{error, ?expect_report(Module, rsassa_pss_sha512_mgf1_sha512_sign, [Message, SK], ActualSig, {badmatch, lists:flatten(io_lib:format("Signature should have been ~w-bytes, but was ~w-bytes", [SigSize, byte_size(ActualSig)]))})}
	end;
support_check(Module, rsassa_pss_sha512_mgf1_sha512_verify, 3) ->
	Sig = ?TV_RSA_2048_rsassa_pss_sha512_mgf1_sha512_Sig(),
	Message = ?TV_Message(),
	PK = ?TV_RSA_2048_PublicKey(),
	?expect(true, Module, rsassa_pss_sha512_mgf1_sha512_verify, [Sig, Message, PK]).

%%====================================================================
%% jose_rsa callbacks
%%====================================================================

-spec rsa_keypair() -> {PublicKey, PrivateKey} when
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
rsa_keypair() ->
	?resolve([]).

-spec rsa_keypair(ModulusSize) -> {PublicKey, PrivateKey} when
	ModulusSize :: jose_rsa:rsa_modulus_size(),
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
rsa_keypair(ModulusSize)
		when (is_integer(ModulusSize) andalso ModulusSize >= 1) ->
	?resolve([ModulusSize]).

-spec rsa_keypair(ModulusSize, PublicExponent) -> {PublicKey, PrivateKey} when
	ModulusSize :: jose_rsa:rsa_modulus_size(),
	PublicExponent :: jose_rsa:rsa_public_exponent(),
	PublicKey :: jose_rsa:rsa_public_key(),
	PrivateKey :: jose_rsa:rsa_private_key().
rsa_keypair(ModulusSize, PublicExponent)
		when (is_integer(ModulusSize) andalso ModulusSize >= 1)
		andalso (is_binary(PublicExponent) andalso byte_size(PublicExponent) >= 1) ->
	?resolve([ModulusSize, PublicExponent]).

-spec rsa_private_to_public(PrivateKey) -> PublicKey when
	PrivateKey :: jose_rsa:rsa_private_key(),
	PublicKey :: jose_rsa:rsa_public_key().
rsa_private_to_public(PrivateKey = #jose_rsa_private_key{}) ->
	?resolve([PrivateKey]).

-spec rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	?resolve([CipherText, PrivateKey]).

-spec rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey = #jose_rsa_private_key{}) when is_binary(PlainText) ->
	?resolve([PlainText, PublicKey]).

-spec rsaes_oaep_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	?resolve([CipherText, PrivateKey]).

-spec rsaes_oaep_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	?resolve([PlainText, PublicKey]).

-spec rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	?resolve([CipherText, PrivateKey]).

-spec rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	?resolve([PlainText, PublicKey]).

-spec rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	?resolve([CipherText, PrivateKey]).

-spec rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	?resolve([PlainText, PublicKey]).

-spec rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
	CipherText :: jose_rsa:cipher_text(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
	?resolve([CipherText, PrivateKey]).

-spec rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
	PlainText :: jose_rsa:plain_text(),
	PublicKey :: jose_rsa:rsa_public_key(),
	CipherText :: jose_rsa:cipher_text(),
	Reason :: message_too_long.
rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
	?resolve([PlainText, PublicKey]).

-spec rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha1_signature().
rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha1_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).

-spec rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha256_signature().
rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha256_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).

-spec rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha384_signature().
rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha384_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).

-spec rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha512_signature().
rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha512_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).

-spec rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature().
rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).

-spec rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature().
rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).

-spec rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey) -> Signature when
	Message :: jose_rsa:message(),
	PrivateKey :: jose_rsa:rsa_private_key(),
	Signature :: jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature().
rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
	?resolve([Message, PrivateKey]).

-spec rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
	Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature()),
	Message :: jose_rsa:message(),
	PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey = #jose_rsa_public_key{})
  		when is_binary(Signature)
		andalso is_binary(Message) ->
	?resolve([Signature, Message, PublicKey]).
