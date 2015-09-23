%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-include("jose.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([jwe_a_1/1]).
-export([jwe_a_2/1]).
-export([jwe_a_3/1]).
-export([jwk_c/1]).
-export([jwk_rsa_multi/1]).
-export([jws_a_1/1]).
-export([jws_a_2/1]).
-export([jws_a_3/1]).
-export([jws_a_4/1]).
-export([jws_a_5/1]).

all() ->
	[
		{group, jose_jwe},
		{group, jose_jwk},
		{group, jose_jws}
	].

groups() ->
	[
		{jose_jwe, [parallel], [
			jwe_a_1,
			jwe_a_2,
			jwe_a_3
		]},
		{jose_jwk, [parallel], [
			jwk_c,
			jwk_rsa_multi
		]},
		{jose_jws, [parallel], [
			jws_a_1,
			jws_a_2,
			jws_a_3,
			jws_a_4,
			jws_a_5
		]}
	].

init_per_suite(Config) ->
	application:set_env(jose, crypto_fallback, true),
	_ = application:ensure_all_started(jose),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(jose),
	ok.

init_per_group(jose_jwe, Config) ->
	{ok, A1} = file:consult(data_file("jwe/a.1.config", Config)),
	{ok, A2} = file:consult(data_file("jwe/a.2.config", Config)),
	{ok, A3} = file:consult(data_file("jwe/a.3.config", Config)),
	[{jwe_a_1, A1}, {jwe_a_2, A2}, {jwe_a_3, A3} | Config];
init_per_group(jose_jwk, Config) ->
	{ok, C} = file:consult(data_file("jwk/c.config", Config)),
	[{jwk_c, C} | Config];
init_per_group(jose_jws, Config) ->
	{ok, A1} = file:consult(data_file("jws/a.1.config", Config)),
	{ok, A2} = file:consult(data_file("jws/a.2.config", Config)),
	{ok, A3} = file:consult(data_file("jws/a.3.config", Config)),
	{ok, A4} = file:consult(data_file("jws/a.4.config", Config)),
	{ok, A5} = file:consult(data_file("jws/a.5.config", Config)),
	[{jws_a_1, A1}, {jws_a_2, A2}, {jws_a_3, A3}, {jws_a_4, A4}, {jws_a_5, A5} | Config];
init_per_group(_Group, Config) ->
	Config.

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

% JSON Web Encryption (JWE)
% A.1.  Example JWE using RSAES-OAEP and AES GCM
% [https://tools.ietf.org/html/rfc7516#appendix-A.1]
jwe_a_1(Config) ->
	C = ?config(jwe_a_1, Config),
	% A.1
	A_1_TXT = ?config("a.1.txt", C),
	% A.1.1
	A_1_1_JWE_DATA = ?config("a.1.1.jwe+json", C),
	A_1_1_JWE_MAP = jose:decode(A_1_1_JWE_DATA),
	A_1_1_JWE = jose_jwe:from_binary(A_1_1_JWE_DATA),
	{_, A_1_1_JWE_MAP} = jose_jwe:to_map(A_1_1_JWE),
	A_1_1_JWE_DATA_B64 = ?config("a.1.1.jwe+json.b64", C),
	A_1_1_JWE_DATA_B64 = base64url:encode(element(2, jose_jwe:to_binary(A_1_1_JWE))),
	% A.1.2
	A_1_2_CEK = ?config("a.1.2.cek", C),
	% A.1.3
	A_1_3_JWK_DATA = ?config("a.1.3.jwk+json", C),
	A_1_3_JWK_MAP = jose:decode(A_1_3_JWK_DATA),
	A_1_3_JWK = jose_jwk:from_binary(A_1_3_JWK_DATA),
	{_, A_1_3_JWK_MAP} = jose_jwk:to_map(A_1_3_JWK),
	A_1_3_CEK_ENCRYPTED = ?config("a.1.3.cek.encrypted", C),
	A_1_3_CEK_ENCRYPTED_B64 = ?config("a.1.3.cek.encrypted.b64", C),
	A_1_3_CEK_ENCRYPTED_B64 = base64url:encode(A_1_3_CEK_ENCRYPTED),
	% A.1.4
	A_1_4_IV = ?config("a.1.4.iv", C),
	A_1_4_IV_B64 = ?config("a.1.4.iv.b64", C),
	A_1_4_IV_B64 = base64url:encode(A_1_4_IV),
	% A.1.5
	A_1_5_AAD = ?config("a.1.5.aad", C),
	A_1_1_JWE_DATA_B64 = A_1_5_AAD,
	% A.1.6
	A_1_6_CIPHER = ?config("a.1.6.txt.cipher", C),
	A_1_6_TAG = ?config("a.1.6.txt.tag", C),
	A_1_6_CIPHER_B64 = ?config("a.1.6.txt.cipher.b64", C),
	A_1_6_TAG_B64 = ?config("a.1.6.txt.tag.b64", C),
	A_1_6_CIPHER = base64url:decode(A_1_6_CIPHER_B64),
	A_1_6_TAG = base64url:decode(A_1_6_TAG_B64),
	% A.1.7
	A_1_7_COMPACT = ?config("a.1.7.jwe+compact", C),
	{A_1_TXT, A_1_1_JWE} = jose_jwe:block_decrypt(A_1_3_JWK, A_1_7_COMPACT),
	% Roundtrip test
	A_1_7_MAP = jose_jwe:block_encrypt(A_1_3_JWK, A_1_TXT, A_1_2_CEK, A_1_4_IV, A_1_1_JWE),
	{A_1_TXT, A_1_1_JWE} = jose_jwe:block_decrypt(A_1_3_JWK, A_1_7_MAP),
	ok.

% JSON Web Encryption (JWE)
% A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
% [https://tools.ietf.org/html/rfc7516#appendix-A.2]
jwe_a_2(Config) ->
	C = ?config(jwe_a_2, Config),
	% A.2
	A_2_TXT = ?config("a.2.txt", C),
	% A.2.1
	A_2_1_JWE_DATA = ?config("a.2.1.jwe+json", C),
	A_2_1_JWE_MAP = jose:decode(A_2_1_JWE_DATA),
	A_2_1_JWE = jose_jwe:from_binary(A_2_1_JWE_DATA),
	{_, A_2_1_JWE_MAP} = jose_jwe:to_map(A_2_1_JWE),
	A_2_1_JWE_DATA_B64 = ?config("a.2.1.jwe+json.b64", C),
	A_2_1_JWE_DATA_B64 = base64url:encode(element(2, jose_jwe:to_binary(A_2_1_JWE))),
	% A.2.2
	A_2_2_CEK = ?config("a.2.2.cek", C),
	% A.2.3
	A_2_3_JWK_DATA = ?config("a.2.3.jwk+json", C),
	A_2_3_JWK_MAP = jose:decode(A_2_3_JWK_DATA),
	A_2_3_JWK = jose_jwk:from_binary(A_2_3_JWK_DATA),
	{_, A_2_3_JWK_MAP} = jose_jwk:to_map(A_2_3_JWK),
	A_2_3_CEK_ENCRYPTED = ?config("a.2.3.cek.encrypted", C),
	A_2_3_CEK_ENCRYPTED_B64 = ?config("a.2.3.cek.encrypted.b64", C),
	A_2_3_CEK_ENCRYPTED_B64 = base64url:encode(A_2_3_CEK_ENCRYPTED),
	% A.2.4
	A_2_4_IV = ?config("a.2.4.iv", C),
	A_2_4_IV_B64 = ?config("a.2.4.iv.b64", C),
	A_2_4_IV_B64 = base64url:encode(A_2_4_IV),
	% A.2.5
	A_2_5_AAD = ?config("a.2.5.aad", C),
	A_2_1_JWE_DATA_B64 = A_2_5_AAD,
	% A.2.6
	A_2_6_CIPHER = ?config("a.2.6.txt.cipher", C),
	A_2_6_TAG = ?config("a.2.6.txt.tag", C),
	A_2_6_CIPHER_B64 = ?config("a.2.6.txt.cipher.b64", C),
	A_2_6_TAG_B64 = ?config("a.2.6.txt.tag.b64", C),
	A_2_6_CIPHER = base64url:decode(A_2_6_CIPHER_B64),
	A_2_6_TAG = base64url:decode(A_2_6_TAG_B64),
	% A.2.7
	A_2_7_COMPACT = ?config("a.2.7.jwe+compact", C),
	{A_2_TXT, A_2_1_JWE} = jose_jwe:block_decrypt(A_2_3_JWK, A_2_7_COMPACT),
	% Roundtrip test
	A_2_7_MAP = jose_jwe:block_encrypt(A_2_3_JWK, A_2_TXT, A_2_2_CEK, A_2_4_IV, A_2_1_JWE),
	{A_2_TXT, A_2_1_JWE} = jose_jwe:block_decrypt(A_2_3_JWK, A_2_7_MAP),
	ok.

% JSON Web Encryption (JWE)
% A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
% [https://tools.ietf.org/html/rfc7516#appendix-A.3]
jwe_a_3(Config) ->
	C = ?config(jwe_a_3, Config),
	% A.3
	A_3_TXT = ?config("a.3.txt", C),
	% A.3.1
	A_3_1_JWE_DATA = ?config("a.3.1.jwe+json", C),
	A_3_1_JWE_MAP = jose:decode(A_3_1_JWE_DATA),
	A_3_1_JWE = jose_jwe:from_binary(A_3_1_JWE_DATA),
	{_, A_3_1_JWE_MAP} = jose_jwe:to_map(A_3_1_JWE),
	A_3_1_JWE_DATA_B64 = ?config("a.3.1.jwe+json.b64", C),
	A_3_1_JWE_DATA_B64 = base64url:encode(element(2, jose_jwe:to_binary(A_3_1_JWE))),
	% A.3.2
	A_3_2_CEK = ?config("a.3.2.cek", C),
	% A.3.3
	A_3_3_JWK_DATA = ?config("a.3.3.jwk+json", C),
	A_3_3_JWK_MAP = jose:decode(A_3_3_JWK_DATA),
	A_3_3_JWK = jose_jwk:from_binary(A_3_3_JWK_DATA),
	{_, A_3_3_JWK_MAP} = jose_jwk:to_map(A_3_3_JWK),
	A_3_3_CEK_ENCRYPTED = ?config("a.3.3.cek.encrypted", C),
	A_3_3_CEK_ENCRYPTED_B64 = ?config("a.3.3.cek.encrypted.b64", C),
	A_3_3_CEK_ENCRYPTED_B64 = base64url:encode(A_3_3_CEK_ENCRYPTED),
	% A.3.4
	A_3_4_IV = ?config("a.3.4.iv", C),
	A_3_4_IV_B64 = ?config("a.3.4.iv.b64", C),
	A_3_4_IV_B64 = base64url:encode(A_3_4_IV),
	% A.3.5
	A_3_5_AAD = ?config("a.3.5.aad", C),
	A_3_1_JWE_DATA_B64 = A_3_5_AAD,
	% A.3.6
	A_3_6_CIPHER = ?config("a.3.6.txt.cipher", C),
	A_3_6_TAG = ?config("a.3.6.txt.tag", C),
	A_3_6_CIPHER_B64 = ?config("a.3.6.txt.cipher.b64", C),
	A_3_6_TAG_B64 = ?config("a.3.6.txt.tag.b64", C),
	A_3_6_CIPHER = base64url:decode(A_3_6_CIPHER_B64),
	A_3_6_TAG = base64url:decode(A_3_6_TAG_B64),
	% A.3.7
	A_3_7_COMPACT = ?config("a.3.7.jwe+compact", C),
	{A_3_TXT, A_3_1_JWE} = jose_jwe:block_decrypt(A_3_3_JWK, A_3_7_COMPACT),
	% Roundtrip test
	A_3_7_MAP = jose_jwe:block_encrypt(A_3_3_JWK, A_3_TXT, A_3_2_CEK, A_3_4_IV, A_3_1_JWE),
	{A_3_TXT, A_3_1_JWE} = jose_jwe:block_decrypt(A_3_3_JWK, A_3_7_MAP),
	ok.

% JSON Web Key (JWK)
% Appendix C.  Example Encrypted RSA Private Key
% [https://tools.ietf.org/html/rfc7517#appendix-C]
jwk_c(Config) ->
	C = ?config(jwk_c, Config),
	% C.1
	C_1_JSON_DATA = ?config("c.1.jwk+json", C),
	C_1_JSON = jose:decode(C_1_JSON_DATA),
	C_1_JWK = jose_jwk:from_file(data_file("jwk/c.1.jwk+json", Config)),
	{_, C_1_JSON} = jose_jwk:to_map(C_1_JWK),
	% C.2
	C_2_JSON_DATA = ?config("c.2.jwe+json", C),
	C_2_JSON = jose:decode(C_2_JSON_DATA),
	C_2_JWE = jose_jwe:from_file(data_file("jwk/c.2.jwe+json", Config)),
	{_, C_2_JSON} = jose_jwe:to_map(C_2_JWE),
	C_2_B64_DATA = ?config("c.2.b64", C),
	C_2_B64_DATA = base64url:encode(C_2_JSON_DATA),
	% C.3
	C_3_CEK = ?config("c.3.cek", C),
	% C.4
	C_4_TXT = ?config("c.4.txt", C),
	C_4_SALT = ?config("c.4.salt", C),
	C_4_SALT = << (maps:get(<<"alg">>, C_2_JSON))/binary, 0, (base64url:decode(maps:get(<<"p2s">>, C_2_JSON)))/binary >>,
	C_4_DKEY = ?config("c.4.derivedkey", C),
	{ok, C_4_DKEY} = jose_jwa_pkcs5:pbkdf2({hmac, sha256}, C_4_TXT, C_4_SALT, maps:get(<<"p2c">>, C_2_JSON), 16),
	% C.5
	C_5_EKEY = ?config("c.5.encryptedkey", C),
	{C_5_EKEY, _} = jose_jwe:key_encrypt(C_4_TXT, C_3_CEK, C_2_JWE),
	% C.6
	C_6_IV = ?config("c.6.iv", C),
	% C.7
	C_7_AAD = ?config("c.7.aad", C),
	C_7_AAD = C_2_JSON_DATA,
	% C.8
	C_8_CIPHER_TXT = ?config("c.8.ciphertxt", C),
	C_8_CIPHER_TAG = ?config("c.8.ciphertag", C),
	%% Forcing the AAD data to be C_7_AAD
	C_8_ENC_MAP=#{
		<<"ciphertext">> := C_8_CIPHER_TXT_B64,
		<<"tag">> := C_8_CIPHER_TAG_B64
	} = force_block_encrypt(C_4_TXT, C_1_JSON_DATA, C_3_CEK, C_6_IV, C_7_AAD, C_2_JWE),
	C_8_CIPHER_TXT = base64url:decode(C_8_CIPHER_TXT_B64),
	C_8_CIPHER_TAG = base64url:decode(C_8_CIPHER_TAG_B64),
	% C.9
	C_9_DATA = ?config("c.9.jwe+txt", C),
	{_, C_9_DATA} = jose_jwe:compact(C_8_ENC_MAP),
	%% Make sure decryption also works
	{C_1_JSON_DATA, _} = jose_jwe:block_decrypt(C_4_TXT, C_9_DATA),
	%% Encrypt and Decrypt
	{_, C_1_JWK} = jose_jwk:from_map(C_4_TXT, jose_jwk:to_map(C_4_TXT, C_2_JWE, C_1_JWK)),
	ok.

jwk_rsa_multi(Config) ->
	JWK = jose_jwk:from_pem_file(data_file("rsa-multi.pem", Config)),
	PlainText = <<"I've Got a Lovely Bunch of Coconuts">>,
	Encrypted = jose_jwk:block_encrypt(PlainText, JWK),
	CompactEncrypted = jose_jwe:compact(Encrypted),
	{PlainText, _} = jose_jwk:block_decrypt(Encrypted, JWK),
	{PlainText, _} = jose_jwk:block_decrypt(CompactEncrypted, JWK),
	Message = <<"Secret Message">>,
	Signed = jose_jwk:sign(Message, JWK),
	CompactSigned = jose_jws:compact(Signed),
	{true, Message, _} = jose_jwk:verify(Signed, JWK),
	{true, Message, _} = jose_jwk:verify(CompactSigned, JWK),
	{_, Map} = jose_jwk:to_map(JWK),
	JWK = jose_jwk:from_map(Map),
	Password = <<"My Passphrase">>,
	PEM = element(2, jose_jwk:to_pem(JWK)),
	EncryptedPEM = element(2, jose_jwk:to_pem(Password, JWK)),
	JWK = jose_jwk:from_pem(PEM),
	JWK = jose_jwk:from_pem(Password, EncryptedPEM),
	JWK = jose_jwk:from_pem(jose_jwk:to_pem(JWK)),
	JWK = jose_jwk:from_pem(Password, jose_jwk:to_pem(Password, JWK)),
	{_, JWK} = jose_jwk:from_binary(Password, jose_jwk:to_binary(Password, JWK)),
	{_, JWK} = jose_jwk:from_binary(Password, jose_jwe:compact(jose_jwk:to_map(Password, JWK))),
	ok.

% JSON Web Signature (JWS)
% Appendix A.1.  Example JWS Using HMAC SHA-256
% [https://tools.ietf.org/html/rfc7515#appendix-A.1]
jws_a_1(Config) ->
	C = ?config(jws_a_1, Config),
	% A.1.1
	A_1_1_JSON_DATA = ?config("a.1.1.jws+json", C),
	A_1_1_JSON = jose:decode(A_1_1_JSON_DATA),
	A_1_1_JWS = jose_jws:from_file(data_file("jws/a.1.1.jws+json", Config)),
	{_, A_1_1_JSON} = jose_jws:to_map(A_1_1_JWS),
	A_1_1_B64_DATA = ?config("a.1.1.b64", C),
	A_1_1_B64_DATA = base64url:encode(A_1_1_JSON_DATA),
	A_1_1_PAYLOAD_DATA = ?config("a.1.1.payload", C),
	A_1_1_B64_PAYLOAD_DATA = ?config("a.1.1.payload-b64", C),
	A_1_1_B64_PAYLOAD_DATA = base64url:encode(A_1_1_PAYLOAD_DATA),
	A_1_1_SIGNING_INPUT_DATA = ?config("a.1.1.signing-input", C),
	A_1_1_SIGNING_INPUT_DATA = << A_1_1_B64_DATA/binary, $., A_1_1_B64_PAYLOAD_DATA/binary >>,
	A_1_1_JWK = jose_jwk:from_file(data_file("jws/a.1.1.jwk+json", Config)),
	A_1_1_B64_SIGNATURE_DATA = ?config("a.1.1.signature-b64", C),
	%% Forcing the Protected header to be A_1_1_JSON_DATA
	A_1_1_MAP=#{
		<<"signature">> := A_1_1_B64_SIGNATURE_DATA
	} = force_sign(A_1_1_JWK, A_1_1_PAYLOAD_DATA, A_1_1_JSON_DATA, A_1_1_JWS),
	A_1_1_COMPACT_DATA = ?config("a.1.1.compact", C),
	{_, A_1_1_COMPACT_DATA} = jose_jws:compact(A_1_1_MAP),
	% A.1.2
	{true, A_1_1_PAYLOAD_DATA, A_1_1_JWS} = jose_jws:verify(A_1_1_JWK, A_1_1_MAP),
	{true, A_1_1_PAYLOAD_DATA, A_1_1_JWS} = jose_jws:verify(A_1_1_JWK, A_1_1_COMPACT_DATA),
	%% Sign and Verify
	{true, A_1_1_PAYLOAD_DATA, A_1_1_JWS} = jose_jwk:verify(jose_jwk:sign(A_1_1_PAYLOAD_DATA, A_1_1_JWS, A_1_1_JWK), A_1_1_JWK),
	ok.

% JSON Web Signature (JWS)
% Appendix A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
% [https://tools.ietf.org/html/rfc7515#appendix-A.2]
jws_a_2(Config) ->
	C = ?config(jws_a_2, Config),
	% A.2.1
	A_2_1_JSON_DATA = ?config("a.2.1.jws+json", C),
	A_2_1_JSON = jose:decode(A_2_1_JSON_DATA),
	A_2_1_JWS = jose_jws:from_file(data_file("jws/a.2.1.jws+json", Config)),
	{_, A_2_1_JSON} = jose_jws:to_map(A_2_1_JWS),
	A_2_1_B64_DATA = ?config("a.2.1.b64", C),
	A_2_1_B64_DATA = base64url:encode(A_2_1_JSON_DATA),
	A_2_1_PAYLOAD_DATA = ?config("a.2.1.payload", C),
	A_2_1_B64_PAYLOAD_DATA = ?config("a.2.1.payload-b64", C),
	A_2_1_B64_PAYLOAD_DATA = base64url:encode(A_2_1_PAYLOAD_DATA),
	A_2_1_SIGNING_INPUT_DATA = ?config("a.2.1.signing-input", C),
	A_2_1_SIGNING_INPUT_DATA = << A_2_1_B64_DATA/binary, $., A_2_1_B64_PAYLOAD_DATA/binary >>,
	A_2_1_JWK = jose_jwk:from_file(data_file("jws/a.2.1.jwk+json", Config)),
	A_2_1_B64_SIGNATURE_DATA = ?config("a.2.1.signature-b64", C),
	%% Forcing the Protected header to be A_2_1_JSON_DATA
	A_2_1_MAP=#{
		<<"signature">> := A_2_1_B64_SIGNATURE_DATA
	} = force_sign(A_2_1_JWK, A_2_1_PAYLOAD_DATA, A_2_1_JSON_DATA, A_2_1_JWS),
	A_2_1_COMPACT_DATA = ?config("a.2.1.compact", C),
	{_, A_2_1_COMPACT_DATA} = jose_jws:compact(A_2_1_MAP),
	% A.2.2
	{true, A_2_1_PAYLOAD_DATA, A_2_1_JWS} = jose_jws:verify(A_2_1_JWK, A_2_1_MAP),
	{true, A_2_1_PAYLOAD_DATA, A_2_1_JWS} = jose_jws:verify(A_2_1_JWK, A_2_1_COMPACT_DATA),
	%% Sign and Verify
	{true, A_2_1_PAYLOAD_DATA, A_2_1_JWS} = jose_jwk:verify(jose_jwk:sign(A_2_1_PAYLOAD_DATA, A_2_1_JWS, A_2_1_JWK), A_2_1_JWK),
	ok.

% JSON Web Signature (JWS)
% Appendix A.3.  Example JWS Using ECDSA P-256 SHA-256
% https://tools.ietf.org/html/rfc7515#appendix-A.3
jws_a_3(Config) ->
	C = ?config(jws_a_3, Config),
	% A.3.1
	A_3_1_JSON_DATA = ?config("a.3.1.jws+json", C),
	A_3_1_JSON = jose:decode(A_3_1_JSON_DATA),
	A_3_1_JWS = jose_jws:from_file(data_file("jws/a.3.1.jws+json", Config)),
	{_, A_3_1_JSON} = jose_jws:to_map(A_3_1_JWS),
	A_3_1_B64_DATA = ?config("a.3.1.b64", C),
	A_3_1_B64_DATA = base64url:encode(A_3_1_JSON_DATA),
	A_3_1_PAYLOAD_DATA = ?config("a.3.1.payload", C),
	A_3_1_B64_PAYLOAD_DATA = ?config("a.3.1.payload-b64", C),
	A_3_1_B64_PAYLOAD_DATA = base64url:encode(A_3_1_PAYLOAD_DATA),
	A_3_1_SIGNING_INPUT_DATA = ?config("a.3.1.signing-input", C),
	A_3_1_SIGNING_INPUT_DATA = << A_3_1_B64_DATA/binary, $., A_3_1_B64_PAYLOAD_DATA/binary >>,
	A_3_1_JWK = jose_jwk:from_file(data_file("jws/a.3.1.jwk+json", Config)),
	A_3_1_B64_SIGNATURE_DATA = ?config("a.3.1.signature-b64", C),
	%% Forcing the Protected header to be A_3_1_JSON_DATA
	A_3_1_MAP=#{
		<<"signature">> := A_3_1_B64_SIGNATURE_DATA_ALT
	} = force_sign(A_3_1_JWK, A_3_1_PAYLOAD_DATA, A_3_1_JSON_DATA, A_3_1_JWS),
	%% ECDSA produces non-matching signatures
	true = (A_3_1_B64_SIGNATURE_DATA =/= A_3_1_B64_SIGNATURE_DATA_ALT),
	A_3_1_COMPACT_DATA = ?config("a.3.1.compact", C),
	{_, A_3_1_COMPACT_DATA} = jose_jws:compact(A_3_1_MAP#{ <<"signature">> => A_3_1_B64_SIGNATURE_DATA }),
	% A.3.2
	{true, A_3_1_PAYLOAD_DATA, A_3_1_JWS} = jose_jws:verify(A_3_1_JWK, A_3_1_MAP),
	{true, A_3_1_PAYLOAD_DATA, A_3_1_JWS} = jose_jws:verify(A_3_1_JWK, A_3_1_COMPACT_DATA),
	%% Sign and Verify
	{true, A_3_1_PAYLOAD_DATA, A_3_1_JWS} = jose_jwk:verify(jose_jwk:sign(A_3_1_PAYLOAD_DATA, A_3_1_JWS, A_3_1_JWK), A_3_1_JWK),
	ok.

% JSON Web Signature (JWS)
% Appendix A.4.  Example JWS Using ECDSA P-521 SHA-512
% https://tools.ietf.org/html/rfc7515#appendix-A.4
jws_a_4(Config) ->
	C = ?config(jws_a_4, Config),
	% A.4.1
	A_4_1_JSON_DATA = ?config("a.4.1.jws+json", C),
	A_4_1_JSON = jose:decode(A_4_1_JSON_DATA),
	A_4_1_JWS = jose_jws:from_file(data_file("jws/a.4.1.jws+json", Config)),
	{_, A_4_1_JSON} = jose_jws:to_map(A_4_1_JWS),
	A_4_1_B64_DATA = ?config("a.4.1.b64", C),
	A_4_1_B64_DATA = base64url:encode(A_4_1_JSON_DATA),
	A_4_1_PAYLOAD_DATA = ?config("a.4.1.payload", C),
	A_4_1_B64_PAYLOAD_DATA = ?config("a.4.1.payload-b64", C),
	A_4_1_B64_PAYLOAD_DATA = base64url:encode(A_4_1_PAYLOAD_DATA),
	A_4_1_SIGNING_INPUT_DATA = ?config("a.4.1.signing-input", C),
	A_4_1_SIGNING_INPUT_DATA = << A_4_1_B64_DATA/binary, $., A_4_1_B64_PAYLOAD_DATA/binary >>,
	A_4_1_JWK = jose_jwk:from_file(data_file("jws/a.4.1.jwk+json", Config)),
	A_4_1_B64_SIGNATURE_DATA = ?config("a.4.1.signature-b64", C),
	%% Forcing the Protected header to be A_4_1_JSON_DATA
	A_4_1_MAP=#{
		<<"signature">> := A_4_1_B64_SIGNATURE_DATA_ALT
	} = force_sign(A_4_1_JWK, A_4_1_PAYLOAD_DATA, A_4_1_JSON_DATA, A_4_1_JWS),
	%% ECDSA produces non-matching signatures
	true = (A_4_1_B64_SIGNATURE_DATA =/= A_4_1_B64_SIGNATURE_DATA_ALT),
	A_4_1_COMPACT_DATA = ?config("a.4.1.compact", C),
	{_, A_4_1_COMPACT_DATA} = jose_jws:compact(A_4_1_MAP#{ <<"signature">> => A_4_1_B64_SIGNATURE_DATA }),
	% A.4.2
	{true, A_4_1_PAYLOAD_DATA, A_4_1_JWS} = jose_jws:verify(A_4_1_JWK, A_4_1_MAP),
	{true, A_4_1_PAYLOAD_DATA, A_4_1_JWS} = jose_jws:verify(A_4_1_JWK, A_4_1_COMPACT_DATA),
	%% Sign and Verify
	{true, A_4_1_PAYLOAD_DATA, A_4_1_JWS} = jose_jwk:verify(jose_jwk:sign(A_4_1_PAYLOAD_DATA, A_4_1_JWS, A_4_1_JWK), A_4_1_JWK),
	ok.

% JSON Web Signature (JWS)
% Appendix A.5.  Example Unsecured JWS
% https://tools.ietf.org/html/rfc7515#appendix-A.5
jws_a_5(Config) ->
	C = ?config(jws_a_5, Config),
	% A.5
	A_5_JSON_DATA = ?config("a.5.jws+json", C),
	A_5_JSON = jose:decode(A_5_JSON_DATA),
	A_5_JWS = jose_jws:from_file(data_file("jws/a.5.jws+json", Config)),
	{_, A_5_JSON} = jose_jws:to_map(A_5_JWS),
	A_5_B64_DATA = ?config("a.5.b64", C),
	A_5_B64_DATA = base64url:encode(A_5_JSON_DATA),
	A_5_PAYLOAD_DATA = ?config("a.5.payload", C),
	A_5_B64_PAYLOAD_DATA = ?config("a.5.payload-b64", C),
	A_5_B64_PAYLOAD_DATA = base64url:encode(A_5_PAYLOAD_DATA),
	A_5_SIGNING_INPUT_DATA = ?config("a.5.signing-input", C),
	A_5_SIGNING_INPUT_DATA = << A_5_B64_DATA/binary, $., A_5_B64_PAYLOAD_DATA/binary >>,
	%% Forcing the Protected header to be A_5_JSON_DATA
	A_5_MAP=#{
		<<"signature">> := <<>>
	} = force_sign(none, A_5_PAYLOAD_DATA, A_5_JSON_DATA, A_5_JWS),
	A_5_COMPACT_DATA = ?config("a.5.compact", C),
	{_, A_5_COMPACT_DATA} = jose_jws:compact(A_5_MAP),
	{true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(none, A_5_MAP),
	{true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(none, A_5_COMPACT_DATA),
	%% Sign and Verify
	{true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(none, jose_jws:sign(none, A_5_PAYLOAD_DATA, A_5_JWS)),
	ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
force_block_encrypt(Key, PlainText, CEK, IV, OverrideProtected, JWE=#jose_jwe{alg={ALGModule, ALG}, enc={ENCModule, ENC}}) ->
	{EncryptedKey, _} = ALGModule:key_encrypt(Key, CEK, ALG),
	Protected = base64url:encode(OverrideProtected),
	{CipherText, CipherTag} = ENCModule:block_encrypt({Protected, maybe_compress(PlainText, JWE)}, CEK, IV, ENC),
	#{
		<<"protected">> => Protected,
		<<"encrypted_key">> => base64url:encode(EncryptedKey),
		<<"iv">> => base64url:encode(IV),
		<<"ciphertext">> => base64url:encode(CipherText),
		<<"tag">> => base64url:encode(CipherTag)
	}.

%% @private
force_sign(Key, PlainText, OverrideProtected, #jose_jws{alg={ALGModule, ALG}}) ->
	Protected = base64url:encode(OverrideProtected),
	Payload = base64url:encode(PlainText),
	Message = << Protected/binary, $., Payload/binary >>,
	Signature = base64url:encode(ALGModule:sign(Key, Message, ALG)),
	#{
		<<"payload">> => Payload,
		<<"protected">> => Protected,
		<<"signature">> => Signature
	}.

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
maybe_compress(PlainText, #jose_jwe{zip={Module, ZIP}}) ->
	Module:compress(PlainText, ZIP);
maybe_compress(PlainText, _) ->
	PlainText.
