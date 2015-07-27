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
-export([jwk_c/1]).
-export([jws_a_1/1]).
-export([jws_a_2/1]).
-export([jws_a_3/1]).
-export([jws_a_4/1]).
-export([jws_a_5/1]).

all() ->
	[
		{group, jose_jwk},
		{group, jose_jws}
	].

groups() ->
	[
		{jose_jwk, [parallel], [
			jwk_c
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
	_ = application:ensure_all_started(jose),
	Config.

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

% JSON Web Key (JWK)
% Appendix C.  Example Encrypted RSA Private Key
% https://tools.ietf.org/html/rfc7517#appendix-C
jwk_c(C) ->
	% C.1
	C_1_JSON_DATA = read_file("jwk/c.1.jwk+json", C),
	C_1_JSON = jsx:decode(C_1_JSON_DATA, [return_maps]),
	C_1_JWK = jose_jwk:from_file(data_file("jwk/c.1.jwk+json", C)),
	{_, C_1_JSON} = jose_jwk:to_map(C_1_JWK),
	% C.2
	C_2_JSON_DATA = read_file("jwk/c.2.jwe+json", C),
	C_2_JSON = jsx:decode(C_2_JSON_DATA, [return_maps]),
	C_2_JWE = jose_jwe:from_file(data_file("jwk/c.2.jwe+json", C)),
	{_, C_2_JSON} = jose_jwe:to_map(C_2_JWE),
	C_2_B64_DATA = read_file("jwk/c.2.b64", C),
	C_2_B64_DATA = base64url:encode(C_2_JSON_DATA),
	% C.3
	C_3_CEK = read_file("jwk/c.3.cek", C),
	% C.4
	C_4_TXT = read_file("jwk/c.4.txt", C),
	C_4_SALT = read_file("jwk/c.4.salt", C),
	C_4_SALT = << (maps:get(<<"alg">>, C_2_JSON))/binary, 0, (base64url:decode(maps:get(<<"p2s">>, C_2_JSON)))/binary >>,
	C_4_DKEY = read_file("jwk/c.4.derivedkey", C),
	{ok, C_4_DKEY} = jose_jwa_pkcs5:pbkdf2({hmac, sha256}, C_4_TXT, C_4_SALT, maps:get(<<"p2c">>, C_2_JSON), 16),
	% C.5
	C_5_EKEY = read_file("jwk/c.5.encryptedkey", C),
	{C_5_EKEY, _} = jose_jwe:key_encrypt(C_4_TXT, C_3_CEK, C_2_JWE),
	% C.6
	C_6_IV = read_file("jwk/c.6.iv", C),
	% C.7
	C_7_AAD = read_file("jwk/c.7.aad", C),
	C_7_AAD = C_2_JSON_DATA,
	% C.8
	C_8_CIPHER_TXT = read_file("jwk/c.8.ciphertxt", C),
	C_8_CIPHER_TAG = read_file("jwk/c.8.ciphertag", C),
	%% Forcing the AAD data to be C_7_AAD
	C_8_ENC_MAP=#{
		<<"ciphertext">> := C_8_CIPHER_TXT_B64,
		<<"tag">> := C_8_CIPHER_TAG_B64
	} = force_block_encrypt(C_4_TXT, C_1_JSON_DATA, C_3_CEK, C_6_IV, C_7_AAD, C_2_JWE),
	C_8_CIPHER_TXT = base64url:decode(C_8_CIPHER_TXT_B64),
	C_8_CIPHER_TAG = base64url:decode(C_8_CIPHER_TAG_B64),
	% C.9
	C_9_DATA = read_file("jwk/c.9.jwe+txt", C),
	{_, C_9_DATA} = jose_jwe:compact(C_8_ENC_MAP),
	%% Make sure decryption also works
	{C_1_JSON_DATA, _} = jose_jwe:block_decrypt(C_4_TXT, C_9_DATA),
	%% Encrypt and Decrypt
	{_, C_1_JWK} = jose_jwk:from_map(C_4_TXT, jose_jwk:to_map(C_4_TXT, C_2_JWE, C_1_JWK)),
	ok.

% JSON Web Signature (JWS)
% Appendix A.1.  Example JWS Using HMAC SHA-256
% https://tools.ietf.org/html/rfc7515#appendix-A.1
jws_a_1(C) ->
	% A.1.1
	A_1_1_JSON_DATA = read_file("jws/a.1.1.jws+json", C),
	A_1_1_JSON = jsx:decode(A_1_1_JSON_DATA, [return_maps]),
	A_1_1_JWS = jose_jws:from_file(data_file("jws/a.1.1.jws+json", C)),
	{_, A_1_1_JSON} = jose_jws:to_map(A_1_1_JWS),
	A_1_1_B64_DATA = read_file("jws/a.1.1.b64", C),
	A_1_1_B64_DATA = base64url:encode(A_1_1_JSON_DATA),
	A_1_1_PAYLOAD_DATA = read_file("jws/a.1.1.payload", C),
	A_1_1_B64_PAYLOAD_DATA = read_file("jws/a.1.1.payload-b64", C),
	A_1_1_B64_PAYLOAD_DATA = base64url:encode(A_1_1_PAYLOAD_DATA),
	A_1_1_SIGNING_INPUT_DATA = read_file("jws/a.1.1.signing-input", C),
	A_1_1_SIGNING_INPUT_DATA = << A_1_1_B64_DATA/binary, $., A_1_1_B64_PAYLOAD_DATA/binary >>,
	A_1_1_JWK = jose_jwk:from_file(data_file("jws/a.1.1.jwk+json", C)),
	A_1_1_B64_SIGNATURE_DATA = read_file("jws/a.1.1.signature-b64", C),
	%% Forcing the Protected header to be A_1_1_JSON_DATA
	A_1_1_MAP=#{
		<<"signature">> := A_1_1_B64_SIGNATURE_DATA
	} = force_sign(A_1_1_JWK, A_1_1_PAYLOAD_DATA, A_1_1_JSON_DATA, A_1_1_JWS),
	A_1_1_COMPACT_DATA = read_file("jws/a.1.1.compact", C),
	{_, A_1_1_COMPACT_DATA} = jose_jws:compact(A_1_1_MAP),
	% A.1.2
	{true, A_1_1_PAYLOAD_DATA, A_1_1_JWS} = jose_jws:verify(A_1_1_JWK, A_1_1_MAP),
	{true, A_1_1_PAYLOAD_DATA, A_1_1_JWS} = jose_jws:verify(A_1_1_JWK, A_1_1_COMPACT_DATA),
	%% Sign and Verify
	{true, A_1_1_PAYLOAD_DATA, A_1_1_JWS} = jose_jwk:verify(jose_jwk:sign(A_1_1_PAYLOAD_DATA, A_1_1_JWS, A_1_1_JWK), A_1_1_JWK),
	ok.

% JSON Web Signature (JWS)
% Appendix A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
% https://tools.ietf.org/html/rfc7515#appendix-A.2
jws_a_2(C) ->
	% A.2.1
	A_2_1_JSON_DATA = read_file("jws/a.2.1.jws+json", C),
	A_2_1_JSON = jsx:decode(A_2_1_JSON_DATA, [return_maps]),
	A_2_1_JWS = jose_jws:from_file(data_file("jws/a.2.1.jws+json", C)),
	{_, A_2_1_JSON} = jose_jws:to_map(A_2_1_JWS),
	A_2_1_B64_DATA = read_file("jws/a.2.1.b64", C),
	A_2_1_B64_DATA = base64url:encode(A_2_1_JSON_DATA),
	A_2_1_PAYLOAD_DATA = read_file("jws/a.2.1.payload", C),
	A_2_1_B64_PAYLOAD_DATA = read_file("jws/a.2.1.payload-b64", C),
	A_2_1_B64_PAYLOAD_DATA = base64url:encode(A_2_1_PAYLOAD_DATA),
	A_2_1_SIGNING_INPUT_DATA = read_file("jws/a.2.1.signing-input", C),
	A_2_1_SIGNING_INPUT_DATA = << A_2_1_B64_DATA/binary, $., A_2_1_B64_PAYLOAD_DATA/binary >>,
	A_2_1_JWK = jose_jwk:from_file(data_file("jws/a.2.1.jwk+json", C)),
	A_2_1_B64_SIGNATURE_DATA = read_file("jws/a.2.1.signature-b64", C),
	%% Forcing the Protected header to be A_2_1_JSON_DATA
	A_2_1_MAP=#{
		<<"signature">> := A_2_1_B64_SIGNATURE_DATA
	} = force_sign(A_2_1_JWK, A_2_1_PAYLOAD_DATA, A_2_1_JSON_DATA, A_2_1_JWS),
	A_2_1_COMPACT_DATA = read_file("jws/a.2.1.compact", C),
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
jws_a_3(C) ->
	% A.3.1
	A_3_1_JSON_DATA = read_file("jws/a.3.1.jws+json", C),
	A_3_1_JSON = jsx:decode(A_3_1_JSON_DATA, [return_maps]),
	A_3_1_JWS = jose_jws:from_file(data_file("jws/a.3.1.jws+json", C)),
	{_, A_3_1_JSON} = jose_jws:to_map(A_3_1_JWS),
	A_3_1_B64_DATA = read_file("jws/a.3.1.b64", C),
	A_3_1_B64_DATA = base64url:encode(A_3_1_JSON_DATA),
	A_3_1_PAYLOAD_DATA = read_file("jws/a.3.1.payload", C),
	A_3_1_B64_PAYLOAD_DATA = read_file("jws/a.3.1.payload-b64", C),
	A_3_1_B64_PAYLOAD_DATA = base64url:encode(A_3_1_PAYLOAD_DATA),
	A_3_1_SIGNING_INPUT_DATA = read_file("jws/a.3.1.signing-input", C),
	A_3_1_SIGNING_INPUT_DATA = << A_3_1_B64_DATA/binary, $., A_3_1_B64_PAYLOAD_DATA/binary >>,
	A_3_1_JWK = jose_jwk:from_file(data_file("jws/a.3.1.jwk+json", C)),
	A_3_1_B64_SIGNATURE_DATA = read_file("jws/a.3.1.signature-b64", C),
	%% Forcing the Protected header to be A_3_1_JSON_DATA
	A_3_1_MAP=#{
		<<"signature">> := A_3_1_B64_SIGNATURE_DATA_ALT
	} = force_sign(A_3_1_JWK, A_3_1_PAYLOAD_DATA, A_3_1_JSON_DATA, A_3_1_JWS),
	%% ECDSA produces non-matching signatures
	true = (A_3_1_B64_SIGNATURE_DATA =/= A_3_1_B64_SIGNATURE_DATA_ALT),
	A_3_1_COMPACT_DATA = read_file("jws/a.3.1.compact", C),
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
jws_a_4(C) ->
	% A.4.1
	A_4_1_JSON_DATA = read_file("jws/a.4.1.jws+json", C),
	A_4_1_JSON = jsx:decode(A_4_1_JSON_DATA, [return_maps]),
	A_4_1_JWS = jose_jws:from_file(data_file("jws/a.4.1.jws+json", C)),
	{_, A_4_1_JSON} = jose_jws:to_map(A_4_1_JWS),
	A_4_1_B64_DATA = read_file("jws/a.4.1.b64", C),
	A_4_1_B64_DATA = base64url:encode(A_4_1_JSON_DATA),
	A_4_1_PAYLOAD_DATA = read_file("jws/a.4.1.payload", C),
	A_4_1_B64_PAYLOAD_DATA = read_file("jws/a.4.1.payload-b64", C),
	A_4_1_B64_PAYLOAD_DATA = base64url:encode(A_4_1_PAYLOAD_DATA),
	A_4_1_SIGNING_INPUT_DATA = read_file("jws/a.4.1.signing-input", C),
	A_4_1_SIGNING_INPUT_DATA = << A_4_1_B64_DATA/binary, $., A_4_1_B64_PAYLOAD_DATA/binary >>,
	A_4_1_JWK = jose_jwk:from_file(data_file("jws/a.4.1.jwk+json", C)),
	A_4_1_B64_SIGNATURE_DATA = read_file("jws/a.4.1.signature-b64", C),
	%% Forcing the Protected header to be A_4_1_JSON_DATA
	A_4_1_MAP=#{
		<<"signature">> := A_4_1_B64_SIGNATURE_DATA_ALT
	} = force_sign(A_4_1_JWK, A_4_1_PAYLOAD_DATA, A_4_1_JSON_DATA, A_4_1_JWS),
	%% ECDSA produces non-matching signatures
	true = (A_4_1_B64_SIGNATURE_DATA =/= A_4_1_B64_SIGNATURE_DATA_ALT),
	A_4_1_COMPACT_DATA = read_file("jws/a.4.1.compact", C),
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
jws_a_5(C) ->
	% A.5
	A_5_JSON_DATA = read_file("jws/a.5.jws+json", C),
	A_5_JSON = jsx:decode(A_5_JSON_DATA, [return_maps]),
	A_5_JWS = jose_jws:from_file(data_file("jws/a.5.jws+json", C)),
	{_, A_5_JSON} = jose_jws:to_map(A_5_JWS),
	A_5_B64_DATA = read_file("jws/a.5.b64", C),
	A_5_B64_DATA = base64url:encode(A_5_JSON_DATA),
	A_5_PAYLOAD_DATA = read_file("jws/a.5.payload", C),
	A_5_B64_PAYLOAD_DATA = read_file("jws/a.5.payload-b64", C),
	A_5_B64_PAYLOAD_DATA = base64url:encode(A_5_PAYLOAD_DATA),
	A_5_SIGNING_INPUT_DATA = read_file("jws/a.5.signing-input", C),
	A_5_SIGNING_INPUT_DATA = << A_5_B64_DATA/binary, $., A_5_B64_PAYLOAD_DATA/binary >>,
	%% Forcing the Protected header to be A_5_JSON_DATA
	A_5_MAP=#{
		<<"signature">> := <<>>
	} = force_sign(none, A_5_PAYLOAD_DATA, A_5_JSON_DATA, A_5_JWS),
	A_5_COMPACT_DATA = read_file("jws/a.5.compact", C),
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

%% @private
read_file(File, Config) ->
	{ok, Binary} = file:read_file(data_file(File, Config)),
	Binary.
