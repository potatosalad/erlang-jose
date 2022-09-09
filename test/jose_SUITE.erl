%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
-module(jose_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("jose_public_key.hrl").
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
-export([jose_cfrg_curves_a_1/1]).
-export([jose_cfrg_curves_a_2/1]).
-export([jose_cfrg_curves_a_3/1]).
-export([jose_cfrg_curves_a_4/1]).
-export([jose_cfrg_curves_a_5/1]).
-export([jose_cfrg_curves_a_6/1]).
-export([jose_cfrg_curves_a_7/1]).
-export([jose_ecdh_1pu_a/1]).
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
-export([rfc7520_5_9/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
    case erlang:apply(M, F, A) of
        E ->
            ok;
        T ->
            ct:fail({{M, F, A}, {expected, E}, {got, T}})
    end
).

all() ->
    [
        {group, jose_cfrg_curves},
        {group, jose_ecdh_1pu},
        {group, jose_jwe},
        {group, jose_jwk},
        {group, jose_jws},
        {group, rfc7520}
    ].

groups() ->
    [
        {jose_cfrg_curves, [parallel], [
            jose_cfrg_curves_a_1,
            jose_cfrg_curves_a_2,
            jose_cfrg_curves_a_3,
            jose_cfrg_curves_a_4,
            jose_cfrg_curves_a_5,
            jose_cfrg_curves_a_6,
            jose_cfrg_curves_a_7
        ]},
        {jose_ecdh_1pu, [parallel], [
            jose_ecdh_1pu_a
        ]},
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
        ]},
        {rfc7520, [parallel], [
            rfc7520_5_9
        ]}
    ].

init_per_suite(Config) ->
    application:set_env(jose, crypto_fallback, true),
    application:set_env(jose, unsecured_signing, true),
    _ = application:ensure_all_started(jose),
    Config.

end_per_suite(_Config) ->
    _ = application:stop(jose),
    ok.

init_per_group(G = jose_cfrg_curves, Config) ->
    {ok, A1} = file:consult(data_file("jose_cfrg_curves/a.1.config", Config)),
    {ok, A3} = file:consult(data_file("jose_cfrg_curves/a.3.config", Config)),
    {ok, A4} = file:consult(data_file("jose_cfrg_curves/a.4.config", Config)),
    {ok, A5} = file:consult(data_file("jose_cfrg_curves/a.5.config", Config)),
    {ok, A6} = file:consult(data_file("jose_cfrg_curves/a.6.config", Config)),
    {ok, A7} = file:consult(data_file("jose_cfrg_curves/a.7.config", Config)),
    [
        {jose_cfrg_curves_a_1, A1},
        {jose_cfrg_curves_a_3, A3},
        {jose_cfrg_curves_a_4, A4},
        {jose_cfrg_curves_a_5, A5},
        {jose_cfrg_curves_a_6, A6},
        {jose_cfrg_curves_a_7, A7}
        | jose_ct:start(G, Config)
    ];
init_per_group(G = jose_ecdh_1pu, Config) ->
    {ok, A} = file:consult(data_file("jose_ecdh_1pu/a.config", Config)),
    [{jose_ecdh_1pu_a, A} | jose_ct:start(G, Config)];
init_per_group(G = jose_jwe, Config) ->
    {ok, A1} = file:consult(data_file("jwe/a.1.config", Config)),
    {ok, A2} = file:consult(data_file("jwe/a.2.config", Config)),
    {ok, A3} = file:consult(data_file("jwe/a.3.config", Config)),
    [{jwe_a_1, A1}, {jwe_a_2, A2}, {jwe_a_3, A3} | jose_ct:start(G, Config)];
init_per_group(G = jose_jwk, Config) ->
    {ok, C} = file:consult(data_file("jwk/c.config", Config)),
    [{jwk_c, C} | jose_ct:start(G, Config)];
init_per_group(G = jose_jws, Config) ->
    {ok, A1} = file:consult(data_file("jws/a.1.config", Config)),
    {ok, A2} = file:consult(data_file("jws/a.2.config", Config)),
    {ok, A3} = file:consult(data_file("jws/a.3.config", Config)),
    {ok, A4} = file:consult(data_file("jws/a.4.config", Config)),
    {ok, A5} = file:consult(data_file("jws/a.5.config", Config)),
    [{jws_a_1, A1}, {jws_a_2, A2}, {jws_a_3, A3}, {jws_a_4, A4}, {jws_a_5, A5} | jose_ct:start(G, Config)];
init_per_group(G = rfc7520, Config) ->
    {ok, V_5_9} = file:consult(data_file("rfc7520/5.9.config", Config)),
    [{rfc7520_5_9, V_5_9} | jose_ct:start(G, Config)];
init_per_group(Group, Config) ->
    jose_ct:start(Group, Config).

end_per_group(_Group, Config) ->
    jose_ct:stop(Config),
    ok.

%%====================================================================
%% Tests
%%====================================================================

% CFRG ECDH and signatures in JOSE
% A.1.  Ed25519 private key
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.1]
jose_cfrg_curves_a_1(Config) ->
    C = ?config(jose_cfrg_curves_a_1, Config),
    % A.1
    A_1_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.1.jwk+json", Config)),
    A_1_Secret = hex:hex_to_bin(?config("a.1.secret", C)),
    A_1_PK = hex:hex_to_bin(?config("a.1.pk", C)),
    % A_1_SK = << A_1_Secret/binary, A_1_PK/binary >>,
    {_, #'jose_EdDSA25519PrivateKey'{
        publicKey = #'jose_EdDSA25519PublicKey'{publicKey = A_1_PK},
        privateKey = A_1_Secret
    }} = jose_jwk:to_key(A_1_JWK),
    {_, #'jose_EdDSA25519PublicKey'{publicKey = A_1_PK}} = jose_jwk:to_public_key(A_1_JWK),
    ok.

% CFRG ECDH and signatures in JOSE
% A.2.  Ed25519 public key
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.2]
jose_cfrg_curves_a_2(Config) ->
    % A.1
    A_1_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.1.jwk+json", Config)),
    % A.2
    A_2_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.2.jwk+json", Config)),
    A_2_JWK = jose_jwk:to_public(A_1_JWK),
    ok.

% CFRG ECDH and signatures in JOSE
% A.3.  JWK thumbprint canonicalization
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.3]
jose_cfrg_curves_a_3(Config) ->
    C = ?config(jose_cfrg_curves_a_3, Config),
    % A.1
    A_1_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.1.jwk+json", Config)),
    % A.2
    A_2_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.2.jwk+json", Config)),
    % A.3
    A_3_JWK = jose_jwk:from_binary(?config("a.3.jwk+json", C)),
    A_3_THUMBPRINT_HEX = ?config("a.3.thumbprint+hex", C),
    A_3_THUMBPRINT = jose_jwa_base64url:encode(hex:hex_to_bin(A_3_THUMBPRINT_HEX)),
    A_3_THUMBPRINT = ?config("a.3.thumbprint+b64", C),
    A_3_THUMBPRINT = jose_jwk:thumbprint(A_1_JWK),
    A_3_THUMBPRINT = jose_jwk:thumbprint(A_2_JWK),
    A_3_THUMBPRINT = jose_jwk:thumbprint(A_3_JWK),
    ok.

% CFRG ECDH and signatures in JOSE
% A.4.  Ed25519 Signing
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.4]
jose_cfrg_curves_a_4(Config) ->
    C = ?config(jose_cfrg_curves_a_4, Config),
    % A.1
    A_1_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.1.jwk+json", Config)),
    % A.4
    A_4_PROTECTED = ?config("a.4.jws+json", C),
    A_4_JWS = jose_jws:from_binary(A_4_PROTECTED),
    A_4_JWS_B64 = ?config("a.4.jws+b64", C),
    A_4_TXT = ?config("a.4.txt", C),
    A_4_TXT_B64 = ?config("a.4.txt+b64", C),
    A_4_SIGNINGINPUT = ?config("a.4.signing-input", C),
    A_4_SIG = hex:hex_to_bin(?config("a.4.sig+hex", C)),
    A_4_SIG_B64 = ?config("a.4.sig+b64", C),
    A_4_SIG_COMPACT = ?config("a.4.sig+compact", C),
    A_4_TXT_B64 = jose_jwa_base64url:encode(A_4_TXT),
    A_4_SIGNINGINPUT = <<A_4_JWS_B64/binary, $., A_4_TXT_B64/binary>>,
    A_4_SIGNINGINPUT = jose_jws:signing_input(A_4_TXT, A_4_JWS),
    %% Forcing the Protected header to be A_4_PROTECTED
    A_4_MAP =
        #{
            <<"signature">> := A_4_SIG_B64
        } = force_sign(A_1_JWK, A_4_TXT, A_4_PROTECTED, A_4_JWS),
    A_4_SIG = jose_jwa_base64url:decode(A_4_SIG_B64),
    {_, A_4_SIG_COMPACT} = jose_jws:compact(A_4_MAP),
    ok.

% CFRG ECDH and signatures in JOSE
% A.5.  Ed25519 Validation
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.5]
jose_cfrg_curves_a_5(Config) ->
    C = ?config(jose_cfrg_curves_a_5, Config),
    % A.1
    A_1_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.1.jwk+json", Config)),
    % A.2
    A_2_JWK = jose_jwk:from_file(data_file("jose_cfrg_curves/a.2.jwk+json", Config)),
    % A.4
    A_5_SIG_COMPACT = ?config("a.5.sig+compact", C),
    A_5_JWS = jose_jws:from_binary(?config("a.5.jws+json", C)),
    A_5_PAYLOAD_DATA = ?config("a.5.txt", C),
    {true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(A_1_JWK, A_5_SIG_COMPACT),
    {true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(A_2_JWK, A_5_SIG_COMPACT),
    ok.

% CFRG ECDH and signatures in JOSE
% A.6.  ECDH-ES with X25519
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.6]
jose_cfrg_curves_a_6(Config) ->
    C = ?config(jose_cfrg_curves_a_6, Config),
    % A.6
    A_6_BOB_JWK = jose_jwk:from_binary(?config("a.6.bob-jwk+json", C)),
    A_6_BOB_Secret = hex:hex_to_bin(?config("a.6.bob-secret+hex", C)),
    A_6_BOB_PK = hex:hex_to_bin(?config("a.6.bob-pk+hex", C)),
    A_6_EPK_Secret = hex:hex_to_bin(?config("a.6.epk-secret+hex", C)),
    A_6_EPK_PK = hex:hex_to_bin(?config("a.6.epk-pk+hex", C)),
    A_6_EPK_JWK = jose_jwk:from_binary(?config("a.6.epk-jwk+json", C)),
    A_6_PROTECTED = ?config("a.6.jwe+json", C),
    A_6_JWE = jose_jwe:from_binary(A_6_PROTECTED),
    A_6_Z = hex:hex_to_bin(?config("a.6.z+hex", C)),
    A_6_BOB_SK = <<A_6_BOB_Secret/binary, A_6_BOB_PK/binary>>,
    A_6_EPK_SK = <<A_6_EPK_Secret/binary, A_6_EPK_PK/binary>>,
    A_6_BOB_S_JWK = jose_jwk:from_okp({'X25519', A_6_BOB_SK}),
    A_6_EPK_S_JWK = jose_jwk:from_okp({'X25519', A_6_EPK_SK}),
    {_, #'jose_X25519PrivateKey'{
        publicKey = #'jose_X25519PublicKey'{publicKey = A_6_BOB_PK},
        privateKey = A_6_BOB_Secret
    }} = jose_jwk:to_key(A_6_BOB_S_JWK),
    {_, #'jose_X25519PublicKey'{publicKey = A_6_BOB_PK}} = jose_jwk:to_public_key(A_6_BOB_S_JWK),
    {_, #'jose_X25519PublicKey'{publicKey = A_6_BOB_PK}} = jose_jwk:to_key(A_6_BOB_JWK),
    {_, #'jose_X25519PrivateKey'{
        publicKey = #'jose_X25519PublicKey'{publicKey = A_6_EPK_PK},
        privateKey = A_6_EPK_Secret
    }} = jose_jwk:to_key(A_6_EPK_S_JWK),
    {_, #'jose_X25519PublicKey'{publicKey = A_6_EPK_PK}} = jose_jwk:to_public_key(A_6_EPK_S_JWK),
    {_, #'jose_X25519PublicKey'{publicKey = A_6_EPK_PK}} = jose_jwk:to_key(A_6_EPK_JWK),
    A_6_Z = jose_jwk:shared_secret(A_6_BOB_JWK, A_6_EPK_S_JWK),
    A_6_Z = jose_jwk:shared_secret(A_6_EPK_JWK, A_6_BOB_S_JWK),
    A_6_TEXT = <<"Example of X25519 encryption">>,
    {_, A_6_ENC_MAP} = jose_jwe:block_encrypt({A_6_BOB_JWK, A_6_EPK_S_JWK}, A_6_TEXT, A_6_JWE),
    {_, A_6_ENC_COMPACT} = jose_jwe:compact(A_6_ENC_MAP),
    {A_6_TEXT, A_6_JWE} = jose_jwe:block_decrypt(A_6_BOB_S_JWK, A_6_ENC_MAP),
    {A_6_TEXT, A_6_JWE} = jose_jwe:block_decrypt(A_6_BOB_S_JWK, A_6_ENC_COMPACT),
    ok.

% CFRG ECDH and signatures in JOSE
% A.7.  ECDH-ES with X448
% [https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-00#appendix-A.7]
jose_cfrg_curves_a_7(Config) ->
    C = ?config(jose_cfrg_curves_a_7, Config),
    % A.7
    A_7_BOB_JWK = jose_jwk:from_binary(?config("a.7.bob-jwk+json", C)),
    A_7_BOB_Secret = hex:hex_to_bin(?config("a.7.bob-secret+hex", C)),
    A_7_BOB_PK = hex:hex_to_bin(?config("a.7.bob-pk+hex", C)),
    A_7_EPK_Secret = hex:hex_to_bin(?config("a.7.epk-secret+hex", C)),
    A_7_EPK_PK = hex:hex_to_bin(?config("a.7.epk-pk+hex", C)),
    A_7_EPK_JWK = jose_jwk:from_binary(?config("a.7.epk-jwk+json", C)),
    A_7_PROTECTED = ?config("a.7.jwe+json", C),
    A_7_JWE = jose_jwe:from_binary(A_7_PROTECTED),
    A_7_Z = hex:hex_to_bin(?config("a.7.z+hex", C)),
    A_7_BOB_SK = <<A_7_BOB_Secret/binary, A_7_BOB_PK/binary>>,
    A_7_EPK_SK = <<A_7_EPK_Secret/binary, A_7_EPK_PK/binary>>,
    A_7_BOB_S_JWK = jose_jwk:from_okp({'X448', A_7_BOB_SK}),
    A_7_EPK_S_JWK = jose_jwk:from_okp({'X448', A_7_EPK_SK}),
    {_, #'jose_X448PrivateKey'{
        publicKey = #'jose_X448PublicKey'{publicKey = A_7_BOB_PK},
        privateKey = A_7_BOB_Secret
    }} = jose_jwk:to_key(A_7_BOB_S_JWK),
    {_, #'jose_X448PublicKey'{publicKey = A_7_BOB_PK}} = jose_jwk:to_public_key(A_7_BOB_S_JWK),
    {_, #'jose_X448PublicKey'{publicKey = A_7_BOB_PK}} = jose_jwk:to_key(A_7_BOB_JWK),
    {_, #'jose_X448PrivateKey'{
        publicKey = #'jose_X448PublicKey'{publicKey = A_7_EPK_PK},
        privateKey = A_7_EPK_Secret
    }} = jose_jwk:to_key(A_7_EPK_S_JWK),
    {_, #'jose_X448PublicKey'{publicKey = A_7_EPK_PK}} = jose_jwk:to_public_key(A_7_EPK_S_JWK),
    {_, #'jose_X448PublicKey'{publicKey = A_7_EPK_PK}} = jose_jwk:to_key(A_7_EPK_JWK),
    A_7_Z = jose_jwk:shared_secret(A_7_BOB_JWK, A_7_EPK_S_JWK),
    A_7_Z = jose_jwk:shared_secret(A_7_EPK_JWK, A_7_BOB_S_JWK),
    A_7_TEXT = <<"Example of X448 encryption">>,
    {_, A_7_ENC_MAP} = jose_jwe:block_encrypt({A_7_BOB_JWK, A_7_EPK_S_JWK}, A_7_TEXT, A_7_JWE),
    {_, A_7_ENC_COMPACT} = jose_jwe:compact(A_7_ENC_MAP),
    {A_7_TEXT, A_7_JWE} = jose_jwe:block_decrypt(A_7_BOB_S_JWK, A_7_ENC_MAP),
    {A_7_TEXT, A_7_JWE} = jose_jwe:block_decrypt(A_7_BOB_S_JWK, A_7_ENC_COMPACT),
    ok.

% Public Key Authenticated Encryption for JOSE: ECDH-1PU
% A.  Example ECDH-1PU Key Agreement Computation with A256GCM
% [https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-A]
jose_ecdh_1pu_a(Config) ->
    C = ?config(jose_ecdh_1pu_a, Config),
    A_USSK_JWK = jose_jwk:from_binary(?config("a.ussk.jwk+json", C)),
    A_VSSK_JWK = jose_jwk:from_binary(?config("a.vssk.jwk+json", C)),
    A_UESK_JWK = jose_jwk:from_binary(?config("a.uesk.jwk+json", C)),
    A_JWE = jose_jwe:from_binary(?config("a.jwe+json", C)),
    A_ZE = hex:hex_to_bin(?config("a.ze+hex", C)),
    A_ZS = hex:hex_to_bin(?config("a.zs+hex", C)),
    A_Z = hex:hex_to_bin(?config("a.z+hex", C)),
    A_CEK = hex:hex_to_bin(?config("a.cek+hex", C)),
    A_ZE = jose_jwk:shared_secret(A_VSSK_JWK, A_UESK_JWK),
    A_ZS = jose_jwk:shared_secret(A_VSSK_JWK, A_USSK_JWK),
    A_ZS = jose_jwk:shared_secret(A_USSK_JWK, A_VSSK_JWK),
    A_Z = <<A_ZE/binary, A_ZS/binary>>,
    {A_CEK, _} = jose_jwe:next_cek({A_VSSK_JWK, A_USSK_JWK, A_UESK_JWK}, A_JWE),
    A_CEK = jose_jwe:key_decrypt({A_USSK_JWK, A_VSSK_JWK, A_UESK_JWK}, <<>>, A_JWE),
    ok.

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
    A_1_1_JWE_DATA_B64 = jose_jwa_base64url:encode(element(2, jose_jwe:to_binary(A_1_1_JWE))),
    % A.1.2
    A_1_2_CEK = ?config("a.1.2.cek", C),
    % A.1.3
    A_1_3_JWK_DATA = ?config("a.1.3.jwk+json", C),
    A_1_3_JWK_MAP = jose:decode(A_1_3_JWK_DATA),
    A_1_3_JWK = jose_jwk:from_binary(A_1_3_JWK_DATA),
    {_, A_1_3_JWK_MAP} = jose_jwk:to_map(A_1_3_JWK),
    A_1_3_CEK_ENCRYPTED = ?config("a.1.3.cek.encrypted", C),
    A_1_3_CEK_ENCRYPTED_B64 = ?config("a.1.3.cek.encrypted.b64", C),
    A_1_3_CEK_ENCRYPTED_B64 = jose_jwa_base64url:encode(A_1_3_CEK_ENCRYPTED),
    % A.1.4
    A_1_4_IV = ?config("a.1.4.iv", C),
    A_1_4_IV_B64 = ?config("a.1.4.iv.b64", C),
    A_1_4_IV_B64 = jose_jwa_base64url:encode(A_1_4_IV),
    % A.1.5
    A_1_5_AAD = ?config("a.1.5.aad", C),
    A_1_1_JWE_DATA_B64 = A_1_5_AAD,
    % A.1.6
    A_1_6_CIPHER = ?config("a.1.6.txt.cipher", C),
    A_1_6_TAG = ?config("a.1.6.txt.tag", C),
    A_1_6_CIPHER_B64 = ?config("a.1.6.txt.cipher.b64", C),
    A_1_6_TAG_B64 = ?config("a.1.6.txt.tag.b64", C),
    A_1_6_CIPHER = jose_jwa_base64url:decode(A_1_6_CIPHER_B64),
    A_1_6_TAG = jose_jwa_base64url:decode(A_1_6_TAG_B64),
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
    A_2_1_JWE_DATA_B64 = jose_jwa_base64url:encode(element(2, jose_jwe:to_binary(A_2_1_JWE))),
    % A.2.2
    A_2_2_CEK = ?config("a.2.2.cek", C),
    % A.2.3
    A_2_3_JWK_DATA = ?config("a.2.3.jwk+json", C),
    A_2_3_JWK_MAP = jose:decode(A_2_3_JWK_DATA),
    A_2_3_JWK = jose_jwk:from_binary(A_2_3_JWK_DATA),
    {_, A_2_3_JWK_MAP} = jose_jwk:to_map(A_2_3_JWK),
    A_2_3_CEK_ENCRYPTED = ?config("a.2.3.cek.encrypted", C),
    A_2_3_CEK_ENCRYPTED_B64 = ?config("a.2.3.cek.encrypted.b64", C),
    A_2_3_CEK_ENCRYPTED_B64 = jose_jwa_base64url:encode(A_2_3_CEK_ENCRYPTED),
    % A.2.4
    A_2_4_IV = ?config("a.2.4.iv", C),
    A_2_4_IV_B64 = ?config("a.2.4.iv.b64", C),
    A_2_4_IV_B64 = jose_jwa_base64url:encode(A_2_4_IV),
    % A.2.5
    A_2_5_AAD = ?config("a.2.5.aad", C),
    A_2_1_JWE_DATA_B64 = A_2_5_AAD,
    % A.2.6
    A_2_6_CIPHER = ?config("a.2.6.txt.cipher", C),
    A_2_6_TAG = ?config("a.2.6.txt.tag", C),
    A_2_6_CIPHER_B64 = ?config("a.2.6.txt.cipher.b64", C),
    A_2_6_TAG_B64 = ?config("a.2.6.txt.tag.b64", C),
    A_2_6_CIPHER = jose_jwa_base64url:decode(A_2_6_CIPHER_B64),
    A_2_6_TAG = jose_jwa_base64url:decode(A_2_6_TAG_B64),
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
    A_3_1_JWE_DATA_B64 = jose_jwa_base64url:encode(element(2, jose_jwe:to_binary(A_3_1_JWE))),
    % A.3.2
    A_3_2_CEK = ?config("a.3.2.cek", C),
    % A.3.3
    A_3_3_JWK_DATA = ?config("a.3.3.jwk+json", C),
    A_3_3_JWK_MAP = jose:decode(A_3_3_JWK_DATA),
    A_3_3_JWK = jose_jwk:from_binary(A_3_3_JWK_DATA),
    {_, A_3_3_JWK_MAP} = jose_jwk:to_map(A_3_3_JWK),
    A_3_3_CEK_ENCRYPTED = ?config("a.3.3.cek.encrypted", C),
    A_3_3_CEK_ENCRYPTED_B64 = ?config("a.3.3.cek.encrypted.b64", C),
    A_3_3_CEK_ENCRYPTED_B64 = jose_jwa_base64url:encode(A_3_3_CEK_ENCRYPTED),
    % A.3.4
    A_3_4_IV = ?config("a.3.4.iv", C),
    A_3_4_IV_B64 = ?config("a.3.4.iv.b64", C),
    A_3_4_IV_B64 = jose_jwa_base64url:encode(A_3_4_IV),
    % A.3.5
    A_3_5_AAD = ?config("a.3.5.aad", C),
    A_3_1_JWE_DATA_B64 = A_3_5_AAD,
    % A.3.6
    A_3_6_CIPHER = ?config("a.3.6.txt.cipher", C),
    A_3_6_TAG = ?config("a.3.6.txt.tag", C),
    A_3_6_CIPHER_B64 = ?config("a.3.6.txt.cipher.b64", C),
    A_3_6_TAG_B64 = ?config("a.3.6.txt.tag.b64", C),
    A_3_6_CIPHER = jose_jwa_base64url:decode(A_3_6_CIPHER_B64),
    A_3_6_TAG = jose_jwa_base64url:decode(A_3_6_TAG_B64),
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
    C_2_B64_DATA = jose_jwa_base64url:encode(C_2_JSON_DATA),
    % C.3
    C_3_CEK = ?config("c.3.cek", C),
    % C.4
    C_4_TXT = ?config("c.4.txt", C),
    C_4_SALT = ?config("c.4.salt", C),
    C_4_SALT = <<(maps:get(<<"alg">>, C_2_JSON))/binary, 0, (jose_jwa_base64url:decode(maps:get(<<"p2s">>, C_2_JSON)))/binary>>,
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
    C_8_ENC_MAP =
        #{
            <<"ciphertext">> := C_8_CIPHER_TXT_B64,
            <<"tag">> := C_8_CIPHER_TAG_B64
        } = force_block_encrypt(C_4_TXT, C_1_JSON_DATA, C_3_CEK, C_6_IV, C_7_AAD, C_2_JWE),
    C_8_CIPHER_TXT = jose_jwa_base64url:decode(C_8_CIPHER_TXT_B64),
    C_8_CIPHER_TAG = jose_jwa_base64url:decode(C_8_CIPHER_TAG_B64),
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
    A_1_1_B64_DATA = jose_jwa_base64url:encode(A_1_1_JSON_DATA),
    A_1_1_PAYLOAD_DATA = ?config("a.1.1.payload", C),
    A_1_1_B64_PAYLOAD_DATA = ?config("a.1.1.payload-b64", C),
    A_1_1_B64_PAYLOAD_DATA = jose_jwa_base64url:encode(A_1_1_PAYLOAD_DATA),
    A_1_1_SIGNING_INPUT_DATA = ?config("a.1.1.signing-input", C),
    A_1_1_SIGNING_INPUT_DATA = <<A_1_1_B64_DATA/binary, $., A_1_1_B64_PAYLOAD_DATA/binary>>,
    A_1_1_JWK = jose_jwk:from_file(data_file("jws/a.1.1.jwk+json", Config)),
    A_1_1_B64_SIGNATURE_DATA = ?config("a.1.1.signature-b64", C),
    %% Forcing the Protected header to be A_1_1_JSON_DATA
    A_1_1_MAP =
        #{
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
    A_2_1_B64_DATA = jose_jwa_base64url:encode(A_2_1_JSON_DATA),
    A_2_1_PAYLOAD_DATA = ?config("a.2.1.payload", C),
    A_2_1_B64_PAYLOAD_DATA = ?config("a.2.1.payload-b64", C),
    A_2_1_B64_PAYLOAD_DATA = jose_jwa_base64url:encode(A_2_1_PAYLOAD_DATA),
    A_2_1_SIGNING_INPUT_DATA = ?config("a.2.1.signing-input", C),
    A_2_1_SIGNING_INPUT_DATA = <<A_2_1_B64_DATA/binary, $., A_2_1_B64_PAYLOAD_DATA/binary>>,
    A_2_1_JWK = jose_jwk:from_file(data_file("jws/a.2.1.jwk+json", Config)),
    A_2_1_B64_SIGNATURE_DATA = ?config("a.2.1.signature-b64", C),
    %% Forcing the Protected header to be A_2_1_JSON_DATA
    A_2_1_MAP =
        #{
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
    A_3_1_B64_DATA = jose_jwa_base64url:encode(A_3_1_JSON_DATA),
    A_3_1_PAYLOAD_DATA = ?config("a.3.1.payload", C),
    A_3_1_B64_PAYLOAD_DATA = ?config("a.3.1.payload-b64", C),
    A_3_1_B64_PAYLOAD_DATA = jose_jwa_base64url:encode(A_3_1_PAYLOAD_DATA),
    A_3_1_SIGNING_INPUT_DATA = ?config("a.3.1.signing-input", C),
    A_3_1_SIGNING_INPUT_DATA = <<A_3_1_B64_DATA/binary, $., A_3_1_B64_PAYLOAD_DATA/binary>>,
    A_3_1_JWK = jose_jwk:from_file(data_file("jws/a.3.1.jwk+json", Config)),
    A_3_1_B64_SIGNATURE_DATA = ?config("a.3.1.signature-b64", C),
    %% Forcing the Protected header to be A_3_1_JSON_DATA
    A_3_1_MAP =
        #{
            <<"signature">> := A_3_1_B64_SIGNATURE_DATA_ALT
        } = force_sign(A_3_1_JWK, A_3_1_PAYLOAD_DATA, A_3_1_JSON_DATA, A_3_1_JWS),
    %% ECDSA produces non-matching signatures
    true = (A_3_1_B64_SIGNATURE_DATA =/= A_3_1_B64_SIGNATURE_DATA_ALT),
    A_3_1_COMPACT_DATA = ?config("a.3.1.compact", C),
    {_, A_3_1_COMPACT_DATA} = jose_jws:compact(A_3_1_MAP#{<<"signature">> => A_3_1_B64_SIGNATURE_DATA}),
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
    A_4_1_B64_DATA = jose_jwa_base64url:encode(A_4_1_JSON_DATA),
    A_4_1_PAYLOAD_DATA = ?config("a.4.1.payload", C),
    A_4_1_B64_PAYLOAD_DATA = ?config("a.4.1.payload-b64", C),
    A_4_1_B64_PAYLOAD_DATA = jose_jwa_base64url:encode(A_4_1_PAYLOAD_DATA),
    A_4_1_SIGNING_INPUT_DATA = ?config("a.4.1.signing-input", C),
    A_4_1_SIGNING_INPUT_DATA = <<A_4_1_B64_DATA/binary, $., A_4_1_B64_PAYLOAD_DATA/binary>>,
    A_4_1_JWK = jose_jwk:from_file(data_file("jws/a.4.1.jwk+json", Config)),
    A_4_1_B64_SIGNATURE_DATA = ?config("a.4.1.signature-b64", C),
    %% Forcing the Protected header to be A_4_1_JSON_DATA
    A_4_1_MAP =
        #{
            <<"signature">> := A_4_1_B64_SIGNATURE_DATA_ALT
        } = force_sign(A_4_1_JWK, A_4_1_PAYLOAD_DATA, A_4_1_JSON_DATA, A_4_1_JWS),
    %% ECDSA produces non-matching signatures
    true = (A_4_1_B64_SIGNATURE_DATA =/= A_4_1_B64_SIGNATURE_DATA_ALT),
    A_4_1_COMPACT_DATA = ?config("a.4.1.compact", C),
    {_, A_4_1_COMPACT_DATA} = jose_jws:compact(A_4_1_MAP#{<<"signature">> => A_4_1_B64_SIGNATURE_DATA}),
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
    A_5_B64_DATA = jose_jwa_base64url:encode(A_5_JSON_DATA),
    A_5_PAYLOAD_DATA = ?config("a.5.payload", C),
    A_5_B64_PAYLOAD_DATA = ?config("a.5.payload-b64", C),
    A_5_B64_PAYLOAD_DATA = jose_jwa_base64url:encode(A_5_PAYLOAD_DATA),
    A_5_SIGNING_INPUT_DATA = ?config("a.5.signing-input", C),
    A_5_SIGNING_INPUT_DATA = <<A_5_B64_DATA/binary, $., A_5_B64_PAYLOAD_DATA/binary>>,
    %% Forcing the Protected header to be A_5_JSON_DATA
    A_5_MAP =
        #{
            <<"signature">> := <<>>
        } = force_sign(none, A_5_PAYLOAD_DATA, A_5_JSON_DATA, A_5_JWS),
    A_5_COMPACT_DATA = ?config("a.5.compact", C),
    {_, A_5_COMPACT_DATA} = jose_jws:compact(A_5_MAP),
    {true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(none, A_5_MAP),
    {true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(none, A_5_COMPACT_DATA),
    %% Sign and Verify
    {true, A_5_PAYLOAD_DATA, A_5_JWS} = jose_jws:verify(none, jose_jws:sign(none, A_5_PAYLOAD_DATA, A_5_JWS)),
    ok.

% Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
% 5.9.  Compressed Content
% https://tools.ietf.org/html/rfc7520#section-5.9
rfc7520_5_9(Config) ->
    C = ?config(rfc7520_5_9, Config),
    % 5.9.1
    V_5_9_1_PLAIN_TEXT = ?config("figure.72", C),
    V_5_9_1_JWK = jose_jwk:from_binary(?config("figure.151", C)),
    % 5.9.2
    V_5_9_2_COMPRESSED_PLAIN_TEXT = ?config("figure.162", C),
    V_5_9_1_PLAIN_TEXT = jose_jwe_zip:uncompress(jose_jwa_base64url:decode(V_5_9_2_COMPRESSED_PLAIN_TEXT), zlib),
    V_5_9_2_COMPRESSED_PLAIN_TEXT = jose_jwa_base64url:encode(jose_jwe_zip:compress(V_5_9_1_PLAIN_TEXT, zlib)),
    V_5_9_2_CEK = ?config("figure.163", C),
    V_5_9_2_IV = ?config("figure.164", C),
    % 5.9.3
    V_5_9_3_ENCRYPTED_KEY = ?config("figure.165", C),
    {ALG, _} = jose_jwe_alg_aes_kw:from_map(#{<<"alg">> => <<"A128KW">>}),
    V_5_9_3_ENCRYPTED_KEY = jose_jwa_base64url:encode(
        element(1, jose_jwe_alg_aes_kw:key_encrypt(V_5_9_1_JWK, jose_jwa_base64url:decode(V_5_9_2_CEK), ALG))
    ),
    V_5_9_2_CEK = jose_jwa_base64url:encode(
        jose_jwe_alg_aes_kw:key_decrypt(V_5_9_1_JWK, {undefined, undefined, jose_jwa_base64url:decode(V_5_9_3_ENCRYPTED_KEY)}, ALG)
    ),
    % 5.9.4
    V_5_9_4_JWE = jose_jwe:from_binary(?config("figure.166", C)),
    V_5_9_4_JWE_PROTECTED = ?config("figure.167", C),
    V_5_9_4_JWE = jose_jwe:from_binary(jose_jwa_base64url:decode(V_5_9_4_JWE_PROTECTED)),
    V_5_9_4_CIPHER_TEXT = ?config("figure.168", C),
    V_5_9_4_CIPHER_TAG = ?config("figure.169", C),
    % 5.9.5
    V_5_9_5_JWE_COMPACT = ?config("figure.170", C),
    V_5_9_5_JWE_MAP = jose:decode(?config("figure.172", C)),
    V_5_9_4_CIPHER_TEXT = maps:get(<<"ciphertext">>, V_5_9_5_JWE_MAP),
    V_5_9_4_CIPHER_TAG = maps:get(<<"tag">>, V_5_9_5_JWE_MAP),
    {V_5_9_1_PLAIN_TEXT, V_5_9_4_JWE} = jose_jwe:block_decrypt(V_5_9_1_JWK, V_5_9_5_JWE_COMPACT),
    {V_5_9_1_PLAIN_TEXT, V_5_9_4_JWE} = jose_jwe:block_decrypt(V_5_9_1_JWK, V_5_9_5_JWE_MAP),
    % Roundtrip test
    {_, CIPHER_TEXT} = jose_jwe:compact(
        jose_jwe:block_encrypt(
            V_5_9_1_JWK,
            V_5_9_1_PLAIN_TEXT,
            jose_jwa_base64url:decode(V_5_9_2_CEK),
            jose_jwa_base64url:decode(V_5_9_2_IV),
            V_5_9_4_JWE
        )
    ),
    {V_5_9_1_PLAIN_TEXT, V_5_9_4_JWE} = jose_jwe:block_decrypt(V_5_9_1_JWK, CIPHER_TEXT),
    ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
force_block_encrypt(Key, PlainText, CEK, IV, OverrideProtected, JWE = #jose_jwe{alg = {ALGModule, ALG}, enc = {ENCModule, ENC}}) ->
    {EncryptedKey, _} = ALGModule:key_encrypt(Key, CEK, ALG),
    Protected = jose_jwa_base64url:encode(OverrideProtected),
    {CipherText, CipherTag} = ENCModule:block_encrypt({Protected, maybe_compress(PlainText, JWE)}, CEK, IV, ENC),
    #{
        <<"protected">> => Protected,
        <<"encrypted_key">> => jose_jwa_base64url:encode(EncryptedKey),
        <<"iv">> => jose_jwa_base64url:encode(IV),
        <<"ciphertext">> => jose_jwa_base64url:encode(CipherText),
        <<"tag">> => jose_jwa_base64url:encode(CipherTag)
    }.

%% @private
force_sign(Key, PlainText, OverrideProtected, #jose_jws{alg = {ALGModule, ALG}}) ->
    Protected = jose_jwa_base64url:encode(OverrideProtected),
    Payload = jose_jwa_base64url:encode(PlainText),
    Message = <<Protected/binary, $., Payload/binary>>,
    Signature = jose_jwa_base64url:encode(ALGModule:sign(Key, Message, ALG)),
    #{
        <<"payload">> => Payload,
        <<"protected">> => Protected,
        <<"signature">> => Signature
    }.

%% @private
data_file(File, Config) ->
    filename:join([?config(data_dir, Config), File]).

%% @private
maybe_compress(PlainText, #jose_jwe{zip = {Module, ZIP}}) ->
    Module:compress(PlainText, ZIP);
maybe_compress(PlainText, _) ->
    PlainText.
