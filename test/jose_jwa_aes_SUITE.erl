%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
%%%-----------------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc Advanced Encryption Standard (AES)
%%% Cipher Block Chaining (CBC), as defined in NIST.800-38A
%%% Electronic Codebook (ECB), as defined in NIST.800-38A
%%% Galois/Counter Mode (GCM) and GMAC, as defined in NIST.800-38D
%%% See NIST.800-38A: http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
%%% See NIST.800-38D: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
%%% See http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
%%% See https://github.com/erlang/otp/blob/OTP-18.0/lib/crypto/test/crypto_SUITE.erl
%%% @end
%%% Created :  10 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-----------------------------------------------------------------------------
-module(jose_jwa_aes_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("jose.hrl").

%% Plain Text used in NIST example vectors
-define(NIST_PLAIN_TEXT,
    hexstr2bin(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )
).

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([aead/0]).
-export([aead/1]).
-export([block/0]).
-export([block/1]).

all() ->
    [
        {group, aes_cbc128},
        {group, aes_cbc192},
        {group, aes_cbc256},
        {group, aes_ecb128},
        {group, aes_ecb192},
        {group, aes_ecb256},
        {group, aes_gcm128},
        {group, aes_gcm192},
        {group, aes_gcm256}
    ].

groups() ->
    [
        {aes_cbc128, [], [block]},
        {aes_cbc192, [], [block]},
        {aes_cbc256, [], [block]},
        {aes_ecb128, [], [block]},
        {aes_ecb192, [], [block]},
        {aes_ecb256, [], [block]},
        {aes_gcm128, [], [aead]},
        {aes_gcm192, [], [aead]},
        {aes_gcm256, [], [aead]}
    ].

init_per_suite(Config) ->
    application:set_env(jose, crypto_fallback, true),
    application:set_env(jose, unsecured_signing, true),
    _ = application:ensure_all_started(jose),
    Config.

end_per_suite(_Config) ->
    _ = application:stop(jose),
    ok.

init_per_group(Group, Config) ->
    jose_ct:start(Group, group_config(Group, Config)).

end_per_group(_Group, Config) ->
    jose_ct:stop(Config),
    ok.

%%%=============================================================================
%% Tests
%%%=============================================================================

aead() ->
    [{doc, "Test AEAD ciphers"}].
aead(Config) when is_list(Config) ->
    AEADs = lazy_eval(proplists:get_value(aead, Config)),
    lists:foreach(fun aead_cipher/1, AEADs).

block() ->
    [{doc, "Test block ciphers"}].
block(Config) when is_list(Config) ->
    Blocks = proplists:get_value(block, Config),
    lists:foreach(fun block_cipher/1, Blocks).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
aead_cipher({Type, Key, PlainText, IV, AAD, CipherText, CipherTag}) ->
    Plain = iolist_to_binary(PlainText),
    case jose_jwa_aes:block_encrypt(Type, Key, IV, {AAD, Plain}) of
        {CipherText, CipherTag} ->
            ok;
        Other0 ->
            ct:fail({
                {jose_jwa_aes, block_encrypt, [Plain, PlainText]}, {expected, {CipherText, CipherTag}}, {got, Other0}
            })
    end,
    case jose_jwa_aes:block_decrypt(Type, Key, IV, {AAD, CipherText, CipherTag}) of
        Plain ->
            ok;
        Other1 ->
            ct:fail({{jose_jwa_aes, block_decrypt, [CipherText]}, {expected, Plain}, {got, Other1}})
    end.

%% @private
block_cipher({Type, Key, PlainText}) ->
    Plain = iolist_to_binary(PlainText),
    CipherText = jose_jwa_aes:block_encrypt(Type, Key, PlainText),
    case jose_jwa_aes:block_decrypt(Type, Key, CipherText) of
        Plain ->
            ok;
        Other ->
            ct:fail({{jose_jwa_aes, block_decrypt, [Type, Key, CipherText]}, {expected, Plain}, {got, Other}})
    end;
block_cipher({Type = {aes_ecb, _}, Key, PlainText, CipherText}) ->
    Plain = iolist_to_binary(PlainText),
    case jose_jwa_aes:block_encrypt(Type, Key, Plain) of
        CipherText ->
            ok;
        Other0 ->
            ct:fail({{jose_jwa_aes, block_encrypt, [Type, Key, Plain]}, {expected, CipherText}, {got, Other0}})
    end,
    case jose_jwa_aes:block_decrypt(Type, Key, CipherText) of
        Plain ->
            ok;
        Other1 ->
            ct:fail({{jose_jwa_aes, block_decrypt, [Type, Key, CipherText]}, {expected, Plain}, {got, Other1}})
    end;
block_cipher({Type, Key, IV, PlainText}) ->
    Plain = iolist_to_binary(PlainText),
    CipherText = jose_jwa_aes:block_encrypt(Type, Key, IV, PlainText),
    case jose_jwa_aes:block_decrypt(Type, Key, IV, CipherText) of
        Plain ->
            ok;
        Other ->
            ct:fail({{jose_jwa_aes, block_decrypt, [Type, Key, IV, CipherText]}, {expected, Plain}, {got, Other}})
    end;
block_cipher({Type, Key, IV, PlainText, CipherText}) ->
    Plain = iolist_to_binary(PlainText),
    case jose_jwa_aes:block_encrypt(Type, Key, IV, Plain) of
        CipherText ->
            ok;
        Other0 ->
            ct:fail({{jose_jwa_aes, block_encrypt, [Plain, PlainText]}, {expected, CipherText}, {got, Other0}})
    end,
    case jose_jwa_aes:block_decrypt(Type, Key, IV, CipherText) of
        Plain ->
            ok;
        Other1 ->
            ct:fail({{jose_jwa_aes, block_decrypt, [CipherText]}, {expected, Plain}, {got, Other1}})
    end.

%% @private
group_config(aes_cbc128, Config) ->
    Block = aes_cbc128(),
    [{block, Block} | Config];
group_config(aes_cbc192, Config) ->
    Block = aes_cbc192(),
    [{block, Block} | Config];
group_config(aes_cbc256, Config) ->
    Block = aes_cbc256(),
    [{block, Block} | Config];
group_config(aes_ecb128, Config) ->
    Block = aes_ecb128(),
    [{block, Block} | Config];
group_config(aes_ecb192, Config) ->
    Block = aes_ecb192(),
    [{block, Block} | Config];
group_config(aes_ecb256, Config) ->
    Block = aes_ecb256(),
    [{block, Block} | Config];
group_config(aes_gcm128, Config) ->
    AEAD = aes_gcm128(),
    [{aead, AEAD} | Config];
group_config(aes_gcm192, Config) ->
    AEAD = aes_gcm192(),
    [{aead, AEAD} | Config];
group_config(aes_gcm256, Config) ->
    AEAD = aes_gcm256(),
    [{aead, AEAD} | Config].

%% @private
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

%% @private
hexstr2list([X, Y | T]) ->
    [mkint(X) * 16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

%% Building huge terms (like long_msg/0) in init_per_group seems to cause
%% test_server crash with 'no_answer_from_tc_supervisor' sometimes on some
%% machines. Therefore lazy evaluation when test case has started.
lazy_eval(F) when is_function(F) -> F();
lazy_eval(Lst) when is_list(Lst) -> lists:map(fun lazy_eval/1, Lst);
lazy_eval(Tpl) when is_tuple(Tpl) -> list_to_tuple(lists:map(fun lazy_eval/1, tuple_to_list(Tpl)));
lazy_eval(Term) -> Term.

%% @private
mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

%% @private
%% See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
aes_cbc128() ->
    [
        {
            {aes_cbc, 128},
            hexstr2bin("2b7e151628aed2a6abf7158809cf4f3c"),
            hexstr2bin("000102030405060708090a0b0c0d0e0f"),
            hexstr2bin("6bc1bee22e409f96e93d7e117393172a")
        },
        {
            {aes_cbc, 128},
            hexstr2bin("2b7e151628aed2a6abf7158809cf4f3c"),
            hexstr2bin("7649ABAC8119B246CEE98E9B12E9197D"),
            hexstr2bin("ae2d8a571e03ac9c9eb76fac45af8e51")
        },
        {
            {aes_cbc, 128},
            hexstr2bin("2b7e151628aed2a6abf7158809cf4f3c"),
            hexstr2bin("5086CB9B507219EE95DB113A917678B2"),
            hexstr2bin("30c81c46a35ce411e5fbc1191a0a52ef")
        },
        {
            {aes_cbc, 128},
            hexstr2bin("2b7e151628aed2a6abf7158809cf4f3c"),
            hexstr2bin("73BED6B8E3C1743B7116E69E22229516"),
            hexstr2bin("f69f2445df4f9b17ad2b417be66c3710")
        },
        %% F.2.1 CBC-AES128.Encrypt
        %% F.2.2 CBC-AES128.Decrypt
        {
            {aes_cbc, 128},
            hexstr2bin("2b7e151628aed2a6abf7158809cf4f3c"),
            hexstr2bin("000102030405060708090a0b0c0d0e0f"),
            ?NIST_PLAIN_TEXT,
            hexstr2bin(
                "7649abac8119b246cee98e9b12e9197d"
                "5086cb9b507219ee95db113a917678b2"
                "73bed6b8e3c1743b7116e69e22229516"
                "3ff1caa1681fac09120eca307586e1a7"
            )
        }
    ].

%% @private
%% See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
aes_cbc192() ->
    [
        %% F.2.3 CBC-AES192.Encrypt
        %% F.2.4 CBC-AES192.Decrypt
        {
            {aes_cbc, 192},
            hexstr2bin(
                "8e73b0f7da0e6452c810f32b809079e5"
                "62f8ead2522c6b7b"
            ),
            hexstr2bin("000102030405060708090a0b0c0d0e0f"),
            ?NIST_PLAIN_TEXT,
            hexstr2bin(
                "4f021db243bc633d7178183a9fa071e8"
                "b4d9ada9ad7dedf4e5e738763f69145a"
                "571b242012fb7ae07fa9baac3df102e0"
                "08b0e27988598881d920a9e64f5615cd"
            )
        }
    ].

%% @private
%% See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
aes_cbc256() ->
    [
        {
            {aes_cbc, 256},
            hexstr2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            hexstr2bin("000102030405060708090A0B0C0D0E0F"),
            hexstr2bin("6bc1bee22e409f96e93d7e117393172a")
        },
        {
            {aes_cbc, 256},
            hexstr2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            hexstr2bin("F58C4C04D6E5F1BA779EABFB5F7BFBD6"),
            hexstr2bin("ae2d8a571e03ac9c9eb76fac45af8e51")
        },
        {
            {aes_cbc, 256},
            hexstr2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            hexstr2bin("9CFC4E967EDB808D679F777BC6702C7D"),
            hexstr2bin("30c81c46a35ce411e5fbc1191a0a52ef")
        },
        {
            {aes_cbc, 256},
            hexstr2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            hexstr2bin("39F23369A9D9BACFA530E26304231461"),
            hexstr2bin("f69f2445df4f9b17ad2b417be66c3710")
        },
        %% F.2.5 CBC-AES256.Encrypt
        %% F.2.6 CBC-AES256.Decrypt
        {
            {aes_cbc, 256},
            hexstr2bin(
                "603deb1015ca71be2b73aef0857d7781"
                "1f352c073b6108d72d9810a30914dff4"
            ),
            hexstr2bin("000102030405060708090a0b0c0d0e0f"),
            ?NIST_PLAIN_TEXT,
            hexstr2bin(
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                "9cfc4e967edb808d679f777bc6702c7d"
                "39f23369a9d9bacfa530e26304231461"
                "b2eb05e2c39be9fcda6c19078c6a9d1b"
            )
        }
    ].

%% @private
%% See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
aes_ecb128() ->
    [
        {{aes_ecb, 128}, <<"YELLOW SUBMARINE">>, <<"YELLOW SUBMARINE">>},
        {{aes_ecb, 128}, <<"0000000000000000">>, <<"0000000000000000">>},
        {{aes_ecb, 128}, <<"FFFFFFFFFFFFFFFF">>, <<"FFFFFFFFFFFFFFFF">>},
        {{aes_ecb, 128}, <<"3000000000000000">>, <<"1000000000000001">>},
        {{aes_ecb, 128}, <<"1111111111111111">>, <<"1111111111111111">>},
        {{aes_ecb, 128}, <<"0123456789ABCDEF">>, <<"1111111111111111">>},
        {{aes_ecb, 128}, <<"0000000000000000">>, <<"0000000000000000">>},
        {{aes_ecb, 128}, <<"FEDCBA9876543210">>, <<"0123456789ABCDEF">>},
        {{aes_ecb, 128}, <<"7CA110454A1A6E57">>, <<"01A1D6D039776742">>},
        {{aes_ecb, 128}, <<"0131D9619DC1376E">>, <<"5CD54CA83DEF57DA">>},
        {{aes_ecb, 128}, <<"07A1133E4A0B2686">>, <<"0248D43806F67172">>},
        {{aes_ecb, 128}, <<"3849674C2602319E">>, <<"51454B582DDF440A">>},
        {{aes_ecb, 128}, <<"04B915BA43FEB5B6">>, <<"42FD443059577FA2">>},
        {{aes_ecb, 128}, <<"0113B970FD34F2CE">>, <<"059B5E0851CF143A">>},
        {{aes_ecb, 128}, <<"0170F175468FB5E6">>, <<"0756D8E0774761D2">>},
        {{aes_ecb, 128}, <<"43297FAD38E373FE">>, <<"762514B829BF486A">>},
        {{aes_ecb, 128}, <<"07A7137045DA2A16">>, <<"3BDD119049372802">>},
        {{aes_ecb, 128}, <<"04689104C2FD3B2F">>, <<"26955F6835AF609A">>},
        {{aes_ecb, 128}, <<"37D06BB516CB7546">>, <<"164D5E404F275232">>},
        {{aes_ecb, 128}, <<"1F08260D1AC2465E">>, <<"6B056E18759F5CCA">>},
        {{aes_ecb, 128}, <<"584023641ABA6176">>, <<"004BD6EF09176062">>},
        {{aes_ecb, 128}, <<"025816164629B007">>, <<"480D39006EE762F2">>},
        {{aes_ecb, 128}, <<"49793EBC79B3258F">>, <<"437540C8698F3CFA">>},
        {{aes_ecb, 128}, <<"018310DC409B26D6">>, <<"1D9D5C5018F728C2">>},
        {{aes_ecb, 128}, <<"1C587F1C13924FEF">>, <<"305532286D6F295A">>},
        {{aes_ecb, 128}, <<"0101010101010101">>, <<"0123456789ABCDEF">>},
        {{aes_ecb, 128}, <<"1F1F1F1F0E0E0E0E">>, <<"0123456789ABCDEF">>},
        {{aes_ecb, 128}, <<"E0FEE0FEF1FEF1FE">>, <<"0123456789ABCDEF">>},
        {{aes_ecb, 128}, <<"0000000000000000">>, <<"FFFFFFFFFFFFFFFF">>},
        {{aes_ecb, 128}, <<"FFFFFFFFFFFFFFFF">>, <<"0000000000000000">>},
        {{aes_ecb, 128}, <<"0123456789ABCDEF">>, <<"0000000000000000">>},
        {{aes_ecb, 128}, <<"FEDCBA9876543210">>, <<"FFFFFFFFFFFFFFFF">>},
        %% F.1.1 ECB-AES128.Encrypt
        %% F.1.2 ECB-AES128.Decrypt
        {
            {aes_ecb, 128},
            hexstr2bin("2b7e151628aed2a6abf7158809cf4f3c"),
            ?NIST_PLAIN_TEXT,
            hexstr2bin(
                "3ad77bb40d7a3660a89ecaf32466ef97"
                "f5d3d58503b9699de785895a96fdbaaf"
                "43b1cd7f598ece23881b00e3ed030688"
                "7b0c785e27e8ad3f8223207104725dd4"
            )
        }
    ].

%% @private
%% See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
aes_ecb192() ->
    [
        %% F.1.3 ECB-AES192.Encrypt
        %% F.1.4 ECB-AES192.Decrypt
        {
            {aes_ecb, 192},
            hexstr2bin(
                "8e73b0f7da0e6452c810f32b809079e5"
                "62f8ead2522c6b7b"
            ),
            ?NIST_PLAIN_TEXT,
            hexstr2bin(
                "bd334f1d6e45f25ff712a214571fa5cc"
                "974104846d0ad3ad7734ecb3ecee4eef"
                "ef7afd2270e2e60adce0ba2face6444e"
                "9a4b41ba738d6c72fb16691603c18e0e"
            )
        }
    ].

%% @private
%% See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
aes_ecb256() ->
    [
        %% F.1.5 ECB-AES256.Encrypt
        %% F.1.6 ECB-AES256.Decrypt
        {
            {aes_ecb, 256},
            hexstr2bin(
                "603deb1015ca71be2b73aef0857d7781"
                "1f352c073b6108d72d9810a30914dff4"
            ),
            ?NIST_PLAIN_TEXT,
            hexstr2bin(
                "f3eed1bdb5d2a03c064b5a7e3db181f8"
                "591ccb10d410ed26dc5ba74a31362870"
                "b6ed21b99ca6f4f9f153e7b1beafed1d"
                "23304b7a39f9f3ff067d8d8f9e24ecc7"
            )
        }
    ].

%% AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
aes_gcm128() ->
    [
        %% Test Case 1
        {
            {aes_gcm, 128},
            %% Key
            hexstr2bin("00000000000000000000000000000000"),
            %% PlainText
            hexstr2bin(""),
            %% IV
            hexstr2bin("000000000000000000000000"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin(""),
            %% CipherTag
            hexstr2bin("58e2fccefa7e3061367f1d57a4e7455a")
        },

        %% Test Case 2
        {
            {aes_gcm, 128},
            %% Key
            hexstr2bin("00000000000000000000000000000000"),
            %% PlainText
            hexstr2bin("00000000000000000000000000000000"),
            %% IV
            hexstr2bin("000000000000000000000000"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin("0388dace60b6a392f328c2b971b2fe78"),
            %% CipherTag
            hexstr2bin("ab6e47d42cec13bdf53a67b21257bddf")
        },

        %% Test Case 3
        {
            {aes_gcm, 128},
            %% Key
            hexstr2bin("feffe9928665731c6d6a8f9467308308"),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255"
            ),
            %% IV
            hexstr2bin("cafebabefacedbaddecaf888"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin(
                "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091473f5985"
            ),
            %% CipherTag
            hexstr2bin("4d5c2af327cd64a62cf35abd2ba6fab4")
        },

        %% Test Case 4
        {
            {aes_gcm, 128},
            %% Key
            hexstr2bin("feffe9928665731c6d6a8f9467308308"),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin("cafebabefacedbaddecaf888"),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "42831ec2217774244b7221b784d0d49c"
                "e3aa212f2c02a4e035c17e2329aca12e"
                "21d514b25466931c7d8f6a5aac84aa05"
                "1ba30b396a0aac973d58e091"
            ),
            %% CipherTag
            hexstr2bin("5bc94fbc3221a5db94fae95ae7121a47")
        },

        %% Test Case 5
        {
            {aes_gcm, 128},
            %% Key
            hexstr2bin("feffe9928665731c6d6a8f9467308308"),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin("cafebabefacedbad"),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "61353b4c2806934a777ff51fa22a4755"
                "699b2a714fcdc6f83766e5f97b6c7423"
                "73806900e49f24b22b097544d4896b42"
                "4989b5e1ebac0f07c23f4598"
            ),
            %% CipherTag
            hexstr2bin("3612d2e79e3b0785561be14aaca2fccb")
        },

        %% Test Case 6
        {
            {aes_gcm, 128},
            %% Key
            hexstr2bin("feffe9928665731c6d6a8f9467308308"),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin(
                "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b"
            ),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "8ce24998625615b603a033aca13fb894"
                "be9112a5c3a211a8ba262a3cca7e2ca7"
                "01e4a9a4fba43c90ccdcb281d48c7c6f"
                "d62875d2aca417034c34aee5"
            ),
            %% CipherTag
            hexstr2bin("619cc5aefffe0bfa462af43c1699d050")
        }
    ].

%% AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
aes_gcm192() ->
    [
        %% Test Case 7
        {
            {aes_gcm, 192},
            %% Key
            hexstr2bin(
                "00000000000000000000000000000000"
                "0000000000000000"
            ),
            %% PlainText
            hexstr2bin(""),
            %% IV
            hexstr2bin("000000000000000000000000"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin(""),
            %% CipherTag
            hexstr2bin("cd33b28ac773f74ba00ed1f312572435")
        },

        %% Test Case 8
        {
            {aes_gcm, 192},
            %% Key
            hexstr2bin(
                "00000000000000000000000000000000"
                "0000000000000000"
            ),
            %% PlainText
            hexstr2bin("00000000000000000000000000000000"),
            %% IV
            hexstr2bin("000000000000000000000000"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin("98e7247c07f0fe411c267e4384b0f600"),
            %% CipherTag
            hexstr2bin("2ff58d80033927ab8ef4d4587514f0fb")
        },

        %% Test Case 9
        {
            {aes_gcm, 192},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255"
            ),
            %% IV
            hexstr2bin("cafebabefacedbaddecaf888"),
            %% ADD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin(
                "3980ca0b3c00e841eb06fac4872a2757"
                "859e1ceaa6efd984628593b40ca1e19c"
                "7d773d00c144c525ac619d18c84a3f47"
                "18e2448b2fe324d9ccda2710acade256"
            ),
            %% CipherTag
            hexstr2bin("9924a7c8587336bfb118024db8674a14")
        },

        %% Test Case 10
        {
            {aes_gcm, 192},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin("cafebabefacedbaddecaf888"),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "3980ca0b3c00e841eb06fac4872a2757"
                "859e1ceaa6efd984628593b40ca1e19c"
                "7d773d00c144c525ac619d18c84a3f47"
                "18e2448b2fe324d9ccda2710"
            ),
            %% CipherTag
            hexstr2bin("2519498e80f1478f37ba55bd6d27618c")
        },

        %% Test Case 11
        {
            {aes_gcm, 192},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin("cafebabefacedbad"),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "0f10f599ae14a154ed24b36e25324db8"
                "c566632ef2bbb34f8347280fc4507057"
                "fddc29df9a471f75c66541d4d4dad1c9"
                "e93a19a58e8b473fa0f062f7"
            ),
            %% CipherTag
            hexstr2bin("65dcc57fcf623a24094fcca40d3533f8")
        },

        %% Test Case 12
        {
            {aes_gcm, 192},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin(
                "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b"
            ),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "d27e88681ce3243c4830165a8fdcf9ff"
                "1de9a1d8e6b447ef6ef7b79828666e45"
                "81e79012af34ddd9e2f037589b292db3"
                "e67c036745fa22e7e9b7373b"
            ),
            %% CipherTag
            hexstr2bin("dcf566ff291c25bbb8568fc3d376a6d9")
        }
    ].

%% AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
aes_gcm256() ->
    [
        %% Test Case 13
        {
            {aes_gcm, 256},
            %% Key
            hexstr2bin(
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
            ),
            %% PlainText
            hexstr2bin(""),
            %% IV
            hexstr2bin("000000000000000000000000"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin(""),
            %% CipherTag
            hexstr2bin("530f8afbc74536b9a963b4f1c4cb738b")
        },

        %% Test Case 14
        {
            {aes_gcm, 256},
            %% Key
            hexstr2bin(
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"
            ),
            %% PlainText
            hexstr2bin("00000000000000000000000000000000"),
            %% IV
            hexstr2bin("000000000000000000000000"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin("cea7403d4d606b6e074ec5d3baf39d18"),
            %% CipherTag
            hexstr2bin("d0d1c8a799996bf0265b98b5d48ab919")
        },

        %% Test Case 15
        {
            {aes_gcm, 256},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b391aafd255"
            ),
            %% IV
            hexstr2bin("cafebabefacedbaddecaf888"),
            %% AAD
            hexstr2bin(""),
            %% CipherText
            hexstr2bin(
                "522dc1f099567d07f47f37a32a84427d"
                "643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838"
                "c5f61e6393ba7a0abcc9f662898015ad"
            ),
            %% CipherTag
            hexstr2bin("b094dac5d93471bdec1a502270e3cc6c")
        },

        %% Test Case 16
        {
            {aes_gcm, 256},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin("cafebabefacedbaddecaf888"),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "522dc1f099567d07f47f37a32a84427d"
                "643a8cdcbfe5c0c97598a2bd2555d1aa"
                "8cb08e48590dbb3da7b08b1056828838"
                "c5f61e6393ba7a0abcc9f662"
            ),
            %% CipherTag
            hexstr2bin("76fc6ece0f4e1768cddf8853bb2d551b")
        },

        %% Test Case 17
        {
            {aes_gcm, 256},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin("cafebabefacedbad"),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "c3762df1ca787d32ae47c13bf19844cb"
                "af1ae14d0b976afac52ff7d79bba9de0"
                "feb582d33934a4f0954cc2363bc73f78"
                "62ac430e64abe499f47c9b1f"
            ),
            %% CipherTag
            hexstr2bin("3a337dbf46a792c45e454913fe2ea8f2")
        },

        %% Test Case 18
        {
            {aes_gcm, 256},
            %% Key
            hexstr2bin(
                "feffe9928665731c6d6a8f9467308308"
                "feffe9928665731c6d6a8f9467308308"
            ),
            %% PlainText
            hexstr2bin(
                "d9313225f88406e5a55909c5aff5269a"
                "86a7a9531534f7da2e4c303d8a318a72"
                "1c3c0c95956809532fcf0e2449a6b525"
                "b16aedf5aa0de657ba637b39"
            ),
            %% IV
            hexstr2bin(
                "9313225df88406e555909c5aff5269aa"
                "6a7a9538534f7da1e4c303d2a318a728"
                "c3c0c95156809539fcf0e2429a6b5254"
                "16aedbf5a0de6a57a637b39b"
            ),
            %% AAD
            hexstr2bin(
                "feedfacedeadbeeffeedfacedeadbeef"
                "abaddad2"
            ),
            %% CipherText
            hexstr2bin(
                "5a8def2f0c9e53f1f75d7853659e2a20"
                "eeb2b22aafde6419a058ab4f6f746bf4"
                "0fc0c3b780f244452da3ebf1c5d82cde"
                "a2418997200ef82e44ae7e3f"
            ),
            %% CipherTag
            hexstr2bin("a44a8266ee1c8eb0c8b5d4cf5ae9f19a")
        }
    ].
