%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_ec).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type message() :: binary().
-type maybe_invalid_signature(T) :: binary() | T.
-type ec_secp256k1_public_key() :: <<_:512>>.
-type ec_secp256k1_secret_key() :: <<_:256>>.
-type ec_secp256k1_seed() :: <<_:256>>.
-type ecdh_secp256k1_shared_secret() :: <<_:256>>.
-type ecdsa_secp256k1_sha256_signature() :: <<_:512>>.
-type ec_secp256r1_public_key() :: <<_:512>>.
-type ec_secp256r1_secret_key() :: <<_:256>>.
-type ec_secp256r1_seed() :: <<_:256>>.
-type ecdh_secp256r1_shared_secret() :: <<_:256>>.
-type ecdsa_secp256r1_sha256_signature() :: <<_:512>>.
-type ec_secp384r1_public_key() :: <<_:768>>.
-type ec_secp384r1_secret_key() :: <<_:384>>.
-type ec_secp384r1_seed() :: <<_:384>>.
-type ecdh_secp384r1_shared_secret() :: <<_:384>>.
-type ecdsa_secp384r1_sha384_signature() :: <<_:768>>.
-type ec_secp521r1_public_key() :: <<_:1056>>.
-type ec_secp521r1_secret_key() :: <<_:528>>.
-type ec_secp521r1_seed() :: <<_:528>>.
-type ecdh_secp521r1_shared_secret() :: <<_:528>>.
-type ecdsa_secp521r1_sha512_signature() :: <<_:1056>>.

-export_type([
    message/0,
    maybe_invalid_signature/1,
    ec_secp256k1_public_key/0,
    ec_secp256k1_secret_key/0,
    ec_secp256k1_seed/0,
    ecdh_secp256k1_shared_secret/0,
    ecdsa_secp256k1_sha256_signature/0,
    ec_secp256r1_public_key/0,
    ec_secp256r1_secret_key/0,
    ec_secp256r1_seed/0,
    ecdh_secp256r1_shared_secret/0,
    ecdsa_secp256r1_sha256_signature/0,
    ec_secp384r1_public_key/0,
    ec_secp384r1_secret_key/0,
    ec_secp384r1_seed/0,
    ecdh_secp384r1_shared_secret/0,
    ecdsa_secp384r1_sha384_signature/0,
    ec_secp521r1_public_key/0,
    ec_secp521r1_secret_key/0,
    ec_secp521r1_seed/0,
    ecdh_secp521r1_shared_secret/0,
    ecdsa_secp521r1_sha512_signature/0
]).

%% Callbacks
-callback ec_secp256k1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp256k1_public_key(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key().
-callback ec_secp256k1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp256k1_seed(),
    PublicKey :: jose_ec:ec_secp256k1_public_key(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key().
-callback ec_secp256k1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp256k1_secret_key(),
    PublicKey :: jose_ec:ec_secp256k1_public_key().
-callback ecdh_secp256k1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp256k1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp256k1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp256k1_shared_secret().
-callback ecdsa_secp256k1_sha256_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key(),
    Signature :: jose_ec:ecdsa_secp256k1_sha256_signature().
-callback ecdsa_secp256k1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp256k1_sha256_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp256k1_public_key().
-callback ec_secp256r1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp256r1_public_key(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key().
-callback ec_secp256r1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp256r1_seed(),
    PublicKey :: jose_ec:ec_secp256r1_public_key(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key().
-callback ec_secp256r1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp256r1_secret_key(),
    PublicKey :: jose_ec:ec_secp256r1_public_key().
-callback ecdh_secp256r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp256r1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp256r1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp256r1_shared_secret().
-callback ecdsa_secp256r1_sha256_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp256r1_sha256_signature().
-callback ecdsa_secp256r1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp256r1_sha256_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp256r1_public_key().
-callback ec_secp384r1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp384r1_public_key(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key().
-callback ec_secp384r1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp384r1_seed(),
    PublicKey :: jose_ec:ec_secp384r1_public_key(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key().
-callback ec_secp384r1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp384r1_secret_key(),
    PublicKey :: jose_ec:ec_secp384r1_public_key().
-callback ecdh_secp384r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp384r1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp384r1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp384r1_shared_secret().
-callback ecdsa_secp384r1_sha384_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp384r1_sha384_signature().
-callback ecdsa_secp384r1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp384r1_sha384_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp384r1_public_key().
-callback ec_secp521r1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp521r1_public_key(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key().
-callback ec_secp521r1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp521r1_seed(),
    PublicKey :: jose_ec:ec_secp521r1_public_key(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key().
-callback ec_secp521r1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp521r1_secret_key(),
    PublicKey :: jose_ec:ec_secp521r1_public_key().
-callback ecdh_secp521r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp521r1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp521r1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp521r1_shared_secret().
-callback ecdsa_secp521r1_sha512_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp521r1_sha512_signature().
-callback ecdsa_secp521r1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp521r1_sha512_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp521r1_public_key().

-optional_callbacks([
    ec_secp256k1_keypair/0,
    ec_secp256k1_keypair/1,
    ec_secp256k1_secret_to_public/1,
    ecdh_secp256k1_shared_secret/2,
    ecdsa_secp256k1_sha256_sign/2,
    ecdsa_secp256k1_sha256_verify/3,
    ec_secp256r1_keypair/0,
    ec_secp256r1_keypair/1,
    ec_secp256r1_secret_to_public/1,
    ecdh_secp256r1_shared_secret/2,
    ecdsa_secp256r1_sha256_sign/2,
    ecdsa_secp256r1_sha256_verify/3,
    ec_secp384r1_keypair/0,
    ec_secp384r1_keypair/1,
    ec_secp384r1_secret_to_public/1,
    ecdh_secp384r1_shared_secret/2,
    ecdsa_secp384r1_sha384_sign/2,
    ecdsa_secp384r1_sha384_verify/3,
    ec_secp521r1_keypair/0,
    ec_secp521r1_keypair/1,
    ec_secp521r1_secret_to_public/1,
    ecdh_secp521r1_shared_secret/2,
    ecdsa_secp521r1_sha512_sign/2,
    ecdsa_secp521r1_sha512_verify/3
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_ec callbacks
-export([
    ec_secp256k1_keypair/0,
    ec_secp256k1_keypair/1,
    ec_secp256k1_secret_to_public/1,
    ecdh_secp256k1_shared_secret/2,
    ecdsa_secp256k1_sha256_sign/2,
    ecdsa_secp256k1_sha256_verify/3,
    ec_secp256r1_keypair/0,
    ec_secp256r1_keypair/1,
    ec_secp256r1_secret_to_public/1,
    ecdh_secp256r1_shared_secret/2,
    ecdsa_secp256r1_sha256_sign/2,
    ecdsa_secp256r1_sha256_verify/3,
    ec_secp384r1_keypair/0,
    ec_secp384r1_keypair/1,
    ec_secp384r1_secret_to_public/1,
    ecdh_secp384r1_shared_secret/2,
    ecdsa_secp384r1_sha384_sign/2,
    ecdsa_secp384r1_sha384_verify/3,
    ec_secp521r1_keypair/0,
    ec_secp521r1_keypair/1,
    ec_secp521r1_secret_to_public/1,
    ecdh_secp521r1_shared_secret/2,
    ecdsa_secp521r1_sha512_sign/2,
    ecdsa_secp521r1_sha512_verify/3
]).

%% Macros
-define(TV_Message(), <<"abc">>).
-define(TV_ec_secp256k1_Seed0(), ?b16d("0000000000000000000000000000000000000000000000000000000000000001")).
-define(TV_ec_secp256k1_SecretKey0(), ?b16d("0000000000000000000000000000000000000000000000000000000000000001")).
-define(TV_ec_secp256k1_PublicKey0(),
    ?b16d(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
).
-define(TV_ec_secp256k1_SecretKey1(), ?b16d("0000000000000000000000000000000000000000000000000000000000000002")).
-define(TV_ec_secp256k1_PublicKey1(),
    ?b16d(
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
    )
).
-define(TV_ecdh_secp256k1_SharedSecret(), ?b16d("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")).
-define(TV_ecdsa_secp256k1_sha256_Sig(),
    ?b16d(
        "fde3c6fb9a9c6f73bbbb1f097c766f446ac83dc86ca9670e4241a8d71e6cb56f91216bfae69b62d5b51501f696fd66948c7d7f0da135a25dbf4899643d4300a7"
    )
).
-define(TV_ec_secp256r1_Seed0(), ?b16d("0000000000000000000000000000000000000000000000000000000000000001")).
-define(TV_ec_secp256r1_SecretKey0(), ?b16d("0000000000000000000000000000000000000000000000000000000000000001")).
-define(TV_ec_secp256r1_PublicKey0(),
    ?b16d(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    )
).
-define(TV_ec_secp256r1_SecretKey1(), ?b16d("0000000000000000000000000000000000000000000000000000000000000002")).
-define(TV_ec_secp256r1_PublicKey1(),
    ?b16d(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
    )
).
-define(TV_ecdh_secp256r1_SharedSecret(), ?b16d("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978")).
-define(TV_ecdsa_secp256r1_sha256_Sig(),
    ?b16d(
        "acd51bdaaddab425bd6440f628c14a34711d2ebc9b36cb7cf98efdfe5b664abd15077b4346c5244ecd1e2330036d4ffc6152f95f513143c73bf68846ce51366f"
    )
).
-define(TV_ec_secp384r1_Seed0(),
    ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")
).
-define(TV_ec_secp384r1_SecretKey0(),
    ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001")
).
-define(TV_ec_secp384r1_PublicKey0(),
    ?b16d(
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
    )
).
-define(TV_ec_secp384r1_SecretKey1(),
    ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002")
).
-define(TV_ec_secp384r1_PublicKey1(),
    ?b16d(
        "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80"
    )
).
-define(TV_ecdh_secp384r1_SharedSecret(),
    ?b16d("08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61")
).
-define(TV_ecdsa_secp384r1_sha384_Sig(),
    ?b16d(
        "ce92b27063aac89338f73b01fe8a19a15b398a2459f069295d2050897e9c3ed21db752d383aaaa91acc23644cd0782b169e60e93d800012cf5fb1d68e4eb02feae37571011899fd91b7fc4890a031ca4c4398cecd815b446e35d1abd75b70631"
    )
).
-define(TV_ec_secp521r1_Seed0(),
    ?b16d(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    )
).
-define(TV_ec_secp521r1_SecretKey0(),
    ?b16d(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    )
).
-define(TV_ec_secp521r1_PublicKey0(),
    ?b16d(
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
    )
).
-define(TV_ec_secp521r1_SecretKey1(),
    ?b16d(
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"
    )
).
-define(TV_ec_secp521r1_PublicKey1(),
    ?b16d(
        "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02"
    )
).
-define(TV_ecdh_secp521r1_SharedSecret(),
    ?b16d(
        "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d"
    )
).
-define(TV_ecdsa_secp521r1_sha512_Sig(),
    ?b16d(
        "005e226d104de466b25afbe93601efd3a1229403bc33f9ae36eaa68b8e13b9e050d318705bea5ccb0ec468f9606a4adf5cf908f7cb2ce8a473d867b336c998e4a2ee00866fed9c896b4875a56769a965062bee0c40c391f68bdad6098d9eae98abb0691f72fd1fdd458cf4fbf0978ecf7ce9e83d5613ef0308c51cb22e143cb3db83c365"
    )
).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{ec_secp256k1_keypair, 0}, []},
            {{ec_secp256k1_keypair, 1}, []},
            {{ec_secp256k1_secret_to_public, 1}, []},
            {{ecdh_secp256k1_shared_secret, 2}, []},
            {{ecdsa_secp256k1_sha256_sign, 2}, []},
            {{ecdsa_secp256k1_sha256_verify, 3}, []},
            {{ec_secp256r1_keypair, 0}, []},
            {{ec_secp256r1_keypair, 1}, []},
            {{ec_secp256r1_secret_to_public, 1}, []},
            {{ecdh_secp256r1_shared_secret, 2}, []},
            {{ecdsa_secp256r1_sha256_sign, 2}, []},
            {{ecdsa_secp256r1_sha256_verify, 3}, []},
            {{ec_secp384r1_keypair, 0}, []},
            {{ec_secp384r1_keypair, 1}, []},
            {{ec_secp384r1_secret_to_public, 1}, []},
            {{ecdh_secp384r1_shared_secret, 2}, []},
            {{ecdsa_secp384r1_sha384_sign, 2}, []},
            {{ecdsa_secp384r1_sha384_verify, 3}, []},
            {{ec_secp521r1_keypair, 0}, []},
            {{ec_secp521r1_keypair, 1}, []},
            {{ec_secp521r1_secret_to_public, 1}, []},
            {{ecdh_secp521r1_shared_secret, 2}, []},
            {{ecdsa_secp521r1_sha512_sign, 2}, []},
            {{ecdsa_secp521r1_sha512_verify, 3}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, ec_secp256k1_keypair, 0) ->
    case Module:ec_secp256k1_keypair() of
        {<<_PK:512/bits>>, <<_SK:256/bits>>} ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ec_secp256k1_keypair, [], Actual, {badmatch, "PK must be 512-bits, SK must be 256-bits"}
                )}
    end;
support_check(Module, ec_secp256k1_keypair, 1) ->
    Seed = ?TV_ec_secp256k1_Seed0(),
    PK = ?TV_ec_secp256k1_PublicKey0(),
    SK = ?TV_ec_secp256k1_SecretKey0(),
    ?expect({PK, SK}, Module, ec_secp256k1_keypair, [Seed]);
support_check(Module, ec_secp256k1_secret_to_public, 1) ->
    SK = ?TV_ec_secp256k1_SecretKey0(),
    PK = ?TV_ec_secp256k1_PublicKey0(),
    ?expect(PK, Module, ec_secp256k1_secret_to_public, [SK]);
support_check(Module, ecdh_secp256k1_shared_secret, 2) ->
    USK = ?TV_ec_secp256k1_SecretKey0(),
    UPK = ?TV_ec_secp256k1_PublicKey0(),
    VSK = ?TV_ec_secp256k1_SecretKey1(),
    VPK = ?TV_ec_secp256k1_PublicKey1(),
    Z = ?TV_ecdh_secp256k1_SharedSecret(),
    ?expect([
        {Z, Module, ecdh_secp256k1_shared_secret, [USK, VPK]},
        {Z, Module, ecdh_secp256k1_shared_secret, [VSK, UPK]}
    ]);
support_check(Module, ecdsa_secp256k1_sha256_sign, 2) ->
    Message = ?TV_Message(),
    SK = ?TV_ec_secp256k1_SecretKey0(),
    Sig = ?TV_ecdsa_secp256k1_sha256_Sig(),
    SigSize = bit_size(Sig),
    case Module:ecdsa_secp256k1_sha256_sign(Message, SK) of
        <<_Sig:SigSize/bits>> ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ecdsa_secp256k1_sha256_sign, [Message, SK], Actual, {badmatch, "Sig must be 512-bits"}
                )}
    end;
support_check(Module, ecdsa_secp256k1_sha256_verify, 3) ->
    Sig = ?TV_ecdsa_secp256k1_sha256_Sig(),
    Message = ?TV_Message(),
    PK = ?TV_ec_secp256k1_PublicKey0(),
    ?expect(true, Module, ecdsa_secp256k1_sha256_verify, [Sig, Message, PK]);
support_check(Module, ec_secp256r1_keypair, 0) ->
    case Module:ec_secp256r1_keypair() of
        {<<_PK:512/bits>>, <<_SK:256/bits>>} ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ec_secp256r1_keypair, [], Actual, {badmatch, "PK must be 512-bits, SK must be 256-bits"}
                )}
    end;
support_check(Module, ec_secp256r1_keypair, 1) ->
    Seed = ?TV_ec_secp256r1_Seed0(),
    PK = ?TV_ec_secp256r1_PublicKey0(),
    SK = ?TV_ec_secp256r1_SecretKey0(),
    ?expect({PK, SK}, Module, ec_secp256r1_keypair, [Seed]);
support_check(Module, ec_secp256r1_secret_to_public, 1) ->
    SK = ?TV_ec_secp256r1_SecretKey0(),
    PK = ?TV_ec_secp256r1_PublicKey0(),
    ?expect(PK, Module, ec_secp256r1_secret_to_public, [SK]);
support_check(Module, ecdsa_secp256r1_sha256_sign, 2) ->
    Message = ?TV_Message(),
    SK = ?TV_ec_secp256r1_SecretKey0(),
    Sig = ?TV_ecdsa_secp256r1_sha256_Sig(),
    SigSize = bit_size(Sig),
    case Module:ecdsa_secp256r1_sha256_sign(Message, SK) of
        <<_Sig:SigSize/bits>> ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ecdsa_secp256r1_sha256_sign, [Message, SK], Actual, {badmatch, "Sig must be 512-bits"}
                )}
    end;
support_check(Module, ecdh_secp256r1_shared_secret, 2) ->
    USK = ?TV_ec_secp256r1_SecretKey0(),
    UPK = ?TV_ec_secp256r1_PublicKey0(),
    VSK = ?TV_ec_secp256r1_SecretKey1(),
    VPK = ?TV_ec_secp256r1_PublicKey1(),
    Z = ?TV_ecdh_secp256r1_SharedSecret(),
    ?expect([
        {Z, Module, ecdh_secp256r1_shared_secret, [USK, VPK]},
        {Z, Module, ecdh_secp256r1_shared_secret, [VSK, UPK]}
    ]);
support_check(Module, ecdsa_secp256r1_sha256_verify, 3) ->
    Sig = ?TV_ecdsa_secp256r1_sha256_Sig(),
    Message = ?TV_Message(),
    PK = ?TV_ec_secp256r1_PublicKey0(),
    ?expect(true, Module, ecdsa_secp256r1_sha256_verify, [Sig, Message, PK]);
support_check(Module, ec_secp384r1_keypair, 0) ->
    case Module:ec_secp384r1_keypair() of
        {<<_PK:768/bits>>, <<_SK:384/bits>>} ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ec_secp384r1_keypair, [], Actual, {badmatch, "PK must be 768-bits, SK must be 384-bits"}
                )}
    end;
support_check(Module, ec_secp384r1_keypair, 1) ->
    Seed = ?TV_ec_secp384r1_Seed0(),
    PK = ?TV_ec_secp384r1_PublicKey0(),
    SK = ?TV_ec_secp384r1_SecretKey0(),
    ?expect({PK, SK}, Module, ec_secp384r1_keypair, [Seed]);
support_check(Module, ec_secp384r1_secret_to_public, 1) ->
    SK = ?TV_ec_secp384r1_SecretKey0(),
    PK = ?TV_ec_secp384r1_PublicKey0(),
    ?expect(PK, Module, ec_secp384r1_secret_to_public, [SK]);
support_check(Module, ecdh_secp384r1_shared_secret, 2) ->
    USK = ?TV_ec_secp384r1_SecretKey0(),
    UPK = ?TV_ec_secp384r1_PublicKey0(),
    VSK = ?TV_ec_secp384r1_SecretKey1(),
    VPK = ?TV_ec_secp384r1_PublicKey1(),
    Z = ?TV_ecdh_secp384r1_SharedSecret(),
    ?expect([
        {Z, Module, ecdh_secp384r1_shared_secret, [USK, VPK]},
        {Z, Module, ecdh_secp384r1_shared_secret, [VSK, UPK]}
    ]);
support_check(Module, ecdsa_secp384r1_sha384_sign, 2) ->
    Message = ?TV_Message(),
    SK = ?TV_ec_secp384r1_SecretKey0(),
    Sig = ?TV_ecdsa_secp384r1_sha384_Sig(),
    SigSize = bit_size(Sig),
    case Module:ecdsa_secp384r1_sha384_sign(Message, SK) of
        <<_Sig:SigSize/bits>> ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ecdsa_secp384r1_sha384_sign, [Message, SK], Actual, {badmatch, "Sig must be 768-bits"}
                )}
    end;
support_check(Module, ecdsa_secp384r1_sha384_verify, 3) ->
    Sig = ?TV_ecdsa_secp384r1_sha384_Sig(),
    Message = ?TV_Message(),
    PK = ?TV_ec_secp384r1_PublicKey0(),
    ?expect(true, Module, ecdsa_secp384r1_sha384_verify, [Sig, Message, PK]);
support_check(Module, ec_secp521r1_keypair, 0) ->
    case Module:ec_secp521r1_keypair() of
        {<<_PK:1056/bits>>, <<_SK:528/bits>>} ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ec_secp521r1_keypair, [], Actual, {badmatch, "PK must be 768-bits, SK must be 384-bits"}
                )}
    end;
support_check(Module, ec_secp521r1_keypair, 1) ->
    Seed = ?TV_ec_secp521r1_Seed0(),
    PK = ?TV_ec_secp521r1_PublicKey0(),
    SK = ?TV_ec_secp521r1_SecretKey0(),
    ?expect({PK, SK}, Module, ec_secp521r1_keypair, [Seed]);
support_check(Module, ec_secp521r1_secret_to_public, 1) ->
    SK = ?TV_ec_secp521r1_SecretKey0(),
    PK = ?TV_ec_secp521r1_PublicKey0(),
    ?expect(PK, Module, ec_secp521r1_secret_to_public, [SK]);
support_check(Module, ecdh_secp521r1_shared_secret, 2) ->
    USK = ?TV_ec_secp521r1_SecretKey0(),
    UPK = ?TV_ec_secp521r1_PublicKey0(),
    VSK = ?TV_ec_secp521r1_SecretKey1(),
    VPK = ?TV_ec_secp521r1_PublicKey1(),
    Z = ?TV_ecdh_secp521r1_SharedSecret(),
    ?expect([
        {Z, Module, ecdh_secp521r1_shared_secret, [USK, VPK]},
        {Z, Module, ecdh_secp521r1_shared_secret, [VSK, UPK]}
    ]);
support_check(Module, ecdsa_secp521r1_sha512_sign, 2) ->
    Message = ?TV_Message(),
    SK = ?TV_ec_secp521r1_SecretKey0(),
    Sig = ?TV_ecdsa_secp521r1_sha512_Sig(),
    SigSize = bit_size(Sig),
    case Module:ecdsa_secp521r1_sha512_sign(Message, SK) of
        <<_Sig:SigSize/bits>> ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, ecdsa_secp521r1_sha512_sign, [Message, SK], Actual, {badmatch, "Sig must be 1056-bits"}
                )}
    end;
support_check(Module, ecdsa_secp521r1_sha512_verify, 3) ->
    Sig = ?TV_ecdsa_secp521r1_sha512_Sig(),
    Message = ?TV_Message(),
    PK = ?TV_ec_secp521r1_PublicKey0(),
    ?expect(true, Module, ecdsa_secp521r1_sha512_verify, [Sig, Message, PK]).

%%====================================================================
%% jose_ec callbacks
%%====================================================================

-spec ec_secp256k1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp256k1_public_key(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key().
ec_secp256k1_keypair() ->
    ?resolve([]).

-spec ec_secp256k1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp256k1_seed(),
    PublicKey :: jose_ec:ec_secp256k1_public_key(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key().
ec_secp256k1_keypair(Seed) when
    bit_size(Seed) =:= 256
->
    ?resolve([Seed]).

-spec ec_secp256k1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp256k1_secret_key(),
    PublicKey :: jose_ec:ec_secp256k1_public_key().
ec_secp256k1_secret_to_public(SecretKey) when
    bit_size(SecretKey) =:= 256
->
    ?resolve([SecretKey]).

-spec ecdh_secp256k1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp256k1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp256k1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp256k1_shared_secret().
ecdh_secp256k1_shared_secret(MySecretKey, YourPublicKey) when
    bit_size(MySecretKey) =:= 256 andalso
        bit_size(YourPublicKey) =:= 512
->
    ?resolve([MySecretKey, YourPublicKey]).

-spec ecdsa_secp256k1_sha256_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key(),
    Signature :: jose_ec:ecdsa_secp256k1_sha256_signature().
ecdsa_secp256k1_sha256_sign(Message, SecretKey) when
    is_binary(Message) andalso
        bit_size(SecretKey) =:= 256
->
    ?resolve([Message, SecretKey]).

-spec ecdsa_secp256k1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp256k1_sha256_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp256k1_public_key().
ecdsa_secp256k1_sha256_verify(Signature, Message, PublicKey) when
    is_binary(Signature) andalso
        is_binary(Message) andalso
        bit_size(PublicKey) =:= 512
->
    ?resolve([Signature, Message, PublicKey]).

-spec ec_secp256r1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp256r1_public_key(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key().
ec_secp256r1_keypair() ->
    ?resolve([]).

-spec ec_secp256r1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp256r1_seed(),
    PublicKey :: jose_ec:ec_secp256r1_public_key(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key().
ec_secp256r1_keypair(Seed) when
    bit_size(Seed) =:= 256
->
    ?resolve([Seed]).

-spec ec_secp256r1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp256r1_secret_key(),
    PublicKey :: jose_ec:ec_secp256r1_public_key().
ec_secp256r1_secret_to_public(SecretKey) when
    bit_size(SecretKey) =:= 256
->
    ?resolve([SecretKey]).

-spec ecdh_secp256r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp256r1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp256r1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp256r1_shared_secret().
ecdh_secp256r1_shared_secret(MySecretKey, YourPublicKey) when
    bit_size(MySecretKey) =:= 256 andalso
        bit_size(YourPublicKey) =:= 512
->
    ?resolve([MySecretKey, YourPublicKey]).

-spec ecdsa_secp256r1_sha256_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp256r1_sha256_signature().
ecdsa_secp256r1_sha256_sign(Message, SecretKey) when
    is_binary(Message) andalso
        bit_size(SecretKey) =:= 256
->
    ?resolve([Message, SecretKey]).

-spec ecdsa_secp256r1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp256r1_sha256_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp256r1_public_key().
ecdsa_secp256r1_sha256_verify(Signature, Message, PublicKey) when
    is_binary(Signature) andalso
        is_binary(Message) andalso
        bit_size(PublicKey) =:= 512
->
    ?resolve([Signature, Message, PublicKey]).

-spec ec_secp384r1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp384r1_public_key(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key().
ec_secp384r1_keypair() ->
    ?resolve([]).

-spec ec_secp384r1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp384r1_seed(),
    PublicKey :: jose_ec:ec_secp384r1_public_key(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key().
ec_secp384r1_keypair(Seed) when
    bit_size(Seed) =:= 384
->
    ?resolve([Seed]).

-spec ec_secp384r1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp384r1_secret_key(),
    PublicKey :: jose_ec:ec_secp384r1_public_key().
ec_secp384r1_secret_to_public(SecretKey) when
    bit_size(SecretKey) =:= 384
->
    ?resolve([SecretKey]).

-spec ecdh_secp384r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp384r1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp384r1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp384r1_shared_secret().
ecdh_secp384r1_shared_secret(MySecretKey, YourPublicKey) when
    bit_size(MySecretKey) =:= 384 andalso
        bit_size(YourPublicKey) =:= 768
->
    ?resolve([MySecretKey, YourPublicKey]).

-spec ecdsa_secp384r1_sha384_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp384r1_sha384_signature().
ecdsa_secp384r1_sha384_sign(Message, SecretKey) when
    is_binary(Message) andalso
        bit_size(SecretKey) =:= 384
->
    ?resolve([Message, SecretKey]).

-spec ecdsa_secp384r1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp384r1_sha384_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp384r1_public_key().
ecdsa_secp384r1_sha384_verify(Signature, Message, PublicKey) when
    is_binary(Signature) andalso
        is_binary(Message) andalso
        bit_size(PublicKey) =:= 768
->
    ?resolve([Signature, Message, PublicKey]).

-spec ec_secp521r1_keypair() -> {PublicKey, SecretKey} when
    PublicKey :: jose_ec:ec_secp521r1_public_key(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key().
ec_secp521r1_keypair() ->
    ?resolve([]).

-spec ec_secp521r1_secret_to_public(SecretKey) -> PublicKey when
    SecretKey :: jose_ec:ec_secp521r1_secret_key(),
    PublicKey :: jose_ec:ec_secp521r1_public_key().
ec_secp521r1_secret_to_public(SecretKey) when
    bit_size(SecretKey) =:= 528
->
    ?resolve([SecretKey]).

-spec ecdh_secp521r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
    MySecretKey :: jose_ec:ec_secp521r1_secret_key(),
    YourPublicKey :: jose_ec:ec_secp521r1_public_key(),
    SharedSecret :: jose_ec:ecdh_secp521r1_shared_secret().
ecdh_secp521r1_shared_secret(MySecretKey, YourPublicKey) when
    bit_size(MySecretKey) =:= 528 andalso
        bit_size(YourPublicKey) =:= 1056
->
    ?resolve([MySecretKey, YourPublicKey]).

-spec ec_secp521r1_keypair(Seed) -> {PublicKey, SecretKey} when
    Seed :: jose_ec:ec_secp521r1_seed(),
    PublicKey :: jose_ec:ec_secp521r1_public_key(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key().
ec_secp521r1_keypair(Seed) when
    bit_size(Seed) =:= 528
->
    ?resolve([Seed]).

-spec ecdsa_secp521r1_sha512_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp521r1_sha512_signature().
ecdsa_secp521r1_sha512_sign(Message, SecretKey) when
    is_binary(Message) andalso
        bit_size(SecretKey) =:= 528
->
    ?resolve([Message, SecretKey]).

-spec ecdsa_secp521r1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp521r1_sha512_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp521r1_public_key().
ecdsa_secp521r1_sha512_verify(Signature, Message, PublicKey) when
    is_binary(Signature) andalso
        is_binary(Message) andalso
        bit_size(PublicKey) =:= 1056
->
    ?resolve([Signature, Message, PublicKey]).
