%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_curve25519).

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type eddsa_public_key() :: <<_:256>>.
-type eddsa_secret_key() :: <<_:512>>.
-type eddsa_seed() :: <<_:256>>.
-type message() :: binary().
-type signature() :: <<_:512>>.
-type maybe_invalid_signature() :: signature() | binary().
-type context() :: binary().
-type x25519_public_key() :: <<_:256>>.
-type x25519_secret_key() :: <<_:256>>.
-type x25519_seed() :: <<_:256>>.
-type x25519_shared_secret() :: <<_:256>>.

-export_type([
    eddsa_public_key/0,
    eddsa_secret_key/0,
    eddsa_seed/0,
    message/0,
    signature/0,
    maybe_invalid_signature/0,
    context/0,
    x25519_public_key/0,
    x25519_secret_key/0,
    x25519_seed/0,
    x25519_shared_secret/0
]).

%% Callbacks
-callback eddsa_keypair() -> {PublicKey :: eddsa_public_key(), SecretKey :: eddsa_secret_key()}.
-callback eddsa_keypair(Seed :: eddsa_seed()) -> {PublicKey :: eddsa_public_key(), SecretKey :: eddsa_secret_key()}.
-callback eddsa_secret_to_public(SecretKey :: eddsa_secret_key()) -> PublicKey :: eddsa_public_key().
-callback ed25519_sign(Message :: message(), SecretKey :: eddsa_secret_key()) -> Signature :: signature().
-callback ed25519_verify(Signature :: maybe_invalid_signature(), Message :: message(), PublicKey :: eddsa_public_key()) ->
    boolean().
-callback ed25519ctx_sign(Message :: message(), SecretKey :: eddsa_secret_key(), Context :: context()) ->
    Signature :: signature().
-callback ed25519ctx_verify(
    Signature :: maybe_invalid_signature(), Message :: message(), PublicKey :: eddsa_public_key(), Context :: context()
) -> boolean().
-callback ed25519ph_sign(Message :: message(), SecretKey :: eddsa_secret_key()) -> Signature :: signature().
-callback ed25519ph_sign(Message :: message(), SecretKey :: eddsa_secret_key(), Context :: context()) ->
    Signature :: signature().
-callback ed25519ph_verify(
    Signature :: maybe_invalid_signature(), Message :: message(), PublicKey :: eddsa_public_key()
) ->
    boolean().
-callback ed25519ph_verify(
    Signature :: maybe_invalid_signature(), Message :: message(), PublicKey :: eddsa_public_key(), Context :: context()
) -> boolean().
-callback x25519_keypair() -> {PublicKey :: x25519_public_key(), SecretKey :: x25519_secret_key()}.
-callback x25519_keypair(Seed :: x25519_seed()) -> {PublicKey :: x25519_public_key(), SecretKey :: x25519_secret_key()}.
-callback x25519_secret_to_public(SecretKey :: x25519_secret_key()) -> PublicKey :: x25519_public_key().
-callback x25519_shared_secret(MySecretKey :: x25519_secret_key(), YourPublicKey :: x25519_public_key()) ->
    SharedSecret :: x25519_shared_secret().

-optional_callbacks([
    eddsa_keypair/0,
    eddsa_keypair/1,
    eddsa_secret_to_public/1,
    ed25519_sign/2,
    ed25519_verify/3,
    ed25519ctx_sign/3,
    ed25519ctx_verify/4,
    ed25519ph_sign/2,
    ed25519ph_sign/3,
    ed25519ph_verify/3,
    ed25519ph_verify/4,
    x25519_keypair/0,
    x25519_keypair/1,
    x25519_secret_to_public/1,
    x25519_shared_secret/2
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_curve25519 callbacks
-export([
    eddsa_keypair/0,
    eddsa_keypair/1,
    eddsa_secret_to_public/1,
    ed25519_sign/2,
    ed25519_verify/3,
    ed25519ctx_sign/3,
    ed25519ctx_verify/4,
    ed25519ph_sign/2,
    ed25519ph_sign/3,
    ed25519ph_verify/3,
    ed25519ph_verify/4,
    x25519_keypair/0,
    x25519_keypair/1,
    x25519_secret_to_public/1,
    x25519_shared_secret/2
]).

%% Macros
-define(TV_Ed25519Seed(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_Ed25519SecretKey(),
    ?b16d(
        "00000000000000000000000000000000000000000000000000000000000000003b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
    )
).
-define(TV_Ed25519PublicKey(), ?b16d("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")).
-define(TV_Message(), <<"abc">>).
-define(TV_Context(), <<"def">>).
-define(TV_Ed25519Sig(),
    ?b16d(
        "885dfb07cab2796eb960531a2f09b972ad59b97bb125bef5fdda0855d6bebebf24447e705fa11575639df396c201ccf52a1a16b014a7a2f0ce73a7a161757308"
    )
).
-define(TV_Ed25519CtxSig(),
    ?b16d(
        "a82ed5ebd28d67c38df18697c1edf10ebadbb0440f964cee4f3931695c5a5206312c1f75d2f070359495e2c321fac485986bca87cbb034b5ecf3bb96cf7a5b0c"
    )
).
-define(TV_Ed25519PhSig(),
    ?b16d(
        "9fd73a9fc6485f02a992ff8016c29b54c05ab06bb525a047df74725f8a0464eb9ef5e4c88db6f99b6d73409ed0148d26442893b4ec21be8b540f2c291ff21701"
    )
).
-define(TV_Ed25519PhCtxSig(),
    ?b16d(
        "d6d51c767b1028aa479919a2aded7664698d655e14d7811ea32239f5437bd6f9a096fff6c690f1226689a162150f950ca7876c67ade47891eb02c12d25ba4903"
    )
).
-define(TV_X25519Seed(), ?b16d("0000000000000000000000000000000000000000000000000000000000000040")).
-define(TV_X25519SecretKey(), ?b16d("0000000000000000000000000000000000000000000000000000000000000040")).
-define(TV_X25519PublicKey(), ?b16d("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")).
-define(TV_X25519USecretKey(), ?b16d("0000000000000000000000000000000000000000000000000000000000000040")).
-define(TV_X25519VPublicKey(), ?b16d("847c0d2c375234f365e660955187a3735a0f7613d1609d3a6a4d8c53aeaa5a22")).
-define(TV_X25519SharedSecret(), ?b16d("f12f59031bae093b8575957f3e10cc799c437778e5d6cf4ea04542135c3dcd11")).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{eddsa_keypair, 0}, [{jose_sha2, [{sha512, 1}]}]},
            {{eddsa_keypair, 1}, [{jose_sha2, [{sha512, 1}]}]},
            {{eddsa_secret_to_public, 1}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519_sign, 2}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519_verify, 3}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519ctx_sign, 3}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519ctx_verify, 4}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519ph_sign, 2}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519ph_sign, 3}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519ph_verify, 3}, [{jose_sha2, [{sha512, 1}]}]},
            {{ed25519ph_verify, 4}, [{jose_sha2, [{sha512, 1}]}]},
            {{x25519_keypair, 0}, []},
            {{x25519_keypair, 1}, []},
            {{x25519_secret_to_public, 1}, []},
            {{x25519_shared_secret, 2}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, eddsa_keypair, 0) ->
    case Module:eddsa_keypair() of
        {<<PK:256/bits>>, <<_SK:256/bits, PK:256/bits>>} ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, eddsa_keypair, [], Actual, {badmatch, "PK must be 256-bits, SK must be 512-bits"}
                )}
    end;
support_check(Module, eddsa_keypair, 1) ->
    Seed = ?TV_Ed25519Seed(),
    PK = ?TV_Ed25519PublicKey(),
    SK = ?TV_Ed25519SecretKey(),
    ?expect({PK, SK}, Module, eddsa_keypair, [Seed]);
support_check(Module, eddsa_secret_to_public, 1) ->
    Seed = ?TV_Ed25519Seed(),
    PK = ?TV_Ed25519PublicKey(),
    ?expect(PK, Module, eddsa_secret_to_public, [Seed]);
support_check(Module, ed25519_sign, 2) ->
    Message = ?TV_Message(),
    SK = ?TV_Ed25519SecretKey(),
    Sig = ?TV_Ed25519Sig(),
    ?expect(Sig, Module, ed25519_sign, [Message, SK]);
support_check(Module, ed25519_verify, 3) ->
    Message = ?TV_Message(),
    PK = ?TV_Ed25519PublicKey(),
    Sig = ?TV_Ed25519Sig(),
    ?expect(true, Module, ed25519_verify, [Sig, Message, PK]);
support_check(Module, ed25519ctx_sign, 3) ->
    Message = ?TV_Message(),
    Context = ?TV_Context(),
    SK = ?TV_Ed25519SecretKey(),
    Sig = ?TV_Ed25519CtxSig(),
    ?expect(Sig, Module, ed25519ctx_sign, [Message, SK, Context]);
support_check(Module, ed25519ctx_verify, 4) ->
    Message = ?TV_Message(),
    Context = ?TV_Context(),
    PK = ?TV_Ed25519PublicKey(),
    Sig = ?TV_Ed25519CtxSig(),
    ?expect(true, Module, ed25519ctx_verify, [Sig, Message, PK, Context]);
support_check(Module, ed25519ph_sign, 2) ->
    Message = ?TV_Message(),
    SK = ?TV_Ed25519SecretKey(),
    Sig = ?TV_Ed25519PhSig(),
    ?expect(Sig, Module, ed25519ph_sign, [Message, SK]);
support_check(Module, ed25519ph_verify, 3) ->
    Message = ?TV_Message(),
    PK = ?TV_Ed25519PublicKey(),
    Sig = ?TV_Ed25519PhSig(),
    ?expect(true, Module, ed25519ph_verify, [Sig, Message, PK]);
support_check(Module, ed25519ph_sign, 3) ->
    Message = ?TV_Message(),
    Context = ?TV_Context(),
    SK = ?TV_Ed25519SecretKey(),
    Sig = ?TV_Ed25519PhCtxSig(),
    ?expect(Sig, Module, ed25519ph_sign, [Message, SK, Context]);
support_check(Module, ed25519ph_verify, 4) ->
    Message = ?TV_Message(),
    Context = ?TV_Context(),
    PK = ?TV_Ed25519PublicKey(),
    Sig = ?TV_Ed25519PhCtxSig(),
    ?expect(true, Module, ed25519ph_verify, [Sig, Message, PK, Context]);
support_check(Module, x25519_keypair, 0) ->
    case Module:x25519_keypair() of
        {<<_PK:256/bits>>, <<_SK:256/bits>>} ->
            ok;
        Actual ->
            {error,
                ?expect_report(
                    Module, x25519_keypair, [], Actual, {badmatch, "PK must be 256-bits, SK must be 256-bits"}
                )}
    end;
support_check(Module, x25519_keypair, 1) ->
    Seed = ?TV_X25519Seed(),
    SK = ?TV_X25519SecretKey(),
    PK = ?TV_X25519PublicKey(),
    ?expect({PK, SK}, Module, x25519_keypair, [Seed]);
support_check(Module, x25519_secret_to_public, 1) ->
    Seed = ?TV_X25519Seed(),
    PK = ?TV_X25519PublicKey(),
    ?expect(PK, Module, x25519_secret_to_public, [Seed]);
support_check(Module, x25519_shared_secret, 2) ->
    USK = ?TV_X25519USecretKey(),
    VPK = ?TV_X25519VPublicKey(),
    Z = ?TV_X25519SharedSecret(),
    ?expect(Z, Module, x25519_shared_secret, [USK, VPK]).

%%%=============================================================================
%%% jose_curve25519 callbacks
%%%=============================================================================

% EdDSA
-spec eddsa_keypair() -> {eddsa_public_key(), eddsa_secret_key()}.
eddsa_keypair() ->
    ?resolve([]).

-spec eddsa_keypair(eddsa_seed()) -> {eddsa_public_key(), eddsa_secret_key()}.
eddsa_keypair(Seed) ->
    ?resolve([Seed]).

-spec eddsa_secret_to_public(eddsa_secret_key()) -> eddsa_public_key().
eddsa_secret_to_public(SecretKey) ->
    ?resolve([SecretKey]).

% Ed25519
-spec ed25519_sign(message(), eddsa_secret_key()) -> signature().
ed25519_sign(Message, SecretKey) ->
    ?resolve([Message, SecretKey]).

-spec ed25519_verify(maybe_invalid_signature(), message(), eddsa_public_key()) -> boolean().
ed25519_verify(Signature, Message, PublicKey) ->
    ?resolve([Signature, Message, PublicKey]).

% Ed25519ctx
-spec ed25519ctx_sign(message(), eddsa_secret_key(), context()) -> signature().
ed25519ctx_sign(Message, SecretKey, Context) ->
    ?resolve([Message, SecretKey, Context]).

-spec ed25519ctx_verify(maybe_invalid_signature(), message(), eddsa_public_key(), context()) -> boolean().
ed25519ctx_verify(Signature, Message, PublicKey, Context) ->
    ?resolve([Signature, Message, PublicKey, Context]).

% Ed25519ph
-spec ed25519ph_sign(message(), eddsa_secret_key()) -> signature().
ed25519ph_sign(Message, SecretKey) ->
    ?resolve([Message, SecretKey]).

-spec ed25519ph_sign(message(), eddsa_secret_key(), context()) -> signature().
ed25519ph_sign(Message, SecretKey, Context) ->
    ?resolve([Message, SecretKey, Context]).

-spec ed25519ph_verify(maybe_invalid_signature(), message(), eddsa_public_key()) -> boolean().
ed25519ph_verify(Signature, Message, PublicKey) ->
    ?resolve([Signature, Message, PublicKey]).

-spec ed25519ph_verify(maybe_invalid_signature(), message(), eddsa_public_key(), context()) -> boolean().
ed25519ph_verify(Signature, Message, PublicKey, Context) ->
    ?resolve([Signature, Message, PublicKey, Context]).

% X25519
-spec x25519_keypair() -> {x25519_public_key(), x25519_secret_key()}.
x25519_keypair() ->
    ?resolve([]).

-spec x25519_keypair(x25519_seed()) -> {x25519_public_key(), x25519_secret_key()}.
x25519_keypair(Seed) ->
    ?resolve([Seed]).

-spec x25519_secret_to_public(x25519_secret_key()) -> x25519_public_key().
x25519_secret_to_public(SecretKey) ->
    ?resolve([SecretKey]).

-spec x25519_shared_secret(MySecretKey :: x25519_secret_key(), YourPublicKey :: x25519_public_key()) ->
    x25519_shared_secret().
x25519_shared_secret(MySecretKey, YourPublicKey) ->
    ?resolve([MySecretKey, YourPublicKey]).
