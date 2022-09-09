%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_curve448).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type eddsa_public_key() :: <<_:456>>.
-type eddsa_secret_key() :: <<_:912>>.
-type eddsa_seed() :: <<_:456>>.
-type message() :: binary().
-type signature() :: <<_:912>>.
-type maybe_invalid_signature() :: signature() | binary().
-type context() :: binary().
-type x448_public_key() :: <<_:448>>.
-type x448_secret_key() :: <<_:448>>.
-type x448_seed() :: <<_:448>>.
-type x448_shared_secret() :: <<_:448>>.

-export_type([
	eddsa_public_key/0,
	eddsa_secret_key/0,
	eddsa_seed/0,
	message/0,
	signature/0,
	maybe_invalid_signature/0,
	context/0,
	x448_public_key/0,
	x448_secret_key/0,
	x448_seed/0,
	x448_shared_secret/0
]).

%% Callbacks
-callback eddsa_keypair() -> {PublicKey::eddsa_public_key(), SecretKey::eddsa_secret_key()}.
-callback eddsa_keypair(Seed::eddsa_seed()) -> {PublicKey::eddsa_public_key(), SecretKey::eddsa_secret_key()}.
-callback eddsa_secret_to_public(SecretKey::eddsa_secret_key()) -> PublicKey::eddsa_public_key().
-callback ed448_sign(Message::message(), SecretKey::eddsa_secret_key()) -> Signature::signature().
-callback ed448_sign(Message::message(), SecretKey::eddsa_secret_key(), Context::context()) -> Signature::signature().
-callback ed448_verify(Signature::maybe_invalid_signature(), Message::message(), PublicKey::eddsa_public_key()) -> boolean().
-callback ed448_verify(Signature::maybe_invalid_signature(), Message::message(), PublicKey::eddsa_public_key(), Context::context()) -> boolean().
-callback ed448ph_sign(Message::message(), SecretKey::eddsa_secret_key()) -> Signature::signature().
-callback ed448ph_sign(Message::message(), SecretKey::eddsa_secret_key(), Context::context()) -> Signature::signature().
-callback ed448ph_verify(Signature::maybe_invalid_signature(), Message::message(), PublicKey::eddsa_public_key()) -> boolean().
-callback ed448ph_verify(Signature::maybe_invalid_signature(), Message::message(), PublicKey::eddsa_public_key(), Context::context()) -> boolean().
-callback x448_keypair() -> {PublicKey::eddsa_public_key(), SecretKey::eddsa_secret_key()}.
-callback x448_keypair(Seed::x448_seed()) -> {PublicKey::x448_public_key(), SecretKey::x448_secret_key()}.
-callback x448_secret_to_public(SecretKey::x448_secret_key()) -> PublicKey::x448_public_key().
-callback x448_shared_secret(MySecretKey::x448_secret_key(), YourPublicKey::x448_public_key()) -> SharedSecret::x448_shared_secret().

-optional_callbacks([
	eddsa_keypair/0,
	eddsa_keypair/1,
	eddsa_secret_to_public/1,
	ed448_sign/2,
	ed448_sign/3,
	ed448_verify/3,
	ed448_verify/4,
	ed448ph_sign/2,
	ed448ph_sign/3,
	ed448ph_verify/3,
	ed448ph_verify/4,
	x448_keypair/0,
	x448_keypair/1,
	x448_secret_to_public/1,
	x448_shared_secret/2
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_curve448 callbacks
-export([
	eddsa_keypair/0,
	eddsa_keypair/1,
	eddsa_secret_to_public/1,
	ed448_sign/2,
	ed448_sign/3,
	ed448_verify/3,
	ed448_verify/4,
	ed448ph_sign/2,
	ed448ph_sign/3,
	ed448ph_verify/3,
	ed448ph_verify/4,
	x448_keypair/0,
	x448_keypair/1,
	x448_secret_to_public/1,
	x448_shared_secret/2
]).

%% Macros
-define(TV_Ed448Seed(), ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_Ed448SecretKey(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005b3afe03878a49b28232d4f1a442aebde109f807acef7dfd9a7f65b962fe52d6547312cacecff04337508f9d2529a8f1669169b21c32c48000")).
-define(TV_Ed448PublicKey(), ?b16d("5b3afe03878a49b28232d4f1a442aebde109f807acef7dfd9a7f65b962fe52d6547312cacecff04337508f9d2529a8f1669169b21c32c48000")).
-define(TV_Message(), <<"abc">>).
-define(TV_Context(), <<"def">>).
-define(TV_Ed448Sig(), ?b16d("e19483a09206d7ec3cf454b709c8cd83033c3c4b44ef3d5739896c021408332a87dbb69c963b32b0a55a14d8282315296e2dcd6c0bb9bfb10031d46a88863b180fd8a6b9ae1b34ccf5a8277d84448be138f9cfdbb135e624ba1170ddddcc684e590d754632e2aea99f11663db96dfe0c1f00")).
-define(TV_Ed448CtxSig(), ?b16d("d15e7314659b6357bccd199d23e423f9307676f0bc49d83184c9d8130272aa9d894618e94ad705ff986f497e5a60f3e3a04078d301d3479c0018c6437caf111c20b4592c0f0a675e7aedc53a327d4fa7dfabfe1426468dd572f6e6d93d64a735f05809001198b5f7f1cd265ed2e16d911e00")).
-define(TV_Ed448PhSig(), ?b16d("842dd98aa509eadf861c154fbe41c13786e21e7f22beec897420c62cb63f944e5a73d138a7d65805fc2bc9251971e57ebc0420166a03205c00f0b017317bda4bb3520791afb52ea9ea9da990c533a1063d0dcc21ec6b13f73fbba7d6991d2cd2f6556d67fd6bff8905bb4cd94dc025b03200")).
-define(TV_Ed448PhCtxSig(), ?b16d("5bcf72453622d7ce6441da8b20d7e8a00c38f2904296c745990aad56df7337aa2075946738ac58cbb8b416e4c04b1092c5f81f78e47c81c700fe5bd3394b4c90b0554d97f70acd6f9447e7ba2f23684a939361774cd9ba5ecb48ea7c7c5ad1693338c29d4c1881d443a0bf4fa635bcad2700")).
-define(TV_X448Seed(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080")).
-define(TV_X448SecretKey(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080")).
-define(TV_X448PublicKey(), ?b16d("e9b820a44dba3bc569bee7214b62b09ee239b50978a7a1c69a9ade46858cc37c48eb03fd88c289badd708fc635c7d863cc40e4dfdd6d5d40")).
-define(TV_X448USecretKey(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080")).
-define(TV_X448VPublicKey(), ?b16d("172837c1ef0bf5d890af8dcee6bda1ad1970c167e893dd46054795693a11397580fe732f2b50bd9fc1d7596c62fd5c4d5df403e94ad8c507")).
-define(TV_X448SharedSecret(), ?b16d("6c5e8fb7a6e989da0ee5ebbdc6414a77a7e53595f09842c3516af04247c42b0c08b5e79bbc1788d86088b8528b62e1ef0650d9c928155075")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [],
		callbacks => [
			{{eddsa_keypair, 0}, [{jose_sha3, [{shake256, 2}]}]},
			{{eddsa_keypair, 1}, [{jose_sha3, [{shake256, 2}]}]},
			{{eddsa_secret_to_public, 1}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448_sign, 2}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448_sign, 3}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448_verify, 3}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448_verify, 4}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448ph_sign, 2}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448ph_sign, 3}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448ph_verify, 3}, [{jose_sha3, [{shake256, 2}]}]},
			{{ed448ph_verify, 4}, [{jose_sha3, [{shake256, 2}]}]},
			{{x448_keypair, 0}, []},
			{{x448_keypair, 1}, []},
			{{x448_secret_to_public, 1}, []},
			{{x448_shared_secret, 2}, []}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, eddsa_keypair, 0) ->
	case Module:eddsa_keypair() of
		{<<PK:456/bits>>, <<_SK:456/bits, PK:456/bits>>} ->
			ok;
		Actual ->
			{error, ?expect_report(Module, eddsa_keypair, [], Actual, {badmatch, "PK must be 456-bits, SK must be 912-bits"})}
	end;
support_check(Module, eddsa_keypair, 1) ->
	Seed = ?TV_Ed448Seed(),
	PK = ?TV_Ed448PublicKey(),
	SK = ?TV_Ed448SecretKey(),
	?expect({PK, SK}, Module, eddsa_keypair, [Seed]);
support_check(Module, eddsa_secret_to_public, 1) ->
	Seed = ?TV_Ed448Seed(),
	PK = ?TV_Ed448PublicKey(),
	?expect(PK, Module, eddsa_secret_to_public, [Seed]);
support_check(Module, ed448_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_Ed448SecretKey(),
	Sig = ?TV_Ed448Sig(),
	?expect(Sig, Module, ed448_sign, [Message, SK]);
support_check(Module, ed448_verify, 3) ->
	Message = ?TV_Message(),
	PK = ?TV_Ed448PublicKey(),
	Sig = ?TV_Ed448Sig(),
	?expect(true, Module, ed448_verify, [Sig, Message, PK]);
support_check(Module, ed448_sign, 3) ->
	Message = ?TV_Message(),
	Context = ?TV_Context(),
	SK = ?TV_Ed448SecretKey(),
	Sig = ?TV_Ed448CtxSig(),
	?expect(Sig, Module, ed448_sign, [Message, SK, Context]);
support_check(Module, ed448_verify, 4) ->
	Message = ?TV_Message(),
	Context = ?TV_Context(),
	PK = ?TV_Ed448PublicKey(),
	Sig = ?TV_Ed448CtxSig(),
	?expect(true, Module, ed448_verify, [Sig, Message, PK, Context]);
support_check(Module, ed448ph_sign, 2) ->
	Message = ?TV_Message(),
	SK = ?TV_Ed448SecretKey(),
	Sig = ?TV_Ed448PhSig(),
	?expect(Sig, Module, ed448ph_sign, [Message, SK]);
support_check(Module, ed448ph_verify, 3) ->
	Message = ?TV_Message(),
	PK = ?TV_Ed448PublicKey(),
	Sig = ?TV_Ed448PhSig(),
	?expect(true, Module, ed448ph_verify, [Sig, Message, PK]);
support_check(Module, ed448ph_sign, 3) ->
	Message = ?TV_Message(),
	Context = ?TV_Context(),
	SK = ?TV_Ed448SecretKey(),
	Sig = ?TV_Ed448PhCtxSig(),
	?expect(Sig, Module, ed448ph_sign, [Message, SK, Context]);
support_check(Module, ed448ph_verify, 4) ->
	Message = ?TV_Message(),
	Context = ?TV_Context(),
	PK = ?TV_Ed448PublicKey(),
	Sig = ?TV_Ed448PhCtxSig(),
	?expect(true, Module, ed448ph_verify, [Sig, Message, PK, Context]);
support_check(Module, x448_keypair, 0) ->
	case Module:x448_keypair() of
		{<<_PK:448/bits>>, <<_SK:448/bits>>} ->
			ok;
		Actual ->
			{error, ?expect_report(Module, x448_keypair, [], Actual, {badmatch, "PK must be 448-bits, SK must be 448-bits"})}
	end;
support_check(Module, x448_keypair, 1) ->
	Seed = ?TV_X448Seed(),
	SK = ?TV_X448SecretKey(),
	PK = ?TV_X448PublicKey(),
	?expect({PK, SK}, Module, x448_keypair, [Seed]);
support_check(Module, x448_secret_to_public, 1) ->
	Seed = ?TV_X448Seed(),
	PK = ?TV_X448PublicKey(),
	?expect(PK, Module, x448_secret_to_public, [Seed]);
support_check(Module, x448_shared_secret, 2) ->
	USK = ?TV_X448USecretKey(),
	VPK = ?TV_X448VPublicKey(),
	Z = ?TV_X448SharedSecret(),
	?expect(Z, Module, x448_shared_secret, [USK, VPK]).

%%====================================================================
%% jose_curve448 callbacks
%%====================================================================

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

% Ed448
-spec ed448_sign(message(), eddsa_secret_key()) -> signature().
ed448_sign(Message, SecretKey) ->
	?resolve([Message, SecretKey]).

-spec ed448_sign(message(), eddsa_secret_key(), context()) -> signature().
ed448_sign(Message, SecretKey, Context) ->
	?resolve([Message, SecretKey, Context]).

-spec ed448_verify(maybe_invalid_signature(), message(), eddsa_public_key()) -> boolean().
ed448_verify(Signature, Message, PublicKey) ->
	?resolve([Signature, Message, PublicKey]).

-spec ed448_verify(maybe_invalid_signature(), message(), eddsa_public_key(), context()) -> boolean().
ed448_verify(Signature, Message, PublicKey, Context) ->
	?resolve([Signature, Message, PublicKey, Context]).

% Ed448ph
-spec ed448ph_sign(message(), eddsa_secret_key()) -> signature().
ed448ph_sign(Message, SecretKey) ->
	?resolve([Message, SecretKey]).

-spec ed448ph_sign(message(), eddsa_secret_key(), context()) -> signature().
ed448ph_sign(Message, SecretKey, Context) ->
	?resolve([Message, SecretKey, Context]).

-spec ed448ph_verify(maybe_invalid_signature(), message(), eddsa_public_key()) -> boolean().
ed448ph_verify(Signature, Message, PublicKey) ->
	?resolve([Signature, Message, PublicKey]).

-spec ed448ph_verify(maybe_invalid_signature(), message(), eddsa_public_key(), context()) -> boolean().
ed448ph_verify(Signature, Message, PublicKey, Context) ->
	?resolve([Signature, Message, PublicKey, Context]).

% X448
-spec x448_keypair() -> {x448_public_key(), x448_secret_key()}.
x448_keypair() ->
	?resolve([]).

-spec x448_keypair(x448_seed()) -> {x448_public_key(), x448_secret_key()}.
x448_keypair(Seed) ->
	?resolve([Seed]).

-spec x448_secret_to_public(x448_secret_key()) -> x448_public_key().
x448_secret_to_public(SecretKey) ->
	?resolve([SecretKey]).

-spec x448_shared_secret(MySecretKey :: x448_secret_key(), YourPublicKey :: x448_public_key()) -> x448_shared_secret().
x448_shared_secret(MySecretKey, YourPublicKey) ->
	?resolve([MySecretKey, YourPublicKey]).
