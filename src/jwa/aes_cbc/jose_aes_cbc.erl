%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  03 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_aes_cbc).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type plain_text() :: <<_:128, _:_*128>>.
-type cipher_text() :: <<_:128, _:_*128>>.
-type aes_block() :: <<_:128>>.
-type aes_cbc_iv() :: <<_:128>>.
-type aes_128_key() :: <<_:128>>.
-type aes_192_key() :: <<_:192>>.
-type aes_256_key() :: <<_:256>>.

-export_type([
	plain_text/0,
	cipher_text/0,
	aes_block/0,
	aes_cbc_iv/0,
	aes_128_key/0,
	aes_192_key/0,
	aes_256_key/0
]).

%% Callbacks
-callback aes_128_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
	CipherText :: jose_aes_cbc:cipher_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_128_key(),
	PlainText :: jose_aes_cbc:plain_text().
-callback aes_128_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
	PlainText :: jose_aes_cbc:plain_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_128_key(),
	CipherText :: jose_aes_cbc:cipher_text().
-callback aes_192_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
	CipherText :: jose_aes_cbc:cipher_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_192_key(),
	PlainText :: jose_aes_cbc:plain_text().
-callback aes_192_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
	PlainText :: jose_aes_cbc:plain_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_192_key(),
	CipherText :: jose_aes_cbc:cipher_text().
-callback aes_256_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
	CipherText :: jose_aes_cbc:cipher_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_256_key(),
	PlainText :: jose_aes_cbc:plain_text().
-callback aes_256_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
	PlainText :: jose_aes_cbc:plain_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_256_key(),
	CipherText :: jose_aes_cbc:cipher_text().

-optional_callbacks([
	aes_128_cbc_decrypt/3,
	aes_128_cbc_encrypt/3,
	aes_192_cbc_decrypt/3,
	aes_192_cbc_encrypt/3,
	aes_256_cbc_decrypt/3,
	aes_256_cbc_encrypt/3
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_aes_cbc callbacks
-export([
	aes_128_cbc_decrypt/3,
	aes_128_cbc_encrypt/3,
	aes_192_cbc_decrypt/3,
	aes_192_cbc_encrypt/3,
	aes_256_cbc_decrypt/3,
	aes_256_cbc_encrypt/3
]).

%% Macros
-define(TV_PlainText(), <<"abcdefghijklmnopqrstuvwxyz012345">>). % 2 x 128-bit AES blocks
-define(TV_AES_CBC_IV(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_CBC_Key(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_CBC_CipherText(), ?b16d("c3af71addfe4fcac6941286a76ddedc2036cc8906710077cb94b25c663f21820")).
-define(TV_AES_192_CBC_Key(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_AES_192_CBC_CipherText(), ?b16d("ec6374e75e004afc29beafbfb25c057dcae69751794b12d28985eb69a2c60772")).
-define(TV_AES_256_CBC_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_256_CBC_CipherText(), ?b16d("ac9c9eb761551ffb7d78d88b5e233014a7d624ae4222993a989f8c62a4986ec2")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [],
		callbacks => [
			{{aes_128_cbc_decrypt, 3}, [{jose_aes_ecb, [{aes_128_ecb_decrypt, 2}]}]},
			{{aes_128_cbc_encrypt, 3}, [{jose_aes_ecb, [{aes_128_ecb_encrypt, 2}]}]},
			{{aes_192_cbc_decrypt, 3}, [{jose_aes_ecb, [{aes_192_ecb_decrypt, 2}]}]},
			{{aes_192_cbc_encrypt, 3}, [{jose_aes_ecb, [{aes_192_ecb_encrypt, 2}]}]},
			{{aes_256_cbc_decrypt, 3}, [{jose_aes_ecb, [{aes_256_ecb_decrypt, 2}]}]},
			{{aes_256_cbc_encrypt, 3}, [{jose_aes_ecb, [{aes_256_ecb_encrypt, 2}]}]}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, aes_128_cbc_decrypt, 3) ->
	CipherText = ?TV_AES_128_CBC_CipherText(),
	IV = ?TV_AES_CBC_IV(),
	CEK = ?TV_AES_128_CBC_Key(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, aes_128_cbc_decrypt, [CipherText, IV, CEK]);
support_check(Module, aes_128_cbc_encrypt, 3) ->
	PlainText = ?TV_PlainText(),
	IV = ?TV_AES_CBC_IV(),
	CEK = ?TV_AES_128_CBC_Key(),
	CipherText = ?TV_AES_128_CBC_CipherText(),
	?expect(CipherText, Module, aes_128_cbc_encrypt, [PlainText, IV, CEK]);
support_check(Module, aes_192_cbc_decrypt, 3) ->
	CipherText = ?TV_AES_192_CBC_CipherText(),
	IV = ?TV_AES_CBC_IV(),
	CEK = ?TV_AES_192_CBC_Key(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, aes_192_cbc_decrypt, [CipherText, IV, CEK]);
support_check(Module, aes_192_cbc_encrypt, 3) ->
	PlainText = ?TV_PlainText(),
	IV = ?TV_AES_CBC_IV(),
	CEK = ?TV_AES_192_CBC_Key(),
	CipherText = ?TV_AES_192_CBC_CipherText(),
	?expect(CipherText, Module, aes_192_cbc_encrypt, [PlainText, IV, CEK]);
support_check(Module, aes_256_cbc_decrypt, 3) ->
	CipherText = ?TV_AES_256_CBC_CipherText(),
	IV = ?TV_AES_CBC_IV(),
	CEK = ?TV_AES_256_CBC_Key(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, aes_256_cbc_decrypt, [CipherText, IV, CEK]);
support_check(Module, aes_256_cbc_encrypt, 3) ->
	PlainText = ?TV_PlainText(),
	IV = ?TV_AES_CBC_IV(),
	CEK = ?TV_AES_256_CBC_Key(),
	CipherText = ?TV_AES_256_CBC_CipherText(),
	?expect(CipherText, Module, aes_256_cbc_encrypt, [PlainText, IV, CEK]).

%%====================================================================
%% jose_sha2 callbacks
%%====================================================================

-spec aes_128_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
	CipherText :: jose_aes_cbc:cipher_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_128_key(),
	PlainText :: jose_aes_cbc:plain_text().
aes_128_cbc_decrypt(CipherText, IV, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 128 ->
	?resolve([CipherText, IV, CEK]).

-spec aes_128_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
	PlainText :: jose_aes_cbc:plain_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_128_key(),
	CipherText :: jose_aes_cbc:cipher_text().
aes_128_cbc_encrypt(PlainText, IV, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 128 ->
	?resolve([PlainText, IV, CEK]).

-spec aes_192_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
	CipherText :: jose_aes_cbc:cipher_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_192_key(),
	PlainText :: jose_aes_cbc:plain_text().
aes_192_cbc_decrypt(CipherText, IV, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 192 ->
	?resolve([CipherText, IV, CEK]).

-spec aes_192_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
	PlainText :: jose_aes_cbc:plain_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_192_key(),
	CipherText :: jose_aes_cbc:cipher_text().
aes_192_cbc_encrypt(PlainText, IV, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 192 ->
	?resolve([PlainText, IV, CEK]).

-spec aes_256_cbc_decrypt(CipherText, IV, CEK) -> PlainText when
	CipherText :: jose_aes_cbc:cipher_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_256_key(),
	PlainText :: jose_aes_cbc:plain_text().
aes_256_cbc_decrypt(CipherText, IV, CEK) when bit_size(CipherText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 256 ->
	?resolve([CipherText, IV, CEK]).

-spec aes_256_cbc_encrypt(PlainText, IV, CEK) -> CipherText when
	PlainText :: jose_aes_cbc:plain_text(),
	IV :: jose_aes_cbc:aes_cbc_iv(),
	CEK :: jose_aes_cbc:aes_256_key(),
	CipherText :: jose_aes_cbc:cipher_text().
aes_256_cbc_encrypt(PlainText, IV, CEK) when bit_size(PlainText) rem 128 =:= 0 andalso bit_size(IV) =:= 128 andalso bit_size(CEK) =:= 256 ->
	?resolve([PlainText, IV, CEK]).
