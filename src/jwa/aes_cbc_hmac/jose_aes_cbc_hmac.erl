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
-module(jose_aes_cbc_hmac).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type additional_authenticated_data() :: binary().
-type plain_text() :: binary().
-type cipher_text() :: binary().
-type aes_cbc_hmac_iv() :: <<_:128>>.
-type aes_128_cbc_hmac_sha256_key() :: <<_:256>>.
-type aes_128_cbc_hmac_sha256_tag() :: <<_:128>>.
-type aes_192_cbc_hmac_sha384_key() :: <<_:384>>.
-type aes_192_cbc_hmac_sha384_tag() :: <<_:192>>.
-type aes_256_cbc_hmac_sha512_key() :: <<_:512>>.
-type aes_256_cbc_hmac_sha512_tag() :: <<_:256>>.

-export_type([
	additional_authenticated_data/0,
	plain_text/0,
	cipher_text/0,
	aes_cbc_hmac_iv/0,
	aes_128_cbc_hmac_sha256_key/0,
	aes_128_cbc_hmac_sha256_tag/0,
	aes_192_cbc_hmac_sha384_key/0,
	aes_192_cbc_hmac_sha384_tag/0,
	aes_256_cbc_hmac_sha512_key/0,
	aes_256_cbc_hmac_sha512_tag/0
]).

%% Callbacks
-callback aes_128_cbc_hmac_sha256_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
-callback aes_128_cbc_hmac_sha256_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag().
-callback aes_192_cbc_hmac_sha384_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
-callback aes_192_cbc_hmac_sha384_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_tag().
-callback aes_256_cbc_hmac_sha512_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
-callback aes_256_cbc_hmac_sha512_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_tag().

-optional_callbacks([
	aes_128_cbc_hmac_sha256_decrypt/5,
	aes_128_cbc_hmac_sha256_encrypt/4,
	aes_192_cbc_hmac_sha384_decrypt/5,
	aes_192_cbc_hmac_sha384_encrypt/4,
	aes_256_cbc_hmac_sha512_decrypt/5,
	aes_256_cbc_hmac_sha512_encrypt/4
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_aes_cbc_hmac callbacks
-export([
	aes_128_cbc_hmac_sha256_decrypt/5,
	aes_128_cbc_hmac_sha256_encrypt/4,
	aes_192_cbc_hmac_sha384_decrypt/5,
	aes_192_cbc_hmac_sha384_encrypt/4,
	aes_256_cbc_hmac_sha512_decrypt/5,
	aes_256_cbc_hmac_sha512_encrypt/4
]).

%% Macros
-define(TV_PlainText(), <<"abcdefghijklmnopqrstuvwxyz">>).
-define(TV_AAD(), <<"0123456789">>).
-define(TV_AES_CBC_HMAC_IV(), ?b16d("00000000000000000000000000000000")).
-define(TV_AES_128_CBC_HMAC_SHA256_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_128_CBC_HMAC_SHA256_CipherText(), ?b16d("c3af71addfe4fcac6941286a76ddedc252c6a7c6428a4476790060c872121030")).
-define(TV_AES_128_CBC_HMAC_SHA256_CipherTag(), ?b16d("aa05f92843231a2ebcee37ff31e60295")).
-define(TV_AES_192_CBC_HMAC_SHA384_Key(), ?b16d("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_192_CBC_HMAC_SHA384_CipherText(), ?b16d("ec6374e75e004afc29beafbfb25c057deb52f2742c70d2e9550f04641a59e7dd")).
-define(TV_AES_192_CBC_HMAC_SHA384_CipherTag(), ?b16d("5472102341e0baded88a431f923178e6a45c8a0e72210141")).
-define(TV_AES_256_CBC_HMAC_SHA512_Key(), ?b16d("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_AES_256_CBC_HMAC_SHA512_CipherText(), ?b16d("ac9c9eb761551ffb7d78d88b5e2330146ff8be7cfc0f8ac2b757c9f078b7ad40")).
-define(TV_AES_256_CBC_HMAC_SHA512_CipherTag(), ?b16d("076c81fdbf46e4567ff8395e1a215a45f4e1be92d03706c56751a051ca60bbb8")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [],
		callbacks => [
			{{aes_128_cbc_hmac_sha256_decrypt, 5}, [{jose_aes_cbc, [{aes_128_cbc_decrypt, 3}]}, {jose_hmac, [{hmac_sha256, 2}]}]},
			{{aes_128_cbc_hmac_sha256_encrypt, 4}, [{jose_aes_cbc, [{aes_128_cbc_encrypt, 3}]}, {jose_hmac, [{hmac_sha256, 2}]}]},
			{{aes_192_cbc_hmac_sha384_decrypt, 5}, [{jose_aes_cbc, [{aes_192_cbc_decrypt, 3}]}, {jose_hmac, [{hmac_sha384, 2}]}]},
			{{aes_192_cbc_hmac_sha384_encrypt, 4}, [{jose_aes_cbc, [{aes_192_cbc_encrypt, 3}]}, {jose_hmac, [{hmac_sha384, 2}]}]},
			{{aes_256_cbc_hmac_sha512_decrypt, 5}, [{jose_aes_cbc, [{aes_256_cbc_decrypt, 3}]}, {jose_hmac, [{hmac_sha512, 2}]}]},
			{{aes_256_cbc_hmac_sha512_encrypt, 4}, [{jose_aes_cbc, [{aes_256_cbc_encrypt, 3}]}, {jose_hmac, [{hmac_sha512, 2}]}]}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, aes_128_cbc_hmac_sha256_decrypt, 5) ->
	CipherText = ?TV_AES_128_CBC_HMAC_SHA256_CipherText(),
	CipherTag = ?TV_AES_128_CBC_HMAC_SHA256_CipherTag(),
	AAD = ?TV_AAD(),
	IV = ?TV_AES_CBC_HMAC_IV(),
	CEK = ?TV_AES_128_CBC_HMAC_SHA256_Key(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, aes_128_cbc_hmac_sha256_decrypt, [CipherText, CipherTag, AAD, IV, CEK]);
support_check(Module, aes_128_cbc_hmac_sha256_encrypt, 4) ->
	PlainText = ?TV_PlainText(),
	AAD = ?TV_AAD(),
	IV = ?TV_AES_CBC_HMAC_IV(),
	CEK = ?TV_AES_128_CBC_HMAC_SHA256_Key(),
	CipherText = ?TV_AES_128_CBC_HMAC_SHA256_CipherText(),
	CipherTag = ?TV_AES_128_CBC_HMAC_SHA256_CipherTag(),
	?expect({CipherText, CipherTag}, Module, aes_128_cbc_hmac_sha256_encrypt, [PlainText, AAD, IV, CEK]);
support_check(Module, aes_192_cbc_hmac_sha384_decrypt, 5) ->
	CipherText = ?TV_AES_192_CBC_HMAC_SHA384_CipherText(),
	CipherTag = ?TV_AES_192_CBC_HMAC_SHA384_CipherTag(),
	AAD = ?TV_AAD(),
	IV = ?TV_AES_CBC_HMAC_IV(),
	CEK = ?TV_AES_192_CBC_HMAC_SHA384_Key(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, aes_192_cbc_hmac_sha384_decrypt, [CipherText, CipherTag, AAD, IV, CEK]);
support_check(Module, aes_192_cbc_hmac_sha384_encrypt, 4) ->
	PlainText = ?TV_PlainText(),
	AAD = ?TV_AAD(),
	IV = ?TV_AES_CBC_HMAC_IV(),
	CEK = ?TV_AES_192_CBC_HMAC_SHA384_Key(),
	CipherText = ?TV_AES_192_CBC_HMAC_SHA384_CipherText(),
	CipherTag = ?TV_AES_192_CBC_HMAC_SHA384_CipherTag(),
	?expect({CipherText, CipherTag}, Module, aes_192_cbc_hmac_sha384_encrypt, [PlainText, AAD, IV, CEK]);
support_check(Module, aes_256_cbc_hmac_sha512_decrypt, 5) ->
	CipherText = ?TV_AES_256_CBC_HMAC_SHA512_CipherText(),
	CipherTag = ?TV_AES_256_CBC_HMAC_SHA512_CipherTag(),
	AAD = ?TV_AAD(),
	IV = ?TV_AES_CBC_HMAC_IV(),
	CEK = ?TV_AES_256_CBC_HMAC_SHA512_Key(),
	PlainText = ?TV_PlainText(),
	?expect(PlainText, Module, aes_256_cbc_hmac_sha512_decrypt, [CipherText, CipherTag, AAD, IV, CEK]);
support_check(Module, aes_256_cbc_hmac_sha512_encrypt, 4) ->
	PlainText = ?TV_PlainText(),
	AAD = ?TV_AAD(),
	IV = ?TV_AES_CBC_HMAC_IV(),
	CEK = ?TV_AES_256_CBC_HMAC_SHA512_Key(),
	CipherText = ?TV_AES_256_CBC_HMAC_SHA512_CipherText(),
	CipherTag = ?TV_AES_256_CBC_HMAC_SHA512_CipherTag(),
	?expect({CipherText, CipherTag}, Module, aes_256_cbc_hmac_sha512_encrypt, [PlainText, AAD, IV, CEK]).

%%====================================================================
%% jose_aes_cbc_hmac callbacks
%%====================================================================

-spec aes_128_cbc_hmac_sha256_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
aes_128_cbc_hmac_sha256_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 128
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 256 ->
	?resolve([CipherText, CipherTag, AAD, IV, CEK]).

-spec aes_128_cbc_hmac_sha256_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_128_cbc_hmac_sha256_tag().
aes_128_cbc_hmac_sha256_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 256 ->
	?resolve([PlainText, AAD, IV, CEK]).

-spec aes_192_cbc_hmac_sha384_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
aes_192_cbc_hmac_sha384_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 192
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 384 ->
	?resolve([CipherText, CipherTag, AAD, IV, CEK]).

-spec aes_192_cbc_hmac_sha384_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_192_cbc_hmac_sha384_tag().
aes_192_cbc_hmac_sha384_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 384 ->
	?resolve([PlainText, AAD, IV, CEK]).

-spec aes_256_cbc_hmac_sha512_decrypt(CipherText, CipherTag, AAD, IV, CEK) -> PlainText | error when
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_tag(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_key(),
	PlainText  :: jose_aes_cbc_hmac:plain_text().
aes_256_cbc_hmac_sha512_decrypt(CipherText, CipherTag, AAD, IV, CEK)
		when is_bitstring(CipherText)
		andalso bit_size(CipherTag) =:= 256
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 512 ->
	?resolve([CipherText, CipherTag, AAD, IV, CEK]).

-spec aes_256_cbc_hmac_sha512_encrypt(PlainText, AAD, IV, CEK) -> {CipherText, CipherTag} when
	PlainText  :: jose_aes_cbc_hmac:plain_text(),
	AAD        :: jose_aes_cbc_hmac:additional_authenticated_data(),
	IV         :: jose_aes_cbc_hmac:aes_cbc_hmac_iv(),
	CEK        :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_key(),
	CipherText :: jose_aes_cbc_hmac:cipher_text(),
	CipherTag  :: jose_aes_cbc_hmac:aes_256_cbc_hmac_sha512_tag().
aes_256_cbc_hmac_sha512_encrypt(PlainText, AAD, IV, CEK)
		when is_bitstring(PlainText)
		andalso is_bitstring(AAD)
		andalso bit_size(IV) =:= 128
		andalso bit_size(CEK) =:= 512 ->
	?resolve([PlainText, AAD, IV, CEK]).
