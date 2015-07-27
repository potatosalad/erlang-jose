%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  21 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwe).

-include("jose_jwe.hrl").
-include("jose_jwk.hrl").

%% Decode API
-export([from/1]).
-export([from_binary/1]).
-export([from_file/1]).
-export([from_map/1]).
%% Encode API
-export([to_binary/1]).
-export([to_file/2]).
-export([to_map/1]).
%% API
-export([block_decrypt/2]).
-export([block_encrypt/3]).
-export([block_encrypt/4]).
-export([block_encrypt/5]).
-export([compact/1]).
-export([expand/1]).
-export([key_decrypt/3]).
-export([key_encrypt/3]).
-export([next_cek/2]).
-export([next_iv/1]).

-define(ALG_AES_KW_MODULE,  jose_jwe_alg_aes_kw).
-define(ALG_DIR_MODULE,     jose_jwe_alg_dir).
-define(ALG_ECDH_ES_MODULE, jose_jwe_alg_ecdh_es).
-define(ALG_PBES2_MODULE,   jose_jwe_alg_pbes2).
-define(ALG_RSA_MODULE,     jose_jwe_alg_rsa).
-define(ENC_AES_MODULE,     jose_jwe_enc_aes).
-define(ZIP_MODULE,         jose_jwe_zip).

%%====================================================================
%% Decode API functions
%%====================================================================

from({Modules, Map}) when is_map(Modules) andalso is_map(Map) ->
	from_map({Modules, Map});
from({Modules, Binary}) when is_map(Modules) andalso is_binary(Binary) ->
	from_binary({Modules, Binary});
from(JWK=#jose_jwk{}) ->
	JWK;
from(Other) when is_map(Other) orelse is_binary(Other) ->
	from({#{}, Other}).

from_binary({Modules, Binary}) when is_map(Modules) andalso is_binary(Binary) ->
	from_map({Modules, jsx:decode(Binary, [return_maps])});
from_binary(Binary) when is_binary(Binary) ->
	from_binary({#{}, Binary}).

from_file({Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_binary({Modules, Binary});
		ReadError ->
			ReadError
	end;
from_file(File) when is_binary(File) orelse is_list(File) ->
	from_file({#{}, File}).

from_map(Map) when is_map(Map) ->
	from_map({#{}, Map});
from_map({Modules, Map}) when is_map(Modules) andalso is_map(Map) ->
	from_map({#jose_jwe{}, Modules, Map});
from_map({JWE, Modules = #{ alg := Module }, Map=#{ <<"alg">> := _ }}) ->
	{ALG, Fields} = Module:from_map(Map),
	from_map({JWE#jose_jwe{ alg = {Module, ALG} }, maps:remove(alg, Modules), Fields});
from_map({JWE, Modules = #{ enc := Module }, Map=#{ <<"enc">> := _ }}) ->
	{ENC, Fields} = Module:from_map(Map),
	from_map({JWE#jose_jwe{ enc = {Module, ENC} }, maps:remove(enc, Modules), Fields});
from_map({JWE, Modules = #{ zip := Module }, Map=#{ <<"zip">> := _ }}) ->
	{ZIP, Fields} = Module:from_map(Map),
	from_map({JWE#jose_jwe{ zip = {Module, ZIP} }, maps:remove(zip, Modules), Fields});
from_map({JWE, Modules, Map=#{ <<"alg">> := << "A", _, _, _, "GCMKW", _/binary >> }}) ->
	from_map({JWE, Modules#{ alg => ?ALG_AES_KW_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"alg">> := << "A", _, _, _, "KW", _/binary >> }}) ->
	from_map({JWE, Modules#{ alg => ?ALG_AES_KW_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"alg">> := << "dir", _/binary >> }}) ->
	from_map({JWE, Modules#{ alg => ?ALG_DIR_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"alg">> := << "ECDH-ES", _/binary >> }}) ->
	from_map({JWE, Modules#{ alg => ?ALG_ECDH_ES_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"alg">> := << "PBES2", _/binary >> }}) ->
	from_map({JWE, Modules#{ alg => ?ALG_PBES2_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"alg">> := << "RSA", _/binary >> }}) ->
	from_map({JWE, Modules#{ alg => ?ALG_RSA_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"enc">> := << "A", _/binary >> }}) ->
	from_map({JWE, Modules#{ enc => ?ENC_AES_MODULE }, Map});
from_map({JWE, Modules, Map=#{ <<"zip">> := <<"DEF">> }}) ->
	from_map({JWE, Modules#{ zip => ?ZIP_MODULE }, Map});
from_map({#jose_jwe{ alg = undefined, enc = undefined }, _Modules, _Map}) ->
	{error, {missing_required_keys, [<<"alg">>, <<"enc">>]}};
from_map({JWE, _Modules, Fields}) ->
	JWE#jose_jwe{ fields = Fields }.

%%====================================================================
%% Encode API functions
%%====================================================================

to_binary(JWE=#jose_jwe{}) ->
	{Modules, Map} = to_map(JWE),
	{Modules, jsx:encode(Map)};
to_binary(Other) ->
	to_binary(from(Other)).

to_file(File, JWE=#jose_jwe{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_binary(JWE),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_file(File, from(Other)).

to_map(JWE=#jose_jwe{fields=Fields}) ->
	record_to_map(JWE, #{}, Fields);
to_map(Other) ->
	to_map(from(Other)).

%%====================================================================
%% API functions
%%====================================================================

block_decrypt(Key, EncryptedMap) when is_map(EncryptedMap) ->
	block_decrypt(Key, {#{}, EncryptedMap});
block_decrypt(Key, EncryptedBinary) when is_binary(EncryptedBinary) ->
	block_decrypt(Key, expand(EncryptedBinary));
block_decrypt(Key, {Modules, EncryptedBinary}) when is_binary(EncryptedBinary) ->
	block_decrypt(Key, expand({Modules, EncryptedBinary}));
block_decrypt(Key, {Modules, #{
		<<"protected">> := Protected,
		<<"encrypted_key">> := EncodedEncryptedKey,
		<<"iv">> := EncodedIV,
		<<"ciphertext">> := EncodedCipherText,
		<<"tag">> := EncodedCipherTag,
		<<"aad">> := EncodedAAD}}) ->
	ConcatAAD = << Protected/binary, $., EncodedAAD/binary >>,
	JWE = #jose_jwe{alg={ALGModule, ALG}, enc={ENCModule, ENC}} = from_binary({Modules, base64url:decode(Protected)}),
	EncryptedKey = base64url:decode(EncodedEncryptedKey),
	IV = base64url:decode(EncodedIV),
	CipherText = base64url:decode(EncodedCipherText),
	CipherTag = base64url:decode(EncodedCipherTag),
	CEK = ALGModule:key_decrypt(Key, {ENCModule, ENC, EncryptedKey}, ALG),
	PlainText = maybe_uncompress(ENCModule:block_decrypt({ConcatAAD, CipherText, CipherTag}, CEK, IV, ENC), JWE),
	{PlainText, JWE};
block_decrypt(Key, {Modules, #{
		<<"protected">> := Protected,
		<<"encrypted_key">> := EncodedEncryptedKey,
		<<"iv">> := EncodedIV,
		<<"ciphertext">> := EncodedCipherText,
		<<"tag">> := EncodedCipherTag}}) ->
	JWE = #jose_jwe{alg={ALGModule, ALG}, enc={ENCModule, ENC}} = from_binary({Modules, base64url:decode(Protected)}),
	EncryptedKey = base64url:decode(EncodedEncryptedKey),
	IV = base64url:decode(EncodedIV),
	CipherText = base64url:decode(EncodedCipherText),
	CipherTag = base64url:decode(EncodedCipherTag),
	CEK = ALGModule:key_decrypt(Key, {ENCModule, ENC, EncryptedKey}, ALG),
	PlainText = maybe_uncompress(ENCModule:block_decrypt({Protected, CipherText, CipherTag}, CEK, IV, ENC), JWE),
	{PlainText, JWE}.

block_encrypt(Key, Block, JWE=#jose_jwe{}) ->
	CEK = next_cek(Key, JWE),
	block_encrypt(Key, Block, CEK, JWE);
block_encrypt(Key, PlainText, Other) ->
	block_encrypt(Key, PlainText, from(Other)).

block_encrypt(Key, Block, CEK, JWE=#jose_jwe{}) ->
	IV = next_iv(JWE),
	block_encrypt(Key, Block, CEK, IV, JWE);
block_encrypt(Key, Block, CEK, Other) ->
	block_encrypt(Key, Block, CEK, from(Other)).

block_encrypt(Key, PlainText, CEK, IV, JWE0=#jose_jwe{alg={ALGModule, ALG0}, enc={ENCModule, ENC}})
		when is_binary(PlainText) ->
	{EncryptedKey, ALG1} = ALGModule:key_encrypt(Key, CEK, ALG0),
	JWE1 = JWE0#jose_jwe{alg={ALGModule, ALG1}},
	{Modules, ProtectedBinary} = to_binary(JWE1),
	Protected = base64url:encode(ProtectedBinary),
	{CipherText, CipherTag} = ENCModule:block_encrypt({Protected, maybe_compress(PlainText, JWE1)}, CEK, IV, ENC),
	{Modules, #{
		<<"protected">> => Protected,
		<<"encrypted_key">> => base64url:encode(EncryptedKey),
		<<"iv">> => base64url:encode(IV),
		<<"ciphertext">> => base64url:encode(CipherText),
		<<"tag">> => base64url:encode(CipherTag)
	}};
block_encrypt(Key, {AAD0, PlainText}, CEK, IV, JWE0=#jose_jwe{alg={ALGModule, ALG0}, enc={ENCModule, ENC}})
		when is_binary(AAD0)
		andalso is_binary(PlainText) ->
	{EncryptedKey, ALG1} = ALGModule:key_encrypt(Key, CEK, ALG0),
	JWE1 = JWE0#jose_jwe{alg={ALGModule, ALG1}},
	{Modules, ProtectedBinary} = to_binary(JWE1),
	Protected = base64url:encode(ProtectedBinary),
	AAD1 = base64url:encode(AAD0),
	ConcatAAD = << Protected/binary, $., AAD1/binary >>,
	{CipherText, CipherTag} = ENCModule:block_encrypt({ConcatAAD, maybe_compress(PlainText, JWE1)}, CEK, IV, ENC),
	{Modules, #{
		<<"protected">> => Protected,
		<<"encrypted_key">> => base64url:encode(EncryptedKey),
		<<"iv">> => base64url:encode(IV),
		<<"ciphertext">> => base64url:encode(CipherText),
		<<"tag">> => base64url:encode(CipherTag),
		<<"aad">> => AAD1
	}};
block_encrypt(Key, Block, CEK, IV, Other) ->
	block_encrypt(Key, Block, CEK, IV, from(Other)).

compact(BadArg={_, #{ <<"aad">> := _ }}) ->
	erlang:error({badarg, [BadArg]});
compact({Modules, #{
		<<"protected">> := Protected,
		<<"encrypted_key">> := EncryptedKey,
		<<"iv">> := InitializationVector,
		<<"ciphertext">> := CipherText,
		<<"tag">> := AuthenticationTag}}) ->
	{Modules, <<
		Protected/binary, $.,
		EncryptedKey/binary, $.,
		InitializationVector/binary, $.,
		CipherText/binary, $.,
		AuthenticationTag/binary
	>>};
compact(Map) when is_map(Map) ->
	compact({#{}, Map}).

expand({Modules, Binary}) when is_binary(Binary) ->
	case binary:split(Binary, <<".">>, [global]) of
		[Protected, EncryptedKey, InitializationVector, CipherText, AuthenticationTag] ->
			{Modules, #{
				<<"protected">> => Protected,
				<<"encrypted_key">> => EncryptedKey,
				<<"iv">> => InitializationVector,
				<<"ciphertext">> => CipherText,
				<<"tag">> => AuthenticationTag
			}};
		_ ->
			erlang:error({badarg, [{Modules, Binary}]})
	end;
expand(Binary) when is_binary(Binary) ->
	expand({#{}, Binary}).

key_decrypt(Key, EncryptedKey, #jose_jwe{alg={ALGModule, ALG}}) ->
	ALGModule:key_decrypt(Key, EncryptedKey, ALG);
key_decrypt(Key, EncryptedKey, Other) ->
	key_decrypt(Key, EncryptedKey, from(Other)).

key_encrypt(Key, DecryptedKey, JWE0=#jose_jwe{alg={ALGModule, ALG0}}) ->
	{EncryptedKey, ALG1} = ALGModule:key_encrypt(Key, DecryptedKey, ALG0),
	JWE1 = JWE0#jose_jwe{alg={ALGModule, ALG1}},
	{EncryptedKey, JWE1};
key_encrypt(Key, EncryptedKey, Other) ->
	key_encrypt(Key, EncryptedKey, from(Other)).

next_cek(Key, #jose_jwe{alg={ALGModule, ALG}, enc={ENCModule, ENC}}) ->
	ALGModule:next_cek(Key, ENCModule, ENC, ALG);
next_cek(Key, Other) ->
	next_cek(Key, from(Other)).

next_iv(#jose_jwe{enc={ENCModule, ENC}}) ->
	ENCModule:next_iv(ENC);
next_iv(Other) ->
	next_iv(from(Other)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
maybe_compress(PlainText, #jose_jwe{zip={Module, ZIP}}) ->
	Module:compress(PlainText, ZIP);
maybe_compress(PlainText, _) ->
	PlainText.

%% @private
maybe_uncompress(Compressed, #jose_jwe{zip={Module, ZIP}}) ->
	Module:uncompress(Compressed, ZIP);
maybe_uncompress(Compressed, _) ->
	Compressed.

%% @private
record_to_map(JWE=#jose_jwe{alg={Module, ALG}}, Modules, Fields0) ->
	Fields1 = Module:to_map(ALG, Fields0),
	record_to_map(JWE#jose_jwe{alg=undefined}, Modules#{ alg => Module }, Fields1);
record_to_map(JWE=#jose_jwe{enc={Module, ENC}}, Modules, Fields0) ->
	Fields1 = Module:to_map(ENC, Fields0),
	record_to_map(JWE#jose_jwe{enc=undefined}, Modules#{ enc => Module }, Fields1);
record_to_map(JWE=#jose_jwe{zip={Module, ZIP}}, Modules, Fields0) ->
	Fields1 = Module:to_map(ZIP, Fields0),
	record_to_map(JWE#jose_jwe{zip=undefined}, Modules#{ zip => Module }, Fields1);
record_to_map(_JWE, Modules, Fields) ->
	{Modules, Fields}.
