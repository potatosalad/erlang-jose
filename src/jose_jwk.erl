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
-module(jose_jwk).

-include("jose_jwe.hrl").
-include("jose_jwk.hrl").
-include("jose_jws.hrl").

-callback from_map(Fields) -> KTY
	when
		Fields :: map(),
		KTY    :: any().
-callback to_key(KTY) -> Key
	when
		KTY :: any(),
		Key :: any().
-callback to_map(KTY, Fields) -> Map
	when
		KTY    :: any(),
		Fields :: map(),
		Map    :: map().
-callback to_public_map(KTY, Fields) -> Map
	when
		KTY    :: any(),
		Fields :: map(),
		Map    :: map().
-callback to_thumbprint_map(KTY, Fields) -> Map
	when
		KTY    :: any(),
		Fields :: map(),
		Map    :: map().

%% Decode API
-export([from/1]).
-export([from/2]).
-export([from_binary/1]).
-export([from_binary/2]).
-export([from_file/1]).
-export([from_file/2]).
-export([from_key/1]).
-export([from_map/1]).
-export([from_map/2]).
-export([from_oct/1]).
-export([from_oct/2]).
-export([from_oct_file/1]).
-export([from_oct_file/2]).
-export([from_pem/1]).
-export([from_pem/2]).
-export([from_pem_file/1]).
-export([from_pem_file/2]).
%% Encode API
-export([to_binary/1]).
-export([to_binary/2]).
-export([to_binary/3]).
-export([to_file/2]).
-export([to_file/3]).
-export([to_file/4]).
-export([to_key/1]).
-export([to_map/1]).
-export([to_map/2]).
-export([to_map/3]).
-export([to_oct/1]).
-export([to_oct/2]).
-export([to_oct/3]).
-export([to_oct_file/2]).
-export([to_oct_file/3]).
-export([to_oct_file/4]).
-export([to_pem/1]).
-export([to_pem/2]).
-export([to_pem_file/2]).
-export([to_pem_file/3]).
-export([to_public/1]).
-export([to_public_file/2]).
-export([to_public_key/1]).
-export([to_public_map/1]).
-export([to_thumbprint_map/1]).
%% API
-export([block_decrypt/2]).
-export([block_encrypt/2]).
-export([block_encrypt/3]).
-export([box_decrypt/2]).
-export([box_encrypt/3]).
-export([box_encrypt/4]).
-export([sign/2]).
-export([sign/3]).
-export([thumbprint/1]).
-export([thumbprint/2]).
-export([verify/2]).

%% Types
-type key() :: #jose_jwk{}.

-export_type([key/0]).

-define(KEYS_MODULE,    jose_jwk_set).
-define(KTY_EC_MODULE,  jose_jwk_kty_ec).
-define(KTY_OCT_MODULE, jose_jwk_kty_oct).
-define(KTY_RSA_MODULE, jose_jwk_kty_rsa).

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

from(Key, {Modules, EncryptedMap}) when is_map(Modules) andalso is_map(EncryptedMap) ->
	from_map(Key, {Modules, EncryptedMap});
from(Key, {Modules, EncryptedBinary}) when is_map(Modules) andalso is_binary(EncryptedBinary) ->
	from_binary(Key, {Modules, EncryptedBinary});
from(_Key, JWK=#jose_jwk{}) ->
	JWK;
from(Key, Other) when is_map(Other) orelse is_binary(Other) ->
	from(Key, {#{}, Other}).

from_binary({Modules, Binary}) when is_map(Modules) andalso is_binary(Binary) ->
	from_map({Modules, jose:decode(Binary)});
from_binary(Binary) when is_binary(Binary) ->
	from_binary({#{}, Binary}).

from_binary(Key, {Modules, Encrypted = << ${, _/binary >>}) when is_map(Modules) andalso is_binary(Encrypted) ->
	EncrypedMap = jose:decode(Encrypted),
	from_map(Key, {Modules, EncrypedMap});
from_binary(Key, {Modules, Encrypted}) when is_map(Modules) andalso is_binary(Encrypted) ->
	{JWKBinary, JWE=#jose_jwe{}} = jose_jwe:block_decrypt(Key, {Modules, Encrypted}),
	{JWE, from_binary({Modules, JWKBinary})};
from_binary(Key, Encrypted) when is_binary(Encrypted) ->
	from_binary(Key, {#{}, Encrypted}).

from_file({Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_binary({Modules, Binary});
		ReadError ->
			ReadError
	end;
from_file(File) when is_binary(File) orelse is_list(File) ->
	from_file({#{}, File}).

from_file(Key, {Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_binary(Key, {Modules, Binary});
		ReadError ->
			ReadError
	end;
from_file(Key, File) when is_binary(File) orelse is_list(File) ->
	from_file(Key, {#{}, File}).

from_key(Key) ->
	case jose_jwk_kty:from_key(Key) of
		{KTYModule, {KTY, Fields}} when KTYModule =/= error ->
			#jose_jwk{ kty = {KTYModule, KTY}, fields = Fields };
		FromKeyError ->
			FromKeyError
	end.

from_map(Map) when is_map(Map) ->
	from_map({#{}, Map});
from_map({Modules, Map}) when is_map(Modules) andalso is_map(Map) ->
	from_map({#jose_jwk{}, Modules, Map});
from_map({JWK, Modules=#{ keys := Module }, Map=#{ <<"keys">> := _ }}) ->
	{KEYS, Fields} = Module:from_map(Map),
	from_map({JWK#jose_jwk{ keys = {Module, KEYS} }, maps:remove(keys, Modules), Fields});
from_map({JWK, Modules=#{ kty := Module }, Map=#{ <<"kty">> := _ }}) ->
	{KTY, Fields} = Module:from_map(Map),
	from_map({JWK#jose_jwk{ kty = {Module, KTY} }, maps:remove(kty, Modules), Fields});
from_map({JWK, Modules, Map=#{ <<"keys">> := _ }}) ->
	from_map({JWK, Modules#{ keys => ?KEYS_MODULE }, Map});
from_map({JWK, Modules, Map=#{ <<"kty">> := <<"EC">> }}) ->
	from_map({JWK, Modules#{ kty => ?KTY_EC_MODULE }, Map});
from_map({JWK, Modules, Map=#{ <<"kty">> := <<"oct">> }}) ->
	from_map({JWK, Modules#{ kty => ?KTY_OCT_MODULE }, Map});
from_map({JWK, Modules, Map=#{ <<"kty">> := <<"RSA">> }}) ->
	from_map({JWK, Modules#{ kty => ?KTY_RSA_MODULE }, Map});
from_map({#jose_jwk{ keys = undefined, kty = undefined }, _Modules, _Map}) ->
	{error, {missing_required_keys, [<<"keys">>, <<"kty">>]}};
from_map({JWK, _Modules, Fields}) ->
	JWK#jose_jwk{ fields = Fields }.

from_map(Key, {Modules, Encrypted}) when is_map(Modules) andalso is_map(Encrypted) ->
	{JWKBinary, JWE=#jose_jwe{}} = jose_jwe:block_decrypt(Key, {Modules, Encrypted}),
	{JWE, from_binary({Modules, JWKBinary})};
from_map(Key, Encrypted) when is_map(Encrypted) ->
	from_map(Key, {#{}, Encrypted}).

from_oct({#{ kty := Module }, Binary}) when is_binary(Binary) ->
	{KTY, Fields} = Module:from_oct(Binary),
	#jose_jwk{ kty = {Module, KTY}, fields = Fields };
from_oct({#{}, Binary}) when is_binary(Binary) ->
	case jose_jwk_oct:from_binary(Binary) of
		{Module, {KTY, Fields}} when Module =/= error ->
			#jose_jwk{ kty = {Module, KTY}, fields = Fields };
		OCTError ->
			OCTError
	end;
from_oct(Binary) when is_binary(Binary) ->
	from_oct({#{}, Binary}).

from_oct(Key, {Modules, Encrypted}) when is_map(Modules) andalso is_binary(Encrypted) ->
	{OCTBinary, JWE=#jose_jwe{}} = jose_jwe:block_decrypt(Key, {Modules, Encrypted}),
	{JWE, from_oct({Modules, OCTBinary})};
from_oct(Key, Encrypted) when is_binary(Encrypted) ->
	from_oct(Key, {#{}, Encrypted}).

from_oct_file({Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_oct({Modules, Binary});
		ReadError ->
			ReadError
	end;
from_oct_file(File) when is_binary(File) orelse is_list(File) ->
	from_oct_file({#{}, File}).

from_oct_file(Key, {Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_oct(Key, {Modules, Binary});
		ReadError ->
			ReadError
	end;
from_oct_file(Key, File) when is_binary(File) orelse is_list(File) ->
	from_oct_file(Key, {#{}, File}).

from_pem({#{ kty := Module }, Binary}) when is_binary(Binary) ->
	{KTY, Fields} = Module:from_pem(Binary),
	#jose_jwk{ kty = {Module, KTY}, fields = Fields };
from_pem({#{}, Binary}) when is_binary(Binary) ->
	case jose_jwk_pem:from_binary(Binary) of
		{Module, {KTY, Fields}} when Module =/= error ->
			#jose_jwk{ kty = {Module, KTY}, fields = Fields };
		PEMError ->
			PEMError
	end;
from_pem(Binary) when is_binary(Binary) ->
	from_pem({#{}, Binary}).

from_pem(Key, {#{ kty := Module }, Binary}) when is_binary(Binary) ->
	{KTY, Fields} = Module:from_pem(Key, Binary),
	#jose_jwk{ kty = {Module, KTY}, fields = Fields };
from_pem(Key, {#{}, Binary}) when is_binary(Binary) ->
	case jose_jwk_pem:from_binary(Key, Binary) of
		{Module, {KTY, Fields}} when Module =/= error ->
			#jose_jwk{ kty = {Module, KTY}, fields = Fields };
		PEMError ->
			PEMError
	end;
from_pem(Key, Binary) when is_binary(Binary) ->
	from_pem(Key, {#{}, Binary}).

from_pem_file({Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_pem({Modules, Binary});
		ReadError ->
			ReadError
	end;
from_pem_file(File) when is_binary(File) orelse is_list(File) ->
	from_pem_file({#{}, File}).

from_pem_file(Key, {Modules, File}) when is_map(Modules) andalso (is_binary(File) orelse is_list(File)) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_pem(Key, {Modules, Binary});
		ReadError ->
			ReadError
	end;
from_pem_file(Key, File) when is_binary(File) orelse is_list(File) ->
	from_pem_file(Key, {#{}, File}).

%%====================================================================
%% Encode API functions
%%====================================================================

to_binary(JWK=#jose_jwk{}) ->
	{Modules, Map} = to_map(JWK),
	{Modules, jose:encode(Map)};
to_binary(Other) ->
	to_binary(from(Other)).

to_binary(Key, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	to_binary(Key, Module:key_encryptor(KTY, Fields, Key), JWK);
to_binary(Key, Other) ->
	to_binary(Key, from(Other)).

to_binary(Key, JWE=#jose_jwe{}, JWK=#jose_jwk{}) ->
	{Modules, EncryptedMap} = to_map(Key, JWE, JWK),
	{Modules, jose:encode(EncryptedMap)};
to_binary(Key, JWEOther, JWKOther) ->
	to_binary(Key, jose_jwe:from(JWEOther), from(JWKOther)).

to_file(File, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_binary(JWK),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_file(File, from(Other)).

to_file(Key, File, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) when is_binary(File) orelse is_list(File) ->
	to_file(Key, File, Module:key_encryptor(KTY, Fields, Key), JWK);
to_file(Key, File, Other) when is_binary(File) orelse is_list(File) ->
	to_file(Key, File, from(Other)).

to_file(Key, File, JWE=#jose_jwe{}, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	{Modules, EncryptedBinary} = to_binary(Key, JWE, JWK),
	case file:write_file(File, EncryptedBinary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_file(Key, File, JWEOther, JWKOther) when is_binary(File) orelse is_list(File) ->
	to_file(Key, File, jose_jwe:from(JWEOther), from(JWKOther)).

to_key(#jose_jwk{kty={Module, KTY}}) ->
	{#{ kty => Module }, Module:to_key(KTY)};
to_key(Other) ->
	to_key(from(Other)).

to_map(JWK=#jose_jwk{fields=Fields}) ->
	record_to_map(JWK, #{}, Fields);
to_map(Other) ->
	to_map(from(Other)).

to_map(Key, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	to_map(Key, Module:key_encryptor(KTY, Fields, Key), JWK);
to_map(Key, Other) ->
	to_map(Key, from(Other)).

to_map(Key, JWE=#jose_jwe{}, JWK=#jose_jwk{}) ->
	{Modules0, JWKBinary} = to_binary(JWK),
	{Modules1, Encrypted} = jose_jwe:block_encrypt(Key, JWKBinary, JWE),
	{maps:merge(Modules0, Modules1), Encrypted};
to_map(Key, JWEOther, JWKOther) ->
	to_map(Key, jose_jwe:from(JWEOther), from(JWKOther)).

to_oct(#jose_jwk{kty={Module, KTY}}) ->
	{#{ kty => Module }, Module:to_oct(KTY)};
to_oct(Other) ->
	to_oct(from(Other)).

to_oct(Key, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	to_oct(Key, Module:key_encryptor(KTY, Fields, Key), JWK);
to_oct(Key, Other) ->
	to_oct(Key, from(Other)).

to_oct(Key, JWE=#jose_jwe{}, JWK=#jose_jwk{}) ->
	{Modules0, OCTBinary} = to_oct(JWK),
	{Modules1, EncryptedMap} = jose_jwe:block_encrypt(Key, OCTBinary, JWE),
	jose_jwe:compact({maps:merge(Modules0, Modules1), EncryptedMap});
to_oct(Key, JWEOther, JWKOther) ->
	to_oct(Key, jose_jwe:from(JWEOther), from(JWKOther)).

to_oct_file(File, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_oct(JWK),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_oct_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_oct_file(File, from(Other)).

to_oct_file(Key, File, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) when is_binary(File) orelse is_list(File) ->
	to_oct_file(Key, File, Module:key_encryptor(KTY, Fields, Key), JWK);
to_oct_file(Key, File, Other) when is_binary(File) orelse is_list(File) ->
	to_oct_file(Key, File, from(Other)).

to_oct_file(Key, File, JWE=#jose_jwe{}, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	{Modules, EncryptedBinary} = to_oct(Key, JWE, JWK),
	case file:write_file(File, EncryptedBinary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_oct_file(Key, File, JWEOther, JWKOther) when is_binary(File) orelse is_list(File) ->
	to_oct_file(Key, File, jose_jwe:from(JWEOther), from(JWKOther)).

to_pem(#jose_jwk{kty={Module, KTY}}) ->
	{#{ kty => Module }, Module:to_pem(KTY)};
to_pem(Other) ->
	to_pem(from(Other)).

to_pem(Key, #jose_jwk{kty={Module, KTY}}) ->
	{#{ kty => Module }, Module:to_pem(Key, KTY)};
to_pem(Key, Other) ->
	to_pem(Key, from(Other)).

to_pem_file(File, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_pem(JWK),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_pem_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_pem_file(File, from(Other)).

to_pem_file(Key, File, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_pem(Key, JWK),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_pem_file(Key, File, Other) when is_binary(File) orelse is_list(File) ->
	to_pem_file(Key, File, from(Other)).

to_public(JWK=#jose_jwk{}) ->
	from_map(to_public_map(JWK));
to_public(Other) ->
	to_public(from(Other)).

to_public_file(File, JWK=#jose_jwk{}) when is_binary(File) orelse is_list(File) ->
	to_file(File, to_public(JWK));
to_public_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_public_file(File, from(Other)).

to_public_key(JWT=#jose_jwk{}) ->
	to_key(to_public(JWT));
to_public_key(Other) ->
	to_public_key(from(Other)).

to_public_map(#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	{#{ kty => Module }, Module:to_public_map(KTY, Fields)};
to_public_map(Other) ->
	to_public_map(from(Other)).

to_thumbprint_map(#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	{#{ kty => Module }, Module:to_thumbprint_map(KTY, Fields)};
to_thumbprint_map(Other) ->
	to_thumbprint_map(from(Other)).

%%====================================================================
%% API functions
%%====================================================================

block_decrypt(Encrypted, JWK=#jose_jwk{}) ->
	jose_jwe:block_decrypt(JWK, Encrypted);
block_decrypt(Encrypted, Other) ->
	block_decrypt(Encrypted, from(Other)).

block_encrypt(PlainText, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	block_encrypt(PlainText, Module:block_encryptor(KTY, Fields, PlainText), JWK);
block_encrypt(PlainText, Other) ->
	block_encrypt(PlainText, from(Other)).

block_encrypt(PlainText, JWE=#jose_jwe{}, JWK=#jose_jwk{}) ->
	jose_jwe:block_encrypt(JWK, PlainText, JWE);
block_encrypt(PlainText, JWEOther, JWKOther) ->
	block_encrypt(PlainText, jose_jwe:from(JWEOther), from(JWKOther)).

box_decrypt(Encrypted, MyPrivateJWK=#jose_jwk{}) ->
	jose_jwe:block_decrypt(MyPrivateJWK, Encrypted);
box_decrypt(Encrypted, Other) ->
	box_decrypt(Encrypted, from(Other)).

box_encrypt(PlainText, OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{kty={Module, KTY}}) ->
	{_, MyPublicMap} = to_public_map(MyPrivateJWK),
	Fields = #{ <<"epk">> => MyPublicMap },
	JWEFields = Module:block_encryptor(KTY, Fields, PlainText),
	box_encrypt(PlainText, JWEFields, OtherPublicJWK, MyPrivateJWK);
box_encrypt(PlainText, JWKOtherPublic, JWKMyPrivate) ->
	box_encrypt(PlainText, from(JWKOtherPublic), from(JWKMyPrivate)).

box_encrypt(PlainText, JWE=#jose_jwe{}, OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}) ->
	jose_jwe:block_encrypt({OtherPublicJWK, MyPrivateJWK}, PlainText, JWE);
box_encrypt(PlainText, {JWEModules, JWEMap=#{ <<"apu">> := _, <<"apv">> := _, <<"epk">> := _ }}, OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}) ->
	box_encrypt(PlainText, jose_jwe:from({JWEModules, JWEMap}), OtherPublicJWK, MyPrivateJWK);
box_encrypt(PlainText, {JWEModules, JWEMap0}, OtherPublicJWK=#jose_jwk{}, MyPrivateJWK=#jose_jwk{}) ->
	Keys = [<<"apu">>, <<"apv">>, <<"epk">>] -- maps:keys(JWEMap0),
	JWEMap1 = normalize_box(Keys, JWEMap0, OtherPublicJWK, MyPrivateJWK),
	box_encrypt(PlainText, {JWEModules, JWEMap1}, OtherPublicJWK, MyPrivateJWK);
box_encrypt(PlainText, JWEMap, OtherPublicJWK, MyPrivateJWK) when is_map(JWEMap) ->
	box_encrypt(PlainText, {#{}, JWEMap}, OtherPublicJWK, MyPrivateJWK);
box_encrypt(PlainText, JWE, JWKOtherPublic, JWKMyPrivate) ->
	box_encrypt(PlainText, JWE, from(JWKOtherPublic), from(JWKMyPrivate)).

sign(PlainText, JWK=#jose_jwk{kty={Module, KTY}, fields=Fields}) ->
	sign(PlainText, Module:signer(KTY, Fields, PlainText), JWK);
sign(PlainText, Other) ->
	sign(PlainText, from(Other)).

sign(PlainText, JWS=#jose_jws{}, JWK=#jose_jwk{}) ->
	jose_jws:sign(JWK, PlainText, JWS);
sign(PlainText, JWSOther, JWKOther) ->
	sign(PlainText, jose_jws:from(JWSOther), from(JWKOther)).

%% See https://tools.ietf.org/html/draft-ietf-jose-jwk-thumbprint
thumbprint(JWK=#jose_jwk{}) ->
	thumbprint(sha256, JWK);
thumbprint(Other) ->
	thumbprint(from(Other)).

thumbprint(DigestType, JWK=#jose_jwk{}) ->
	{_, ThumbprintMap} = to_thumbprint_map(JWK),
	ThumbprintBinary = jose:encode(ThumbprintMap),
	base64url:encode(crypto:hash(DigestType, ThumbprintBinary));
thumbprint(DigestType, Other) ->
	thumbprint(DigestType, from(Other)).

verify(Signed, JWK=#jose_jwk{}) ->
	jose_jws:verify(JWK, Signed);
verify(Signed, Other) ->
	verify(Signed, from(Other)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
normalize_box([<<"apu">> | Keys], Map, OtherPublicJWK, MyPrivateJWK=#jose_jwk{fields=#{ <<"kid">> := KID }}) ->
	normalize_box(Keys, Map#{ <<"apu">> => KID }, OtherPublicJWK, MyPrivateJWK);
normalize_box([<<"apu">> | Keys], Map, OtherPublicJWK, MyPrivateJWK) ->
	normalize_box(Keys, Map#{ <<"apu">> => thumbprint(MyPrivateJWK) }, OtherPublicJWK, MyPrivateJWK);
normalize_box([<<"apv">> | Keys], Map, OtherPublicJWK=#jose_jwk{fields=#{ <<"kid">> := KID }}, MyPrivateJWK) ->
	normalize_box(Keys, Map#{ <<"apv">> => KID }, OtherPublicJWK, MyPrivateJWK);
normalize_box([<<"apv">> | Keys], Map, OtherPublicJWK, MyPrivateJWK) ->
	normalize_box(Keys, Map#{ <<"apv">> => thumbprint(OtherPublicJWK) }, OtherPublicJWK, MyPrivateJWK);
normalize_box([<<"epk">> | Keys], Map, OtherPublicJWK, MyPrivateJWK) ->
	{_, MyPublicMap} = to_public_map(MyPrivateJWK),
	normalize_box(Keys, Map#{ <<"epk">> => MyPublicMap }, OtherPublicJWK, MyPrivateJWK);
normalize_box([], Map, _, _) ->
	Map.

%% @private
record_to_map(JWK=#jose_jwk{keys={Module, KEYS}}, Modules, Fields0) ->
	Fields1 = Module:to_map(KEYS, Fields0),
	record_to_map(JWK#jose_jwk{keys=undefined}, Modules#{ keys => Module }, Fields1);
record_to_map(JWK=#jose_jwk{kty={Module, KTY}}, Modules, Fields0) ->
	Fields1 = Module:to_map(KTY, Fields0),
	record_to_map(JWK#jose_jwk{kty=undefined}, Modules#{ kty => Module }, Fields1);
record_to_map(_JWK, Modules, Fields) ->
	{Modules, Fields}.
