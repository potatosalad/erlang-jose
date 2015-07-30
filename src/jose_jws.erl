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
-module(jose_jws).

-include("jose_jwk.hrl").
-include("jose_jws.hrl").

-callback from_map(Fields) -> State
	when
		Fields :: map(),
		State  :: any().
-callback to_map(State, Fields) -> Map
	when
		State  :: any(),
		Fields :: map(),
		Map    :: map().

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
-export([compact/1]).
-export([expand/1]).
-export([sign/3]).
-export([sign/4]).
-export([verify/2]).

-define(ALG_ECDSA_MODULE,          jose_jws_alg_ecdsa).
-define(ALG_HMAC_MODULE,           jose_jws_alg_hmac).
-define(ALG_NONE_MODULE,           jose_jws_alg_none).
-define(ALG_RSA_PKCS1_V1_5_MODULE, jose_jws_alg_rsa_pkcs1_v1_5).
-define(ALG_RSA_PSS_MODULE,        jose_jws_alg_rsa_pss).

%%====================================================================
%% Decode API functions
%%====================================================================

from({Modules, Map}) when is_map(Modules) andalso is_map(Map) ->
	from_map({Modules, Map});
from({Modules, Binary}) when is_map(Modules) andalso is_binary(Binary) ->
	from_binary({Modules, Binary});
from(JWS=#jose_jws{}) ->
	JWS;
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
	from_map({#jose_jws{}, Modules, Map});
from_map({JWS, Modules = #{ alg := Module }, Map=#{ <<"alg">> := _ }}) ->
	{ALG, Fields} = Module:from_map(Map),
	from_map({JWS#jose_jws{ alg = {Module, ALG} }, maps:remove(alg, Modules), Fields});
from_map({JWS, Modules, Map=#{ <<"alg">> := << "ES", _/binary >> }}) ->
	from_map({JWS, Modules#{ alg => ?ALG_ECDSA_MODULE }, Map});
from_map({JWS, Modules, Map=#{ <<"alg">> := << "HS", _/binary >> }}) ->
	from_map({JWS, Modules#{ alg => ?ALG_HMAC_MODULE }, Map});
from_map({JWS, Modules, Map=#{ <<"alg">> := << "PS", _/binary >> }}) ->
	from_map({JWS, Modules#{ alg => ?ALG_RSA_PSS_MODULE }, Map});
from_map({JWS, Modules, Map=#{ <<"alg">> := << "RS", _/binary >> }}) ->
	from_map({JWS, Modules#{ alg => ?ALG_RSA_PKCS1_V1_5_MODULE }, Map});
from_map({JWS, Modules, Map=#{ <<"alg">> := << "none" >> }}) ->
	from_map({JWS, Modules#{ alg => ?ALG_NONE_MODULE }, Map});
from_map({#jose_jws{ alg = undefined }, _Modules, _Map}) ->
	{error, {missing_required_keys, [<<"alg">>]}};
from_map({JWS, _Modules, Fields}) ->
	JWS#jose_jws{ fields = Fields }.

%%====================================================================
%% Encode API functions
%%====================================================================

to_binary(JWS=#jose_jws{}) ->
	{Modules, Map} = to_map(JWS),
	{Modules, jsx:encode(Map)};
to_binary(Other) ->
	to_binary(from(Other)).

to_file(File, JWS=#jose_jws{}) when is_binary(File) orelse is_list(File) ->
	{Modules, Binary} = to_binary(JWS),
	case file:write_file(File, Binary) of
		ok ->
			{Modules, File};
		WriteError ->
			WriteError
	end;
to_file(File, Other) when is_binary(File) orelse is_list(File) ->
	to_file(File, from(Other)).

to_map(JWS=#jose_jws{fields=Fields}) ->
	record_to_map(JWS, #{}, Fields);
to_map(Other) ->
	to_map(from(Other)).

%%====================================================================
%% API functions
%%====================================================================

compact({Modules, #{
		<<"payload">> := Payload,
		<<"protected">> := Protected,
		<<"signature">> := Signature}}) ->
	{Modules, <<
		Protected/binary, $.,
		Payload/binary, $.,
		Signature/binary
	>>};
compact(Map) when is_map(Map) ->
	compact({#{}, Map});
compact(BadArg) ->
	erlang:error({badarg, [BadArg]}).

expand({Modules, Binary}) when is_binary(Binary) ->
	case binary:split(Binary, <<".">>, [global]) of
		[Protected, Payload, Signature] ->
			{Modules, #{
				<<"payload">> => Payload,
				<<"protected">> => Protected,
				<<"signature">> => Signature
			}};
		_ ->
			erlang:error({badarg, [{Modules, Binary}]})
	end;
expand(Binary) when is_binary(Binary) ->
	expand({#{}, Binary}).

sign(Key, PlainText, JWS=#jose_jws{}) ->
	sign(Key, PlainText, #{}, JWS);
sign(Key, PlainText, Other) ->
	sign(Key, PlainText, from(Other)).

sign(Keys=[_ | _], PlainText, Header, JWS=#jose_jws{alg={ALGModule, ALG}})
		when is_binary(PlainText)
		andalso is_map(Header) ->
	{Modules, ProtectedBinary} = to_binary(JWS),
	Protected = base64url:encode(ProtectedBinary),
	Payload = base64url:encode(PlainText),
	Message = << Protected/binary, $., Payload/binary >>,
	Signatures = [begin
		{Key, base64url:encode(ALGModule:sign(Key, Message, ALG))}
	end || Key <- Keys],
	{Modules, #{
		<<"payload">> => Payload,
		<<"signatures">> => [begin
			signature_to_map(Protected, Header, Key, Signature)
		end || {Key, Signature} <- Signatures]
	}};
sign(Key, PlainText, Header, JWS=#jose_jws{alg={ALGModule, ALG}})
		when is_binary(PlainText)
		andalso is_map(Header) ->
	{Modules, ProtectedBinary} = to_binary(JWS),
	Protected = base64url:encode(ProtectedBinary),
	Payload = base64url:encode(PlainText),
	Message = << Protected/binary, $., Payload/binary >>,
	Signature = base64url:encode(ALGModule:sign(Key, Message, ALG)),
	{Modules, maps:put(<<"payload">>, Payload,
		signature_to_map(Protected, Header, Key, Signature))};
sign(Key, PlainText, Header, Other) ->
	sign(Key, PlainText, Header, from(Other)).

verify(Key, SignedMap) when is_map(SignedMap) ->
	verify(Key, {#{}, SignedMap});
verify(Key, SignedBinary) when is_binary(SignedBinary) ->
	verify(Key, expand(SignedBinary));
verify(Key, {Modules, SignedBinary}) when is_binary(SignedBinary) ->
	verify(Key, expand({Modules, SignedBinary}));
verify(Key, {Modules, #{
		<<"payload">> := Payload,
		<<"protected">> := Protected,
		<<"signature">> := EncodedSignature}}) ->
	JWS = #jose_jws{alg={ALGModule, ALG}} = from_binary({Modules, base64url:decode(Protected)}),
	Signature = base64url:decode(EncodedSignature),
	Message = << Protected/binary, $., Payload/binary >>,
	{ALGModule:verify(Key, Message, Signature, ALG), base64url:decode(Payload), JWS};
verify(Keys = [_ | _], {Modules, Signed=#{
		<<"payload">> := _Payload,
		<<"signatures">> := EncodedSignatures}})
		when is_list(EncodedSignatures) ->
	[begin
		{Key, verify(Key, {Modules, Signed})}
	end || Key <- Keys];
verify(Key, {Modules, #{
		<<"payload">> := Payload,
		<<"signatures">> := EncodedSignatures}})
		when is_list(EncodedSignatures) ->
	[begin
		verify(Key, {Modules, maps:put(<<"payload">>, Payload, EncodedSignature)})
	end || EncodedSignature <- EncodedSignatures].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
record_to_map(JWS=#jose_jws{alg={Module, ALG}}, Modules, Fields0) ->
	Fields1 = Module:to_map(ALG, Fields0),
	record_to_map(JWS#jose_jws{alg=undefined}, Modules#{ alg => Module }, Fields1);
record_to_map(_JWS, Modules, Fields) ->
	{Modules, Fields}.

%% @private
signature_to_map(Protected, Header, #jose_jwk{fields=Fields}, Signature) ->
	signature_to_map(Protected, Header, Fields, Signature);
signature_to_map(Protected, Header, #{ <<"kid">> := KID }, Signature) ->
	#{
		<<"protected">> => Protected,
		<<"header">> => maps:put(<<"kid">>, KID, Header),
		<<"signature">> => Signature
	};
signature_to_map(Protected, Header, _Fields, Signature) ->
	case maps:size(Header) of
		0 ->
			#{
				<<"protected">> => Protected,
				<<"signature">> => Signature
			};
		_ ->
			#{
				<<"protected">> => Protected,
				<<"header">> => Header,
				<<"signature">> => Signature
			}
	end.
