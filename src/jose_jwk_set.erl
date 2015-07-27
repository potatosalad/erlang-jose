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
-module(jose_jwk_set).

-include("jose_jwk.hrl").

%% API
-export([from_json/1]).
-export([from_json_file/1]).
-export([to_json/1]).
-export([to_json_file/2]).

%%====================================================================
%% API functions
%%====================================================================

from_json(JSON = #{ <<"keys">> := Keys }) ->
	#jose_jwk_set{
		keys = [jose_jwk:from_json(Key) || Key <- Keys],
		fields = maps:remove(<<"keys">>, JSON)
	}.

from_json_file(JSONFile) ->
	case file:read_file(JSONFile) of
		{ok, JSONData} ->
			from_json(jsx:decode(JSONData, [return_maps]));
		ReadError ->
			erlang:error({badarg, ReadError})
	end.

to_json(#jose_jwk_set{keys=Keys, fields=Fields}) ->
	Fields#{
		<<"keys">> => [begin
			{_, JSONKey} = jose_jwk:to_json(Key),
			JSONKey
		end || Key <- Keys]
	}.

to_json_file(JSONFile, JWK=#jose_jwk{}) ->
	{_, JSON} = to_json(JWK),
	JSONData = jsx:encode(JSON),
	file:write_file(JSONFile, JSONData).
