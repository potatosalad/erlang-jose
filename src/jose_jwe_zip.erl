%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwe_zip).

%% jose_jwe callbacks
-export([from_json/1]).
-export([to_json/2]).

%% jose_jwe_zip callbacks
-export([compress/2]).
-export([uncompress/2]).

%% API
-export([zip_supported/0]).

%% Types
-record(jose_jwe_zip, {
	zip = undefined :: undefined | zlib
}).

-type zip() :: #jose_jwe_zip{}.

-export_type([zip/0]).

%%====================================================================
%% jose_jwe callbacks
%%====================================================================

from_json(Fields = #{ <<"zip">> := <<"DEF">> }) ->
	{#jose_jwe_zip{ zip = zlib }, maps:remove(<<"zip">>, Fields)}.

to_json(#jose_jwe_zip{ zip = zlib }, Fields) ->
	Fields#{ <<"zip">> => <<"DEF">> }.

%%====================================================================
%% jose_jwe_zip callbacks
%%====================================================================

compress(Uncompressed, #jose_jwe_zip{zip=ZIP}) ->
	ZIP:compress(Uncompressed).

uncompress(Compressed, #jose_jwe_zip{zip=ZIP}) ->
	ZIP:uncompress(Compressed).

%%====================================================================
%% API functions
%%====================================================================

zip_supported() ->
	[zlib].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
