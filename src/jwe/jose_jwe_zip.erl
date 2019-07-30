%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwe_zip).
-behaviour(jose_jwe).

-callback compress(Uncompressed, ZIP) -> Compressed
	when
		Uncompressed :: iodata(),
		ZIP          :: any(),
		Compressed   :: iodata().
-callback uncompress(Compressed, ZIP) -> Uncompressed
	when
		Compressed   :: iodata(),
		ZIP          :: any(),
		Uncompressed :: iodata().

%% jose_jwe callbacks
-export([from_map/1]).
-export([to_map/2]).
%% jose_jwe_zip callbacks
-export([compress/2]).
-export([uncompress/2]).
%% API
-export([zip_supported/0]).

%% Types
-type zip() :: zlib.

-export_type([zip/0]).

-define(DEF, zlib).

%%====================================================================
%% jose_jwe callbacks
%%====================================================================

from_map(Fields = #{ <<"zip">> := <<"DEF">> }) ->
	{?DEF, maps:remove(<<"zip">>, Fields)}.

to_map(?DEF, Fields) ->
	Fields#{ <<"zip">> => <<"DEF">> }.

%%====================================================================
%% jose_jwe_zip callbacks
%%====================================================================

compress(Uncompressed, zlib) ->
	Z = zlib:open(),
	ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
	Compressed = zlib:deflate(Z, Uncompressed, finish),
	ok = zlib:deflateEnd(Z),
	ok = zlib:close(Z),
	iolist_to_binary(Compressed).

uncompress(Compressed, zlib) ->
	Z = zlib:open(),
	ok = zlib:inflateInit(Z, -15),
	Uncompressed = zlib:inflate(Z, Compressed),
	ok = zlib:inflateEnd(Z),
	ok = zlib:close(Z),
	iolist_to_binary(Uncompressed).

%%====================================================================
%% API functions
%%====================================================================

zip_supported() ->
	[zlib].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
