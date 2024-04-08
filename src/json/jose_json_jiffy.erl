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
%%% Created :  20 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_json_jiffy).
-behaviour(jose_provider).
-behaviour(jose_json).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_json callbacks
-export([
    decode/1,
    encode/1
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_json,
        priority => normal,
        requirements => [
            {app, jiffy},
            jiffy
        ]
    }.

%%%=============================================================================
%%% jose_json callbacks
%%%=============================================================================

-spec decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
decode(JSON) when is_binary(JSON) ->
    jiffy:decode(JSON, [return_maps]).

-spec encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().
encode(Map) when is_map(Map) ->
    ensure_binary(jiffy:encode(sort(Map)));
encode(List) when is_list(List) ->
    ensure_binary(jiffy:encode(sort(List)));
encode(Term) ->
    ensure_binary(jiffy:encode(Term)).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
sort(Map) when is_map(Map) ->
    {[{sort(Key), sort(Val)} || {Key, Val} <- maps:to_list(Map)]};
sort(List) when is_list(List) ->
    [sort(Term) || Term <- List];
sort(Term) ->
    Term.

%% @private
%% NOTE: jiffy may return an iolist instead of a binary when encoding
%%       big objects.
ensure_binary(List) when is_list(List) ->
    iolist_to_binary(List);
ensure_binary(Binary) ->
    Binary.
