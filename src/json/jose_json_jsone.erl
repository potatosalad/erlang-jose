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
-module(jose_json_jsone).
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
            {app, jsone},
            jsone
        ]
    }.

%%%=============================================================================
%%% jose_json callbacks
%%%=============================================================================

-spec decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
decode(JSON) when is_binary(JSON) ->
    jsone:decode(JSON).

-spec encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().
encode(Term) ->
    jsone:encode(Term, [canonical_form]).
