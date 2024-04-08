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
%%% Created :  14 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_json).

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type json() :: binary().

-export_type([
    json/0
]).

%% Callbacks
-callback decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
-callback encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_json callbacks
-export([
    decode/1,
    encode/1
]).

%% Macros
-define(TV_JSON(), <<"{\"a\":1,\"b\":2,\"c\":{\"d\":3,\"e\":4}}">>).
-define(TV_Term(), #{
    <<"a">> => 1,
    <<"b">> => 2,
    <<"c">> => #{
        <<"d">> => 3,
        <<"e">> => 4
    }
}).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [
            [
                {decode, 1},
                {encode, 1}
            ]
        ],
        callbacks => [
            {{decode, 1}, []},
            {{encode, 1}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, decode, 1) ->
    JSON = ?TV_JSON(),
    Term = ?TV_Term(),
    ?expect(Term, Module, decode, [JSON]);
support_check(Module, encode, 1) ->
    Term = ?TV_Term(),
    JSON = ?TV_JSON(),
    ?expect(JSON, Module, encode, [Term]).

%%%=============================================================================
%%% jose_json callbacks
%%%=============================================================================

-spec decode(JSON) -> Term when JSON :: jose_json:json(), Term :: term().
decode(JSON) when is_binary(JSON) ->
    ?resolve([JSON]).

-spec encode(Term) -> JSON when Term :: term(), JSON :: jose_json:json().
encode(Term) ->
    ?resolve([Term]).
