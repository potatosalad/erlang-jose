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
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_sha1).

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type sha1_output() :: <<_:160>>.

-export_type([
    input/0,
    sha1_output/0
]).

-callback sha1(Input) -> Output when
    Input :: jose_sha1:input(), Output :: jose_sha1:sha1_output().

-optional_callbacks([
    sha1/1
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_sha1 callbacks
-export([
    sha1/1
]).

%% Macros
-define(TV_Input(), <<"abc">>).
-define(TV_SHA1(), ?b16d("a9993e364706816aba3e25717850c26c9cd0d89d")).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{sha1, 1}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, sha1, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA1(),
    ?expect(Output, Module, sha1, [Input]).

%%%=============================================================================
%%% jose_sha1 callbacks
%%%=============================================================================

-spec sha1(Input) -> Output when
    Input :: jose_sha1:input(), Output :: jose_sha1:sha1_output().
sha1(Input) ->
    ?resolve([Input]).
