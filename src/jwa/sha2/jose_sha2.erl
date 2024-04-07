%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_sha2).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type sha224_output() :: <<_:224>>.
-type sha256_output() :: <<_:256>>.
-type sha384_output() :: <<_:384>>.
-type sha512_output() :: <<_:512>>.

-export_type([
    input/0,
    sha224_output/0,
    sha256_output/0,
    sha384_output/0,
    sha512_output/0
]).

-callback sha224(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha224_output().
-callback sha256(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha256_output().
-callback sha384(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha384_output().
-callback sha512(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha512_output().

-optional_callbacks([
    sha224/1,
    sha256/1,
    sha384/1,
    sha512/1
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_sha2 callbacks
-export([
    sha224/1,
    sha256/1,
    sha384/1,
    sha512/1
]).

%% Macros
-define(TV_Input(), <<"abc">>).
-define(TV_SHA224(), ?b16d("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")).
-define(TV_SHA256(), ?b16d("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")).
-define(TV_SHA384(),
    ?b16d("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
).
-define(TV_SHA512(),
    ?b16d(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{sha224, 1}, []},
            {{sha256, 1}, []},
            {{sha384, 1}, []},
            {{sha512, 1}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, sha224, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA224(),
    ?expect(Output, Module, sha224, [Input]);
support_check(Module, sha256, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA256(),
    ?expect(Output, Module, sha256, [Input]);
support_check(Module, sha384, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA384(),
    ?expect(Output, Module, sha384, [Input]);
support_check(Module, sha512, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA512(),
    ?expect(Output, Module, sha512, [Input]).

%%====================================================================
%% jose_sha2 callbacks
%%====================================================================

-spec sha224(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha224_output().
sha224(Input) ->
    ?resolve([Input]).

-spec sha256(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha256_output().
sha256(Input) ->
    ?resolve([Input]).

-spec sha384(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha384_output().
sha384(Input) ->
    ?resolve([Input]).

-spec sha512(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha512_output().
sha512(Input) ->
    ?resolve([Input]).
