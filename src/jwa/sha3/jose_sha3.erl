%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  11 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_sha3).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type sha3_224_output() :: <<_:224>>.
-type sha3_256_output() :: <<_:256>>.
-type sha3_384_output() :: <<_:384>>.
-type sha3_512_output() :: <<_:512>>.
-type shake128_output() :: binary().
-type shake128_output_size() :: non_neg_integer().
-type shake256_output() :: binary().
-type shake256_output_size() :: non_neg_integer().

-export_type([
    input/0,
    sha3_224_output/0,
    sha3_256_output/0,
    sha3_384_output/0,
    sha3_512_output/0,
    shake128_output/0,
    shake128_output_size/0,
    shake256_output/0,
    shake256_output_size/0
]).

%% Callbacks
-callback sha3_224(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_224_output().
-callback sha3_256(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_256_output().
-callback sha3_384(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_384_output().
-callback sha3_512(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_512_output().
-callback shake128(Input, OutputSize) -> Output when
    Input :: jose_sha3:input(), OutputSize :: jose_sha3:shake128_output_size(), Output :: jose_sha3:shake128_output().
-callback shake256(Input, OutputSize) -> Output when
    Input :: jose_sha3:input(), OutputSize :: jose_sha3:shake256_output_size(), Output :: jose_sha3:shake256_output().

-optional_callbacks([
    sha3_224/1,
    sha3_256/1,
    sha3_384/1,
    sha3_512/1,
    shake128/2,
    shake256/2
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_sha3 callbacks
-export([
    sha3_224/1,
    sha3_256/1,
    sha3_384/1,
    sha3_512/1,
    shake128/2,
    shake256/2
]).

%% Macros
-define(TV_Input(), <<"abc">>).
-define(TV_SHA3_224(), ?b16d("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")).
-define(TV_SHA3_256(), ?b16d("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")).
-define(TV_SHA3_384(),
    ?b16d("ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25")
).
-define(TV_SHA3_512(),
    ?b16d(
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    )
).
-define(TV_SHAKE128(), ?b16d("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")).
-define(TV_SHAKE256(),
    ?b16d(
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
    )
).

%%%=============================================================================
%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{sha3_224, 1}, []},
            {{sha3_256, 1}, []},
            {{sha3_384, 1}, []},
            {{sha3_512, 1}, []},
            {{shake128, 2}, []},
            {{shake256, 2}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, sha3_224, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA3_224(),
    ?expect(Output, Module, sha3_224, [Input]);
support_check(Module, sha3_256, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA3_256(),
    ?expect(Output, Module, sha3_256, [Input]);
support_check(Module, sha3_384, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA3_384(),
    ?expect(Output, Module, sha3_384, [Input]);
support_check(Module, sha3_512, 1) ->
    Input = ?TV_Input(),
    Output = ?TV_SHA3_512(),
    ?expect(Output, Module, sha3_512, [Input]);
support_check(Module, shake128, 2) ->
    Input = ?TV_Input(),
    Output = ?TV_SHAKE128(),
    OutputSize = byte_size(Output),
    ?expect(Output, Module, shake128, [Input, OutputSize]);
support_check(Module, shake256, 2) ->
    Input = ?TV_Input(),
    Output = ?TV_SHAKE256(),
    OutputSize = byte_size(Output),
    ?expect(Output, Module, shake256, [Input, OutputSize]).

%%%=============================================================================
%% jose_sha3 callbacks
%%%=============================================================================

-spec sha3_224(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_224_output().
sha3_224(Input) ->
    ?resolve([Input]).

-spec sha3_256(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_256_output().
sha3_256(Input) ->
    ?resolve([Input]).

-spec sha3_384(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_384_output().
sha3_384(Input) ->
    ?resolve([Input]).

-spec sha3_512(Input) -> Output when
    Input :: jose_sha3:input(), Output :: jose_sha3:sha3_512_output().
sha3_512(Input) ->
    ?resolve([Input]).

-spec shake128(Input, OutputSize) -> Output when
    Input :: jose_sha3:input(), OutputSize :: jose_sha3:shake128_output_size(), Output :: jose_sha3:shake128_output().
shake128(Input, OutputSize) ->
    ?resolve([Input, OutputSize]).

-spec shake256(Input, OutputSize) -> Output when
    Input :: jose_sha3:input(), OutputSize :: jose_sha3:shake256_output_size(), Output :: jose_sha3:shake256_output().
shake256(Input, OutputSize) ->
    ?resolve([Input, OutputSize]).
