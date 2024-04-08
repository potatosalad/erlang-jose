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
%%% Created :  02 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_sha2_libdecaf).

-behaviour(jose_provider).
-behaviour(jose_sha2).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_sha2 callbacks
-export([
    sha512/1
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_sha2,
        priority => normal,
        requirements => [
            {app, libdecaf},
            libdecaf_sha2
        ]
    }.

%%%=============================================================================
%%% jose_sha2 callbacks
%%%=============================================================================

-spec sha512(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha512_output().
sha512(Input) ->
    libdecaf_sha2:hash(sha2_512, Input).
