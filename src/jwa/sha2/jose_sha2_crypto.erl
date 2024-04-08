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
-module(jose_sha2_crypto).

-behaviour(jose_provider).
-behaviour(jose_sha2).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_sha2 callbacks
-export([
    sha224/1,
    sha256/1,
    sha384/1,
    sha512/1
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_sha2,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%%=============================================================================
%%% jose_sha2 callbacks
%%%=============================================================================

-spec sha224(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha224_output().
sha224(Input) ->
    crypto:hash(sha224, Input).

-spec sha256(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha256_output().
sha256(Input) ->
    crypto:hash(sha256, Input).

-spec sha384(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha384_output().
sha384(Input) ->
    crypto:hash(sha384, Input).

-spec sha512(Input) -> Output when
    Input :: jose_sha2:input(), Output :: jose_sha2:sha512_output().
sha512(Input) ->
    crypto:hash(sha512, Input).
