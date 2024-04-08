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
-module(jose_hmac_crypto).

-behaviour(jose_provider).
-behaviour(jose_hmac).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_hmac callbacks
-export([
    hmac_sha1/2,
    hmac_sha224/2,
    hmac_sha256/2,
    hmac_sha384/2,
    hmac_sha512/2
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_hmac,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%%=============================================================================
%%% jose_hmac callbacks
%%%=============================================================================

-spec hmac_sha1(Key, Input) -> Output when
    Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha1_output().
hmac_sha1(Key, Input) ->
    crypto:mac(hmac, sha, Key, Input).

-spec hmac_sha224(Key, Input) -> Output when
    Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha224_output().
hmac_sha224(Key, Input) ->
    crypto:mac(hmac, sha224, Key, Input).

-spec hmac_sha256(Key, Input) -> Output when
    Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha256_output().
hmac_sha256(Key, Input) ->
    crypto:mac(hmac, sha256, Key, Input).

-spec hmac_sha384(Key, Input) -> Output when
    Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha384_output().
hmac_sha384(Key, Input) ->
    crypto:mac(hmac, sha384, Key, Input).

-spec hmac_sha512(Key, Input) -> Output when
    Key :: jose_hmac:hmac_key(), Input :: jose_hmac:input(), Output :: jose_hmac:hmac_sha512_output().
hmac_sha512(Key, Input) ->
    crypto:mac(hmac, sha512, Key, Input).
