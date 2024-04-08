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
-module(jose_pbkdf2_hmac_crypto).

-behaviour(jose_provider).
-behaviour(jose_pbkdf2_hmac).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_pbkdf2_hmac callbacks
-export([
    pbkdf2_hmac_sha256/4,
    pbkdf2_hmac_sha384/4,
    pbkdf2_hmac_sha512/4
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_pbkdf2_hmac,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%%=============================================================================
%%% jose_pbkdf2_hmac callbacks
%%%=============================================================================

-spec pbkdf2_hmac_sha256(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
pbkdf2_hmac_sha256(Password, Salt, Iterations, KeyLen) when
    is_binary(Password) andalso
        is_binary(Salt) andalso
        (is_integer(Iterations) andalso Iterations >= 1) andalso
        (is_integer(KeyLen) andalso KeyLen >= 1)
->
    crypto:pbkdf2_hmac(sha256, Password, Salt, Iterations, KeyLen).

-spec pbkdf2_hmac_sha384(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
pbkdf2_hmac_sha384(Password, Salt, Iterations, KeyLen) when
    is_binary(Password) andalso
        is_binary(Salt) andalso
        (is_integer(Iterations) andalso Iterations >= 1) andalso
        (is_integer(KeyLen) andalso KeyLen >= 1)
->
    crypto:pbkdf2_hmac(sha384, Password, Salt, Iterations, KeyLen).

-spec pbkdf2_hmac_sha512(Password, Salt, Iterations, KeyLen) -> Key when
    Password :: jose_pbkdf2_hmac:password(),
    Salt :: jose_pbkdf2_hmac:salt(),
    Iterations :: jose_pbkdf2_hmac:iterations(),
    KeyLen :: jose_pbkdf2_hmac:key_len(),
    Key :: jose_pbkdf2_hmac:key().
pbkdf2_hmac_sha512(Password, Salt, Iterations, KeyLen) when
    is_binary(Password) andalso
        is_binary(Salt) andalso
        (is_integer(Iterations) andalso Iterations >= 1) andalso
        (is_integer(KeyLen) andalso KeyLen >= 1)
->
    crypto:pbkdf2_hmac(sha512, Password, Salt, Iterations, KeyLen).
