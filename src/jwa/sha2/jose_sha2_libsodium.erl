%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  02 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_sha2_libsodium).

-behaviour(jose_provider).
-behaviour(jose_sha2).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_sha2 callbacks
-export([
	sha256/1,
	sha512/1
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_sha2,
        priority => normal,
        requirements => [
            {app, libsodium},
			libsodium_crypto_hash_sha256,
			libsodium_crypto_hash_sha512
        ]
    }.

%%====================================================================
%% jose_sha2 callbacks
%%====================================================================

-spec sha256(Input) -> Output when
	Input :: jose_sha2:input(), Output :: jose_sha2:sha256_output().
sha256(Input) ->
	libsodium_crypto_hash_sha256:crypto_hash_sha256(Input).

-spec sha512(Input) -> Output when
	Input :: jose_sha2:input(), Output :: jose_sha2:sha512_output().
sha512(Input) ->
	libsodium_crypto_hash_sha512:crypto_hash_sha512(Input).
