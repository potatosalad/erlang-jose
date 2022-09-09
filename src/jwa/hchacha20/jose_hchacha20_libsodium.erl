%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_hchacha20_libsodium).

-behaviour(jose_provider).
-behaviour(jose_hchacha20).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_hchacha20 callbacks
-export([
	hchacha20_subkey/2
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_hchacha20,
		priority => normal,
		requirements => [
			{app, libsodium},
			libsodium_crypto_core_hchacha20
		]
	}.

%%====================================================================
%% jose_chacha20 callbacks
%%====================================================================

-spec hchacha20_subkey(Nonce, Key) -> Subkey when
	Nonce :: jose_hchacha20:hchacha20_nonce(),
	Key :: jose_hchacha20:hchacha20_key(),
	Subkey :: jose_hchacha20:hchacha20_subkey().
hchacha20_subkey(Nonce, Key)
		when bit_size(Nonce) =:= 128
		andalso bit_size(Key) =:= 256 ->
    libsodium_crypto_core_hchacha20:crypto_core_hchacha20(Nonce, Key, <<"expand 32-byte k">>).

%%%-------------------------------------------------------------------
%%% Internal HChaCha20 functions
%%%-------------------------------------------------------------------
