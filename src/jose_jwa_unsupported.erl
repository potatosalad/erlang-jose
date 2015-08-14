%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  10 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_unsupported).
-behaviour(jose_block_encryptor).

%% jose_block_encryptor callbacks
-export([block_decrypt/3]).
-export([block_decrypt/4]).
-export([block_encrypt/3]).
-export([block_encrypt/4]).

%%====================================================================
%% jose_block_encryptor callbacks
%%====================================================================

block_decrypt(Cipher, _Key, _CipherText) ->
	erlang:error({cipher_unsupported, [Cipher]}).

block_decrypt(Cipher, _Key, _IV, _CipherText) ->
	erlang:error({cipher_unsupported, [Cipher]}).

block_encrypt(Cipher, _Key, _PlainText) ->
	erlang:error({cipher_unsupported, [Cipher]}).

block_encrypt(Cipher, _Key, _IV, _PlainText) ->
	erlang:error({cipher_unsupported, [Cipher]}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
