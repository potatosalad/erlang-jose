%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Aug 2016 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_chacha20_poly1305_crypto).

-behaviour(jose_chacha20_poly1305).

%% jose_chacha20_poly1305 callbacks
-export([decrypt/5]).
-export([encrypt/4]).
-export([authenticate/3]).
-export([verify/4]).

%%====================================================================
%% jose_chacha20_poly1305 callbacks
%%====================================================================

decrypt(CipherText, CipherTag, AAD, IV, CEK) ->
	crypto:block_decrypt(chacha20_poly1305, CEK, IV, {AAD, CipherText, CipherTag}).

encrypt(PlainText, AAD, IV, CEK) ->
	crypto:block_encrypt(chacha20_poly1305, CEK, IV, {AAD, PlainText}).

authenticate(Message, Key, Nonce) ->
	jose_jwa_chacha20_poly1305:authenticate(Message, Key, Nonce).

verify(MAC, Message, Key, Nonce) ->
	jose_jwa_chacha20_poly1305:verify(MAC, Message, Key, Nonce).
