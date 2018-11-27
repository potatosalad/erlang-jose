%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2016, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  31 May 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_chacha20_poly1305).

-behaviour(jose_block_encryptor).

-type digest() :: << _:16 >>.
-type key()    :: << _:32 >>.
-type nonce()  :: << _:12 >>.

-callback decrypt(CipherText, CipherTag, AAD, IV, Key) -> PlainText | error
	when
		CipherText :: binary(),
		CipherTag  :: digest(),
		AAD        :: binary(),
		IV         :: nonce(),
		Key        :: key(),
		PlainText  :: binary().
-callback encrypt(PlainText, AAD, IV, Key) -> CipherText
	when
		PlainText  :: binary(),
		AAD        :: binary(),
		IV         :: nonce(),
		Key        :: key(),
		CipherText :: binary().
-callback authenticate(Message, Key, Nonce) -> MAC
	when
		Message :: binary(),
		Key     :: key(),
		Nonce   :: nonce(),
		MAC     :: digest().
-callback verify(MAC, Message, Key, Nonce) -> boolean()
	when
		MAC     :: digest(),
		Message :: binary(),
		Key     :: key(),
		Nonce   :: nonce().

%% jose_block_encryptor callbacks
-export([block_decrypt/4]).
-export([block_encrypt/4]).
-export([authenticate/3]).
-export([verify/4]).

%% Macros
-define(JOSE_CHACHA20_POLY1305, (jose:chacha20_poly1305_module())).

%%====================================================================
%% jose_block_encryptor callbacks
%%====================================================================

block_decrypt({chacha20_poly1305, 256}, Key, IV, {AAD, CipherText, CipherTag}) ->
	?JOSE_CHACHA20_POLY1305:decrypt(CipherText, CipherTag, AAD, IV, Key).

block_encrypt({chacha20_poly1305, 256}, Key, IV, {AAD, PlainText}) ->
	?JOSE_CHACHA20_POLY1305:encrypt(PlainText, AAD, IV, Key).

authenticate(Message, Key, Nonce) ->
	?JOSE_CHACHA20_POLY1305:authenticate(Message, Key, Nonce).

verify(MAC, Message, Key, Nonce) ->
	?JOSE_CHACHA20_POLY1305:verify(MAC, Message, Key, Nonce).
