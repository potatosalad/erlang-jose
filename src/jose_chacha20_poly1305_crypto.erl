%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2019, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Aug 2016 by Andrew Bennett <potatosaladx@gmail.com>
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
	%% NOTE: As of OTP 22, crypto does not seem to validate the CipherTag :-(
	MacData = <<
		AAD/binary,
		(jose_jwa_chacha20_poly1305:pad16(AAD))/binary,
		CipherText/binary,
		(jose_jwa_chacha20_poly1305:pad16(CipherText))/binary,
		(byte_size(AAD)):64/unsigned-little-integer-unit:1,
		(byte_size(CipherText)):64/unsigned-little-integer-unit:1
	>>,
	case verify(CipherTag, MacData, CEK, IV) of
		true ->
			crypto:crypto_one_time_aead(chacha20_poly1305, CEK, IV, CipherText, AAD, CipherTag, false);
		false ->
			error
	end.

encrypt(PlainText, AAD, IV, CEK) ->
	crypto:crypto_one_time_aead(chacha20_poly1305, CEK, IV, PlainText, AAD, true).

authenticate(Message, Key, Nonce) ->
	OTK = jose_jwa_chacha20_poly1305:poly1305_key_gen(Key, Nonce),
	jose_crypto_compat:mac(poly1305, OTK, Message).

verify(MAC, Message, Key, Nonce) ->
	Challenge = jose_jwa_chacha20_poly1305:authenticate(Message, Key, Nonce),
	jose_jwa:constant_time_compare(MAC, Challenge).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
