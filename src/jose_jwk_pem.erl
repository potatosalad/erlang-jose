%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  24 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_pem).

%% API
-export([from_binary/1]).
-export([from_binary/2]).
-export([to_binary/3]).

%%====================================================================
%% API functions
%%====================================================================

from_binary(PEMBinary) when is_binary(PEMBinary) ->
	case public_key:pem_decode(PEMBinary) of
		[PEMEntry] ->
			jose_jwk_kty:from_key(public_key:pem_entry_decode(PEMEntry));
		PEMDecodeError ->
			PEMDecodeError
	end.

from_binary(Password, EncryptedPEMBinary) when is_binary(EncryptedPEMBinary) ->
	case public_key:pem_decode(EncryptedPEMBinary) of
		[EncryptedPEMEntry] ->
			PasswordString = unicode:characters_to_list(Password),
			jose_jwk_kty:from_key(public_key:pem_entry_decode(EncryptedPEMEntry, PasswordString));
		PEMDecodeError ->
			PEMDecodeError
	end.

to_binary(Password, KeyType, Key) ->
	CipherInfo = {"DES-EDE3-CBC", crypto:strong_rand_bytes(8)},
	PasswordString = binary_to_list(iolist_to_binary(Password)),
	PEMEntry = public_key:pem_entry_encode(KeyType, Key, {CipherInfo, PasswordString}),
	public_key:pem_encode([PEMEntry]).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
