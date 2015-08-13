%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_sup).
-behaviour(supervisor).

-include_lib("public_key/include/public_key.hrl").

-define(SERVER, ?MODULE).

%% API
-export([start_link/0]).
-export([is_cipher_supported/2]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type), {I, {I, start_link, []}, permanent, 5000, Type, [I]}).

-define(MAYBE_FALLBACK(N),
	application:get_env(jose, N, application:get_env(jose, crypto_fallback, false))).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
	supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%% @private
init([]) ->
	jose_jwa = ets:new(jose_jwa, [
		named_table,
		public,
		ordered_set,
		{read_concurrency, true}
	]),
	true = ets:insert(jose_jwa, determine_ec_key_mode()),
	true = ets:insert(jose_jwa, determine_supported_ciphers()),
	true = ets:insert(jose_jwa, determine_supported_rsa_padding()),
	true = ets:insert(jose_jwa, determine_supported_signers()),
	ChildSpecs = [],
	Restart = {one_for_one, 10, 10},
	{ok, {Restart, ChildSpecs}}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
determine_ec_key_mode() ->
	ECPEMEntry = {
		'ECPrivateKey',
		<<
			48,119,2,1,1,4,32,104,152,88,12,19,82,251,156,171,31,222,207,
			0,76,115,88,210,229,36,106,137,192,81,153,154,254,226,38,247,
			70,226,157,160,10,6,8,42,134,72,206,61,3,1,7,161,68,3,66,0,4,
			46,75,29,46,150,77,222,40,220,159,244,193,125,18,190,254,216,
			38,191,11,52,115,159,213,230,77,27,131,94,17,46,21,186,71,62,
			36,225,0,90,21,186,235,132,152,229,13,189,196,121,64,84,64,
			229,173,12,24,23,127,175,67,247,29,139,91
		>>,
		not_encrypted
	},
	case public_key:pem_entry_decode(ECPEMEntry) of
		#'ECPrivateKey'{ privateKey = PrivateKey, publicKey = PublicKey } when is_list(PrivateKey) andalso is_tuple(PublicKey) ->
			[{ec_key_mode, list}];
		#'ECPrivateKey'{ privateKey = PrivateKey, publicKey = PublicKey } when is_binary(PrivateKey) andalso is_binary(PublicKey) ->
			[{ec_key_mode, binary}]
	end.

%% @private
determine_supported_ciphers() ->
	determine_supported_ciphers(?MAYBE_FALLBACK(crypto_aes_fallback)).

%% @private
determine_supported_ciphers(false) ->
	[begin
		case Module of
			crypto ->
				{{cipher, Cipher}, {Module, Type}};
			_ ->
				{{cipher, Cipher}, {jose_jwa_unsupported, Type}}
		end
	end || {{cipher, Cipher}, {Module, Type}} <- determine_supported_ciphers(true)];
determine_supported_ciphers(true) ->
	SpecificBlockCiphers = [
		aes_cbc128,
		aes_cbc192,
		aes_cbc256
	],
	BlockCiphers = [
		aes_ecb,
		aes_gcm
	],
	BlockCipherBits = [
		128,
		192,
		256
	],
	NativeCiphers = proplists:get_value(ciphers, crypto:supports()),
	PureSpecificBlockCiphers = SpecificBlockCiphers -- NativeCiphers,
	NativeSpecificBlockCiphers = SpecificBlockCiphers -- PureSpecificBlockCiphers,
	PureBlockCiphers = BlockCiphers -- NativeCiphers,
	NativeBlockCiphers = BlockCiphers -- PureBlockCiphers,
	C0 = [begin
		"aes_cbc" ++ BitsList = atom_to_list(Cipher),
		Bits = list_to_integer(BitsList),
		[
			{{cipher, Cipher}, {crypto, Cipher}},
			{{cipher, {aes_cbc, Bits}}, {crypto, Cipher}}
		]
	end || Cipher <- NativeSpecificBlockCiphers],
	C1 = [begin
		"aes_cbc" ++ BitsList = atom_to_list(Cipher),
		Bits = list_to_integer(BitsList),
		[
			{{cipher, Cipher}, {jose_jwa_aes, {aes_cbc, Bits}}},
			{{cipher, {aes_cbc, Bits}}, {jose_jwa_aes, {aes_cbc, Bits}}}
		]
	end || Cipher <- PureSpecificBlockCiphers],
	C2 = [begin
		CipherName = list_to_atom(atom_to_list(Cipher) ++ integer_to_list(Bits)),
		case is_cipher_supported(Bits, Cipher) of
			false ->
				[
					{{cipher, CipherName}, {jose_jwa_aes, {Cipher, Bits}}},
					{{cipher, {Cipher, Bits}}, {jose_jwa_aes, {Cipher, Bits}}}
				];
			true ->
				[
					{{cipher, CipherName}, {crypto, Cipher}},
					{{cipher, {Cipher, Bits}}, {crypto, Cipher}}
				]
		end
	end || Cipher <- NativeBlockCiphers, Bits <- BlockCipherBits],
	C3 = [begin
		CipherName = list_to_atom(atom_to_list(Cipher) ++ integer_to_list(Bits)),
		[
			{{cipher, CipherName}, {jose_jwa_aes, {Cipher, Bits}}},
			{{cipher, {Cipher, Bits}}, {jose_jwa_aes, {Cipher, Bits}}}
		]
	end || Cipher <- PureBlockCiphers, Bits <- BlockCipherBits],
	lists:flatten([C0, C1, C2, C3]).

%% @private
determine_supported_rsa_padding() ->
	[begin
		{{rsa_padding, RSAPadding}}
	end || RSAPadding <- determine_supported_rsa_padding(?MAYBE_FALLBACK(crypto_rsa_fallback))].

%% @private
determine_supported_rsa_padding(false) ->
	[rsa_pkcs1_padding, rsa_pkcs1_oaep_padding];
determine_supported_rsa_padding(true) ->
	[rsa_pkcs1_padding, rsa_pkcs1_oaep_padding, rsa_pkcs1_oaep256_padding].

%% @private
determine_supported_signers() ->
	[begin
		{{signer, Signer}}
	end || Signer <- determine_supported_signers(?MAYBE_FALLBACK(crypto_rsa_fallback))].

%% @private
determine_supported_signers(false) ->
	[ecdsa, hmac, none, rsa_pkcs1_v1_5];
determine_supported_signers(true) ->
	[ecdsa, hmac, none, rsa_pkcs1_v1_5, rsa_pss].

%% @private
is_cipher_supported(Bits, aes_ecb) ->
	Key = << 0:Bits >>,
	PlainText = jose_jwa_pkcs7:pad(<<>>),
	try crypto:block_encrypt(aes_ecb, Key, PlainText) of
		CipherText when is_binary(CipherText) ->
			try crypto:block_decrypt(aes_ecb, Key, CipherText) of
				PlainText ->
					true;
				_ ->
					false
			catch
				_:_ ->
					false
			end;
		_ ->
			false
	catch
		_:_ ->
			false
	end;
is_cipher_supported(Bits, aes_gcm) ->
	Key = << 0:Bits >>,
	IV = << 0:96 >>,
	AAD = <<>>,
	PlainText = jose_jwa_pkcs7:pad(<<>>),
	try crypto:block_encrypt(aes_gcm, Key, IV, {AAD, PlainText}) of
		{CipherText, CipherTag} when is_binary(CipherText) andalso is_binary(CipherTag) ->
			try crypto:block_decrypt(aes_gcm, Key, IV, {AAD, CipherText, CipherTag}) of
				PlainText ->
					true;
				_ ->
					false
			catch
				_:_ ->
					false
			end;
		_ ->
			false
	catch
		_:_ ->
			false
	end.
