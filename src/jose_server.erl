%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  13 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_server).
-behaviour(gen_server).

-include_lib("public_key/include/public_key.hrl").

-define(SERVER, ?MODULE).

%% API
-export([start_link/0]).
-export([config_change/0]).
-export([json_module/1]).

%% gen_server callbacks
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-define(CRYPTO_FALLBACK, application:get_env(jose, crypto_fallback, false)).

-define(TAB, jose_jwa).

-define(POISON_MAP, #{
	<<"a">> => 1,
	<<"b">> => 2,
	<<"c">> => #{
		<<"d">> => 3,
		<<"e">> => 4
	}
}).
-define(POISON_BIN, <<"{\"a\":1,\"b\":2,\"c\":{\"d\":3,\"e\":4}}">>).

%% Types
-record(state, {}).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
	gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

config_change() ->
	gen_server:call(?SERVER, config_change).

json_module(JSONModule) when is_atom(JSONModule) ->
	gen_server:call(?SERVER, {json_module, JSONModule}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
	?TAB = ets:new(?TAB, [
		named_table,
		public,
		ordered_set,
		{read_concurrency, true}
	]),
	ok = support_check(),
	{ok, #state{}}.

%% @private
handle_call(config_change, _From, State) ->
	{reply, support_check(), State};
handle_call({json_module, M}, _From, State) ->
	JSONModule = determine_json_module(M),
	true = ets:insert(?TAB, {json_module, JSONModule}),
	{reply, ok, State};
handle_call(_Request, _From, State) ->
	{reply, ignore, State}.

%% @private
handle_cast(_Request, State) ->
	{noreply, State}.

%% @private
handle_info(_Info, State) ->
	{noreply, State}.

%% @private
terminate(_Reason, _State) ->
	ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
support_check() ->
	Entries = lists:flatten([
		determine_ec_key_mode(),
		determine_json_module(),
		determine_supported_ciphers(),
		determine_supported_rsa_padding(),
		determine_supported_signers()
	]),
	true = ets:delete_all_objects(?TAB),
	true = ets:insert(?TAB, Entries),
	ok.

%%%-------------------------------------------------------------------
%%% Internal determine functions
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
determine_json_module() ->
	JSONModule = case ets:lookup(?TAB, json_module) of
		[{json_module, M}] when is_atom(M) ->
			M;
		[] ->
			case application:get_env(jose, json_module, undefined) of
				undefined ->
					case code:ensure_loaded(elixir) of
						{module, elixir} ->
							case code:ensure_loaded('Elixir.Poison') of
								{module, 'Elixir.Poison'} ->
									_ = application:ensure_all_started(poison),
									determine_json_module('Elixir.Poison');
								_ ->
									case code:ensure_loaded(jsx) of
										{module, jsx} ->
											_ = application:ensure_all_started(jsx),
											determine_json_module(jsx);
										_ ->
											jose_json_unsupported
									end
							end;
						_ ->
							case code:ensure_loaded(jsx) of
								{module, jsx} ->
									_ = application:ensure_all_started(jsx),
									determine_json_module(jsx);
								_ ->
									jose_json_unsupported
							end
					end;
				M when is_atom(M) ->
					determine_json_module(M)
			end
	end,
	[{json_module, JSONModule}].

%% @private
determine_json_module(jsx) ->
	jose_json_jsx;
determine_json_module('Elixir.Poison') ->
	Map = ?POISON_MAP,
	Bin = ?POISON_BIN,
	case jose_json_poison:encode(Map) of
		Bin ->
			jose_json_poison;
		_ ->
			determine_json_module('Elixir.JOSE.Poison')
	end;
determine_json_module('Elixir.JOSE.Poison') ->
	Map = ?POISON_MAP,
	Bin = ?POISON_BIN,
	case code:ensure_loaded('Elixir.JOSE.Poison') of
		{module, 'Elixir.JOSE.Poison'} ->
			try jose_json_poison_ord_encoder:encode(Map) of
				Bin ->
					jose_json_poison_ord_encoder;
				_ ->
					determine_json_module(jose_json_poison_compat_encoder)
			catch
				_:_ ->
					determine_json_module(jose_json_poison_compat_encoder)
			end;
		_ ->
			determine_json_module(jose_json_poison_compat_encoder)
	end;
determine_json_module(jose_json_poison_compat_encoder) ->
	Map = ?POISON_MAP,
	Bin = ?POISON_BIN,
	try jose_json_poison_compat_encoder:encode(Map) of
		Bin ->
			jose_json_poison_compat_encoder;
		_ ->
			jose_json_poison
	catch
		_:_ ->
			jose_json_poison
	end;
determine_json_module(Module) when is_atom(Module) ->
	Module.

%% @private
determine_supported_ciphers() ->
	determine_supported_ciphers(?CRYPTO_FALLBACK).

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
	end || RSAPadding <- determine_supported_rsa_padding(?CRYPTO_FALLBACK)].

%% @private
determine_supported_rsa_padding(false) ->
	[rsa_pkcs1_padding, rsa_pkcs1_oaep_padding];
determine_supported_rsa_padding(true) ->
	[rsa_pkcs1_padding, rsa_pkcs1_oaep_padding, rsa_pkcs1_oaep256_padding].

%% @private
determine_supported_signers() ->
	[begin
		{{signer, Signer}}
	end || Signer <- determine_supported_signers(?CRYPTO_FALLBACK)].

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
