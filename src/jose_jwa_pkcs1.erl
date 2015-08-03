%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc PKCS #1: RSA Cryptography Specifications Version 2.1
%%% See RFC 3447: [https://tools.ietf.org/html/rfc3447]
%%% @end
%%% Created :  28 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_pkcs1).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([eme_oaep_decode/4]).
-export([eme_oaep_encode/4]).
-export([emsa_pss_encode/3]).
-export([emsa_pss_encode/4]).
-export([emsa_pss_verify/4]).
-export([emsa_pss_verify/5]).
-export([mgf1/3]).
-export([rsaes_oaep_decrypt/3]).
-export([rsaes_oaep_decrypt/4]).
-export([rsaes_oaep_encrypt/3]).
-export([rsaes_oaep_encrypt/4]).
-export([rsassa_pss_sign/3]).
-export([rsassa_pss_sign/4]).
-export([rsassa_pss_verify/4]).
-export([rsassa_pss_verify/5]).

%% Types
-type rsa_digest_type() :: 'md5' | 'sha' | 'sha224' | 'sha256' | 'sha384' | 'sha512'.
-type rsa_hash_fun()    :: rsa_digest_type() | {hmac, rsa_digest_type(), iodata()} | fun((iodata()) -> binary()).
-type rsa_public_key()  :: #'RSAPublicKey'{}.
-type rsa_private_key() :: #'RSAPrivateKey'{}.

-define(PSS_TRAILER_FIELD, 16#BC).

%%====================================================================
%% API functions
%%====================================================================

%% See [https://tools.ietf.org/html/rfc3447#section-7.1.2]
-spec eme_oaep_decode(Hash, EM, Label, K) -> M | error
	when
		Hash  :: rsa_hash_fun(),
		EM    :: binary(),
		Label :: binary(),
		K     :: integer(),
		M     :: binary().
eme_oaep_decode(Hash, EM, Label, K)
		when is_function(Hash, 1)
		andalso is_binary(EM)
		andalso is_binary(Label)
		andalso is_integer(K) ->
	HLen = byte_size(Hash(<<>>)),
	LHash = Hash(Label),
	MaskedDBLen = K - HLen - 1,
	case EM of
		<< Y, MaskedSeed:HLen/binary, MaskedDB:MaskedDBLen/binary >> ->
			case mgf1(Hash, MaskedDB, HLen) of
				{ok, SeedMask} ->
					Seed = crypto:exor(MaskedSeed, SeedMask),
					case mgf1(Hash, Seed, K - HLen - 1) of
						{ok, DBMask} ->
							DB = crypto:exor(MaskedDB, DBMask),
							case DB of
								<< LHashPrime:HLen/binary, DBRight/binary >> ->
									case {Y, unpad_zero(DBRight), LHashPrime} of
										{16#00, << 16#01, M/binary >>, LHash} ->
											M;
										_BadPS ->
											error
									end;
								_BadDB ->
									error
							end;
						_DBMaskMGF1Error ->
							error
					end;
				_SeedMGF1Error ->
					error
			end;
		_BadEM ->
			error
	end;
eme_oaep_decode(Hash, EM, Label, K)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	eme_oaep_decode(HashFun, EM, Label, K).

%% See [https://tools.ietf.org/html/rfc3447#section-7.1.1]
-spec eme_oaep_encode(Hash, DM, Label, K) -> {ok, EM} | {error, Reason}
	when
		Hash   :: rsa_hash_fun(),
		DM     :: binary(),
		Label  :: binary(),
		K      :: integer(),
		EM     :: binary(),
		Reason :: term().
eme_oaep_encode(Hash, DM, Label, K)
		when is_function(Hash, 1)
		andalso is_binary(DM)
		andalso is_binary(Label)
		andalso is_integer(K) ->
	HLen = byte_size(Hash(<<>>)),
	MLen = byte_size(DM),
	LHash = Hash(Label),
	PSLen = ((K - MLen - (2 * HLen) - 2) * 8),
	PS = case PSLen > 0 of
		true ->
			<< 0:PSLen >>;
		false ->
			<<>>
	end,
	DB = << LHash/binary, PS/binary, 16#01, DM/binary >>,
	Seed = crypto:rand_bytes(HLen),
	case mgf1(Hash, Seed, K - HLen - 1) of
		{ok, DBMask} ->
			MaskedDB = crypto:exor(DB, DBMask),
			case mgf1(Hash, MaskedDB, HLen) of
				{ok, SeedMask} ->
					MaskedSeed = crypto:exor(Seed, SeedMask),
					EM = << 16#00, MaskedSeed/binary, MaskedDB/binary >>,
					{ok, EM};
				MGF1SeedError ->
					MGF1SeedError
			end;
		MGF1Error ->
			MGF1Error
	end;
eme_oaep_encode(Hash, DM, Label, K)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	eme_oaep_encode(HashFun, DM, Label, K).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.1]
-spec emsa_pss_encode(Hash, Message, EMBits) -> {ok, EM} | {error, Reason}
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		EMBits  :: integer(),
		EM      :: binary(),
		Reason  :: term().
emsa_pss_encode(Hash, Message, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_integer(EMBits) ->
	SaltLen = byte_size(Hash(<<>>)),
	emsa_pss_encode(Hash, Message, SaltLen, EMBits);
emsa_pss_encode(Hash, Message, EMBits)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	emsa_pss_encode(HashFun, Message, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.1]
-spec emsa_pss_encode(Hash, Message, Salt, EMBits) -> {ok, EM} | {error, Reason}
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		Salt    :: binary() | integer(),
		EMBits  :: integer(),
		EM      :: binary(),
		Reason  :: term().
emsa_pss_encode(Hash, Message, Salt, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(Salt)
		andalso is_integer(EMBits) ->
	MHash = Hash(Message),
	HashLen = byte_size(MHash),
	SaltLen = byte_size(Salt),
	EMLen = ceiling(EMBits / 8),
	case EMLen < (HashLen + SaltLen + 2) of
		false ->
			MPrime = << 0:64, MHash/binary, Salt/binary >>,
			H = Hash(MPrime),
			PS = << 0:((EMLen - SaltLen - HashLen - 2) * 8) >>,
			DB = << PS/binary, 16#01, Salt/binary >>,
			case mgf1(Hash, H, EMLen - HashLen - 1) of
				{ok, DBMask} ->
					LeftBits = (EMLen * 8) - EMBits,
					<< _:LeftBits/bitstring, MaskedDBRight/bitstring >> = crypto:exor(DB, DBMask),
					MaskedDB = << 0:LeftBits, MaskedDBRight/bitstring >>,
					EM = << MaskedDB/binary, H/binary, ?PSS_TRAILER_FIELD >>,
					{ok, EM};
				MGF1Error ->
					MGF1Error
			end;
		true ->
			{error, encoding_error}
	end;
emsa_pss_encode(Hash, Message, SaltLen, EMBits)
		when is_integer(SaltLen)
		andalso SaltLen >= 0 ->
	Salt = crypto:rand_bytes(SaltLen),
	emsa_pss_encode(Hash, Message, Salt, EMBits);
emsa_pss_encode(Hash, Message, Salt, EMBits)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	emsa_pss_encode(HashFun, Message, Salt, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.2]
-spec emsa_pss_verify(Hash, Message, EM, EMBits) -> boolean()
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		EM      :: binary(),
		EMBits  :: integer().
emsa_pss_verify(Hash, Message, EM, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(EM)
		andalso is_integer(EMBits) ->
	SaltLen = byte_size(Hash(<<>>)),
	emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits);
emsa_pss_verify(Hash, Message, EM, EMBits)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	emsa_pss_verify(HashFun, Message, EM, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.2]
-spec emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits) -> boolean()
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		EM      :: binary(),
		SaltLen :: integer(),
		EMBits  :: integer().
emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits) ->
	MHash = Hash(Message),
	HashLen = byte_size(MHash),
	EMLen = ceiling(EMBits / 8),
	MaskedDBLen = (EMLen - HashLen - 1),
	case {EMLen < (HashLen + SaltLen + 2), byte_size(EM), EM} of
		{false, EMLen, << MaskedDB:MaskedDBLen/binary, H:HashLen/binary, ?PSS_TRAILER_FIELD >>} ->
			LeftBits = ((EMLen * 8) - EMBits),
			case MaskedDB of
				<< 0:LeftBits, _/bitstring >> ->
					case mgf1(Hash, H, EMLen - HashLen - 1) of
						{ok, DBMask} ->
							<< _:LeftBits/bitstring, DBRight/bitstring >> = crypto:exor(MaskedDB, DBMask),
							DB = << 0:LeftBits, DBRight/bitstring >>,
							PSLen = ((EMLen - HashLen - SaltLen - 2) * 8),
							case DB of
								<< 0:PSLen, 16#01, Salt:SaltLen/binary >> ->
									MPrime = << 0:64, MHash/binary, Salt/binary >>,
									HPrime = Hash(MPrime),
									H =:= HPrime;
								_BadDB ->
									false
							end;
						_MGF1Error ->
							false
					end;
				_BadMaskedDB ->
					false
			end;
		_ ->
			false
	end.

%% See [https://tools.ietf.org/html/rfc3447#appendix-B.2]
-spec mgf1(Hash, Seed, MaskLen) -> {ok, binary()} | {error, mask_too_long}
	when
		Hash    :: rsa_hash_fun(),
		Seed    :: binary(),
		MaskLen :: pos_integer().
mgf1(Hash, Seed, MaskLen)
		when is_function(Hash, 1)
		andalso is_binary(Seed)
		andalso is_integer(MaskLen)
		andalso MaskLen >= 0 ->
	HashLen = byte_size(Hash(<<>>)),
	case MaskLen > (16#FFFFFFFF * HashLen) of
		false ->
			Reps = ceiling(MaskLen / HashLen),
			{ok, derive_mgf1(Hash, 0, Reps, Seed, MaskLen, <<>>)};
		true ->
			{error, mask_too_long}
	end;
mgf1(Hash, Seed, MaskLen)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	mgf1(HashFun, Seed, MaskLen).

%% See [https://tools.ietf.org/html/rfc3447#section-7.1.2]
-spec rsaes_oaep_decrypt(Hash, CipherText, RSAPrivateKey) -> PlainText
	when
		Hash          :: rsa_hash_fun(),
		CipherText    :: binary(),
		RSAPrivateKey :: rsa_private_key(),
		PlainText     :: binary().
rsaes_oaep_decrypt(Hash, CipherText, RSAPrivateKey=#'RSAPrivateKey'{})
		when is_function(Hash, 1)
		andalso is_binary(CipherText) ->
	rsaes_oaep_decrypt(Hash, CipherText, <<>>, RSAPrivateKey);
rsaes_oaep_decrypt(Hash, CipherText, RSAPrivateKey)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsaes_oaep_decrypt(HashFun, CipherText, RSAPrivateKey).

%% See [https://tools.ietf.org/html/rfc3447#section-7.1.2]
-spec rsaes_oaep_decrypt(Hash, CipherText, Label, RSAPrivateKey) -> PlainText
	when
		Hash          :: rsa_hash_fun(),
		CipherText    :: binary(),
		Label         :: binary(),
		RSAPrivateKey :: rsa_private_key(),
		PlainText     :: binary().
rsaes_oaep_decrypt(Hash, CipherText, Label, RSAPrivateKey=#'RSAPrivateKey'{modulus=N})
		when is_function(Hash, 1)
		andalso is_binary(CipherText)
		andalso is_binary(Label) ->
	HLen = byte_size(Hash(<<>>)),
	K = int_to_byte_size(N),
	case {byte_size(CipherText), K < ((2 * HLen) + 2)} of
		{K, false} ->
			EM = pad_to_key_size(K, dp(CipherText, RSAPrivateKey)),
			eme_oaep_decode(Hash, EM, Label, K);
		_BadSize ->
			{error, {badsize, _BadSize}}
	end;
rsaes_oaep_decrypt(Hash, CipherText, Label, RSAPrivateKey)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsaes_oaep_decrypt(HashFun, CipherText, Label, RSAPrivateKey).

%% See [https://tools.ietf.org/html/rfc3447#section-7.1.1]
-spec rsaes_oaep_encrypt(Hash, PlainText, RSAPublicKey) -> CipherText
	when
		Hash         :: rsa_hash_fun(),
		PlainText    :: binary(),
		RSAPublicKey :: rsa_public_key(),
		CipherText   :: binary().
rsaes_oaep_encrypt(Hash, PlainText, RSAPublicKey=#'RSAPublicKey'{})
		when is_function(Hash, 1)
		andalso is_binary(PlainText) ->
	rsaes_oaep_encrypt(Hash, PlainText, <<>>, RSAPublicKey);
rsaes_oaep_encrypt(Hash, PlainText, RSAPublicKey)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsaes_oaep_encrypt(HashFun, PlainText, RSAPublicKey).

%% See [https://tools.ietf.org/html/rfc3447#section-7.1.1]
-spec rsaes_oaep_encrypt(Hash, PlainText, Label, RSAPublicKey) -> CipherText
	when
		Hash         :: rsa_hash_fun(),
		PlainText    :: binary(),
		Label        :: binary(),
		RSAPublicKey :: rsa_public_key(),
		CipherText   :: binary().
rsaes_oaep_encrypt(Hash, PlainText, Label, RSAPublicKey=#'RSAPublicKey'{modulus=N})
		when is_function(Hash, 1)
		andalso is_binary(PlainText)
		andalso is_binary(Label) ->
	HLen = byte_size(Hash(<<>>)),
	MLen = byte_size(PlainText),
	K = int_to_byte_size(N),
	case MLen > (K - (2 * HLen) - 2) of
		false ->
			case eme_oaep_encode(Hash, PlainText, Label, K) of
				{ok, EM} ->
					C = pad_to_key_size(K, ep(EM, RSAPublicKey)),
					{ok, C};
				EncodingError ->
					EncodingError
			end;
		true ->
			{error, message_too_long}
	end;
rsaes_oaep_encrypt(Hash, PlainText, Label, RSAPublicKey)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsaes_oaep_encrypt(HashFun, PlainText, Label, RSAPublicKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.1]
-spec rsassa_pss_sign(Hash, Message, RSAPrivateKey) -> {ok, Signature} | {error, Reason}
	when
		Hash          :: rsa_hash_fun(),
		Message       :: binary(),
		RSAPrivateKey :: rsa_private_key(),
		Signature     :: binary(),
		Reason        :: term().
rsassa_pss_sign(Hash, Message, RSAPrivateKey=#'RSAPrivateKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message) ->
	ModBits = int_to_bit_size(Modulus),
	case emsa_pss_encode(Hash, Message, ModBits - 1) of
		{ok, EM} ->
			ModBytes = int_to_byte_size(Modulus),
			S = pad_to_key_size(ModBytes, dp(EM, RSAPrivateKey)),
			{ok, S};
		EncodingError ->
			EncodingError
	end;
rsassa_pss_sign(Hash, Message, RSAPrivateKey=#'RSAPrivateKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_sign(HashFun, Message, RSAPrivateKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.1]
-spec rsassa_pss_sign(Hash, Message, Salt, RSAPrivateKey) -> {ok, Signature} | {error, Reason}
	when
		Hash          :: rsa_hash_fun(),
		Message       :: binary(),
		Salt          :: binary() | integer(),
		RSAPrivateKey :: rsa_private_key(),
		Signature     :: binary(),
		Reason        :: term().
rsassa_pss_sign(Hash, Message, Salt, RSAPrivateKey=#'RSAPrivateKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso (is_binary(Salt) orelse is_integer(Salt)) ->
	ModBits = int_to_bit_size(Modulus),
	case emsa_pss_encode(Hash, Message, Salt, ModBits - 1) of
		{ok, EM} ->
			ModBytes = int_to_byte_size(Modulus),
			S = pad_to_key_size(ModBytes, dp(EM, RSAPrivateKey)),
			{ok, S};
		EncodingError ->
			EncodingError
	end;
rsassa_pss_sign(Hash, Message, Salt, RSAPrivateKey=#'RSAPrivateKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_sign(HashFun, Message, Salt, RSAPrivateKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.2]
-spec rsassa_pss_verify(Hash, Message, Signature, RSAPublicKey) -> boolean()
	when
		Hash         :: rsa_hash_fun(),
		Message      :: binary(),
		Signature    :: binary(),
		RSAPublicKey :: rsa_public_key().
rsassa_pss_verify(Hash, Message, Signature, RSAPublicKey=#'RSAPublicKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(Signature) ->
	ModBytes = int_to_byte_size(Modulus),
	case byte_size(Signature) =:= ModBytes of
		true ->
			ModBits = int_to_bit_size(Modulus),
			EM = pad_to_key_size(ceiling((ModBits - 1) / 8), ep(Signature, RSAPublicKey)),
			emsa_pss_verify(Hash, Message, EM, ModBits - 1);
		false ->
			false
	end;
rsassa_pss_verify(Hash, Message, Signature, RSAPublicKey=#'RSAPublicKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_verify(HashFun, Message, Signature, RSAPublicKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.2]
-spec rsassa_pss_verify(Hash, Message, Signature, SaltLen, RSAPublicKey) -> boolean()
	when
		Hash         :: rsa_hash_fun(),
		Message      :: binary(),
		Signature    :: binary(),
		SaltLen      :: integer(),
		RSAPublicKey :: rsa_public_key().
rsassa_pss_verify(Hash, Message, Signature, SaltLen, RSAPublicKey=#'RSAPublicKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(Signature)
		andalso is_integer(SaltLen) ->
	ModBytes = int_to_byte_size(Modulus),
	case byte_size(Signature) =:= ModBytes of
		true ->
			ModBits = int_to_bit_size(Modulus),
			EM = pad_to_key_size(ceiling((ModBits - 1) / 8), ep(Signature, RSAPublicKey)),
			emsa_pss_verify(Hash, Message, EM, SaltLen, ModBits - 1);
		false ->
			false
	end;
rsassa_pss_verify(Hash, Message, Signature, SaltLen, RSAPublicKey=#'RSAPublicKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_verify(HashFun, Message, Signature, SaltLen, RSAPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
ceiling(X) when X < 0 ->
	trunc(X);
ceiling(X) ->
	T = trunc(X),
	case X - T == 0 of
		false ->
			T + 1;
		true ->
			T
	end.

%% @private
derive_mgf1(_Hash, Reps, Reps, _Seed, MaskLen, T) ->
	binary:part(T, 0, MaskLen);
derive_mgf1(Hash, Counter, Reps, Seed, MaskLen, T) ->
	CounterBin = << Counter:8/unsigned-big-integer-unit:4 >>,
	NewT = << T/binary, (Hash(<< Seed/binary, CounterBin/binary >>))/binary >>,
	derive_mgf1(Hash, Counter + 1, Reps, Seed, MaskLen, NewT).

%% @private
dp(B, #'RSAPrivateKey'{modulus=N, privateExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
ep(B, #'RSAPublicKey'{modulus=N, publicExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
int_to_bit_size(I) ->
	int_to_bit_size(I, 0).

%% @private
int_to_bit_size(0, B) ->
	B;
int_to_bit_size(I, B) ->
	int_to_bit_size(I bsr 1, B + 1).

%% @private
int_to_byte_size(I) ->
	int_to_byte_size(I, 0).

%% @private
int_to_byte_size(0, B) ->
	B;
int_to_byte_size(I, B) ->
	int_to_byte_size(I bsr 8, B + 1).

%% @private
pad_to_key_size(Bytes, Data) when byte_size(Data) < Bytes ->
	pad_to_key_size(Bytes, << 0, Data/binary >>);
pad_to_key_size(_Bytes, Data) ->
	Data.

%% @private
resolve_hash(HashFun) when is_function(HashFun, 1) ->
	HashFun;
resolve_hash(DigestType) when is_atom(DigestType) ->
	fun(Data) ->
		crypto:hash(DigestType, Data)
	end;
resolve_hash({hmac, DigestType, Key}) when is_atom(DigestType) ->
	fun(Data) ->
		crypto:hmac(DigestType, Key, Data)
	end.

%% @private
unpad_zero(<< 0, Rest/binary >>) ->
	unpad_zero(Rest);
unpad_zero(Rest) ->
	Rest.
