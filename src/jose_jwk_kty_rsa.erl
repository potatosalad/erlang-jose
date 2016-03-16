%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  23 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_kty_rsa).
-behaviour(jose_jwk).
-behaviour(jose_jwk_kty).
-behaviour(jose_jwk_use_enc).
-behaviour(jose_jwk_use_sig).

-include_lib("public_key/include/public_key.hrl").

%% jose_jwk callbacks
-export([from_map/1]).
-export([to_key/1]).
-export([to_map/2]).
-export([to_public_map/2]).
-export([to_thumbprint_map/2]).
%% jose_jwk_kty callbacks
-export([generate_key/1]).
-export([generate_key/2]).
-export([key_encryptor/3]).
%% jose_jwk_use_enc callbacks
-export([block_encryptor/2]).
-export([decrypt_private/3]).
-export([encrypt_public/3]).
%% jose_jwk_use_sig callbacks
-export([sign/3]).
-export([signer/2]).
-export([verifier/2]).
-export([verify/4]).
%% API
-export([from_key/1]).
-export([from_pem/1]).
-export([from_pem/2]).
-export([to_pem/1]).
-export([to_pem/2]).

%% Types
-type key() :: #'RSAPrivateKey'{} | #'RSAPublicKey'{}.

-export_type([key/0]).

%%====================================================================
%% jose_jwk callbacks
%%====================================================================

from_map(F = #{ <<"kty">> := <<"RSA">>, <<"d">> := _ }) ->
	from_map_rsa_private_key(maps:remove(<<"kty">>, F), #'RSAPrivateKey'{ version = 'two-prime', otherPrimeInfos = 'asn1_NOVALUE' });
from_map(F = #{ <<"kty">> := <<"RSA">> }) ->
	from_map_rsa_public_key(maps:remove(<<"kty">>, F), #'RSAPublicKey'{}).

to_key(RSAPrivateKey=#'RSAPrivateKey'{}) ->
	RSAPrivateKey;
to_key(RSAPublicKey=#'RSAPublicKey'{}) ->
	RSAPublicKey.

to_map(#'RSAPrivateKey'{
		version = 'two-prime',
		otherPrimeInfos = 'asn1_NOVALUE',
		privateExponent = D,
		exponent1 = DP,
		exponent2 = DQ,
		publicExponent = E,
		modulus = N,
		prime1 = P,
		prime2 = Q,
		coefficient = QI}, F) ->
	F#{
		<<"d">> => base64url:encode(int_to_bin(D)),
		<<"dp">> => base64url:encode(int_to_bin(DP)),
		<<"dq">> => base64url:encode(int_to_bin(DQ)),
		<<"e">> => base64url:encode(int_to_bin(E)),
		<<"kty">> => <<"RSA">>,
		<<"n">> => base64url:encode(int_to_bin(N)),
		<<"p">> => base64url:encode(int_to_bin(P)),
		<<"q">> => base64url:encode(int_to_bin(Q)),
		<<"qi">> => base64url:encode(int_to_bin(QI))
	};
to_map(#'RSAPrivateKey'{
		version = 'multi',
		otherPrimeInfos = OTH,
		privateExponent = D,
		exponent1 = DP,
		exponent2 = DQ,
		publicExponent = E,
		modulus = N,
		prime1 = P,
		prime2 = Q,
		coefficient = QI}, F) ->
	F#{
		<<"d">> => base64url:encode(int_to_bin(D)),
		<<"dp">> => base64url:encode(int_to_bin(DP)),
		<<"dq">> => base64url:encode(int_to_bin(DQ)),
		<<"e">> => base64url:encode(int_to_bin(E)),
		<<"kty">> => <<"RSA">>,
		<<"n">> => base64url:encode(int_to_bin(N)),
		<<"oth">> => [begin
			#{
				<<"d">> => base64url:encode(int_to_bin(OD)),
				<<"r">> => base64url:encode(int_to_bin(OR)),
				<<"t">> => base64url:encode(int_to_bin(OT))
			}
		end || #'OtherPrimeInfo'{
			prime = OR,
			exponent = OD,
			coefficient = OT} <- OTH],
		<<"p">> => base64url:encode(int_to_bin(P)),
		<<"q">> => base64url:encode(int_to_bin(Q)),
		<<"qi">> => base64url:encode(int_to_bin(QI))
	};
to_map(#'RSAPublicKey'{
		publicExponent = E,
		modulus = N}, F) ->
	F#{
		<<"e">> => base64url:encode(int_to_bin(E)),
		<<"kty">> => <<"RSA">>,
		<<"n">> => base64url:encode(int_to_bin(N))
	}.

to_public_map(K=#'RSAPrivateKey'{}, F) ->
	maps:without([<<"d">>, <<"dp">>, <<"dq">>, <<"p">>, <<"q">>, <<"qi">>, <<"oth">>], to_map(K, F));
to_public_map(K=#'RSAPublicKey'{}, F) ->
	to_map(K, F).

to_thumbprint_map(K, F) ->
	maps:with([<<"e">>, <<"kty">>, <<"n">>], to_public_map(K, F)).

%%====================================================================
%% jose_jwk_kty callbacks
%%====================================================================

generate_key(#'RSAPrivateKey'{ modulus = N, publicExponent = E }) ->
	generate_key({rsa, int_to_bit_size(N), E});
generate_key(#'RSAPublicKey'{ modulus = N, publicExponent = E }) ->
	generate_key({rsa, int_to_bit_size(N), E});
generate_key({rsa, ModulusSize}) when is_integer(ModulusSize) ->
	generate_key({rsa, ModulusSize, 65537});
generate_key({rsa, ModulusSize, ExponentSize})
		when is_integer(ModulusSize)
		andalso is_integer(ExponentSize) ->
	case code:ensure_loaded(cutkey) of
		{module, cutkey} ->
			_ = application:ensure_all_started(cutkey),
			try cutkey:rsa(ModulusSize, ExponentSize, [{return, key}]) of
				{ok, Key=#'RSAPrivateKey'{}} ->
					{Key, #{}};
				{error, Reason} ->
					erlang:error({cutkey_error, Reason})
			catch
				Class:Reason ->
					erlang:error({cutkey_error, {Class, Reason}})
			end;
		Error ->
			erlang:error({cutkey_missing, Error})
	end.

generate_key(KTY, Fields) ->
	{NewKTY, OtherFields} = generate_key(KTY),
	{NewKTY, maps:merge(maps:remove(<<"kid">>, Fields), OtherFields)}.

key_encryptor(KTY, Fields, Key) ->
	jose_jwk_kty:key_encryptor(KTY, Fields, Key).

%%====================================================================
%% jose_jwk_use_enc callbacks
%%====================================================================

block_encryptor(_KTY, #{ <<"alg">> := ALG, <<"enc">> := ENC, <<"use">> := <<"enc">> }) ->
	#{
		<<"alg">> => ALG,
		<<"enc">> => ENC
	};
block_encryptor(_KTY, _Fields) ->
	#{
		<<"alg">> => case jose_jwa:is_rsa_crypt_supported(rsa_oaep) of
			false -> <<"RSA1_5">>;
			true  -> <<"RSA-OAEP">>
		end,
		<<"enc">> => case jose_jwa:is_block_cipher_supported({aes_gcm, 128}) of
			false -> <<"A128CBC-HS256">>;
			true  -> <<"A128GCM">>
		end
	}.

decrypt_private(CipherText, Options, RSAPrivateKey=#'RSAPrivateKey'{}) ->
	jose_jwa:decrypt_private(CipherText, RSAPrivateKey, Options).

encrypt_public(PlainText, Options, RSAPublicKey=#'RSAPublicKey'{}) ->
	jose_jwa:encrypt_public(PlainText, RSAPublicKey, Options);
encrypt_public(PlainText, Options, #'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}) ->
	RSAPublicKey = #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent},
	encrypt_public(PlainText, Options, RSAPublicKey).

%%====================================================================
%% jose_jwk_use_sig callbacks
%%====================================================================

sign(Message, {Padding, DigestType}, RSAPrivateKey=#'RSAPrivateKey'{}) ->
	jose_jwa:sign(Message, DigestType, RSAPrivateKey, Padding);
sign(Message, DigestType, RSAPrivateKey=#'RSAPrivateKey'{}) ->
	sign(Message, {rsa_pkcs1_padding, DigestType}, RSAPrivateKey).

signer(#'RSAPrivateKey'{}, #{ <<"alg">> := ALG, <<"use">> := <<"sig">> }) ->
	#{
		<<"alg">> => ALG
	};
signer(#'RSAPrivateKey'{}, _Fields) ->
	#{
		<<"alg">> => case jose_jwa:is_rsa_sign_supported(rsa_pkcs1_pss_padding) of
			false -> <<"RS256">>;
			true  -> <<"PS256">>
		end
	}.

verifier(_KTY, #{ <<"alg">> := ALG, <<"use">> := <<"sig">> }) ->
	[ALG];
verifier(#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}, Fields) ->
	RSAPublicKey = #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent},
	verifier(RSAPublicKey, Fields);
verifier(#'RSAPublicKey'{}, _Fields) ->
	case jose_jwa:is_rsa_sign_supported(rsa_pkcs1_pss_padding) of
		false ->
			[<<"RS256">>, <<"RS384">>, <<"RS512">>];
		true ->
			[<<"PS256">>, <<"PS384">>, <<"PS512">>, <<"RS256">>, <<"RS384">>, <<"RS512">>]
	end.

verify(Message, {Padding, DigestType}, Signature, RSAPublicKey=#'RSAPublicKey'{}) ->
	jose_jwa:verify(Message, DigestType, Signature, RSAPublicKey, Padding);
verify(Message, DigestType, Signature, RSAPublicKey=#'RSAPublicKey'{}) ->
	verify(Message, {rsa_pkcs1_padding, DigestType}, Signature, RSAPublicKey);
verify(Message, DigestType, Signature, #'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}) ->
	RSAPublicKey = #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent},
	verify(Message, DigestType, Signature, RSAPublicKey).

%%====================================================================
%% API functions
%%====================================================================

from_key(RSAPrivateKey=#'RSAPrivateKey'{}) ->
	{RSAPrivateKey, #{}};
from_key(RSAPublicKey=#'RSAPublicKey'{}) ->
	{RSAPublicKey, #{}}.

from_pem(PEMBinary) when is_binary(PEMBinary) ->
	case jose_jwk_pem:from_binary(PEMBinary) of
		{?MODULE, {Key, Fields}} ->
			{Key, Fields};
		PEMError ->
			PEMError
	end.

from_pem(Password, PEMBinary) when is_binary(PEMBinary) ->
	case jose_jwk_pem:from_binary(Password, PEMBinary) of
		{?MODULE, {Key, Fields}} ->
			{Key, Fields};
		PEMError ->
			PEMError
	end.

to_pem(RSAPrivateKey=#'RSAPrivateKey'{}) ->
	PEMEntry = public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey),
	public_key:pem_encode([PEMEntry]);
to_pem(RSAPublicKey=#'RSAPublicKey'{}) ->
	PEMEntry = public_key:pem_entry_encode('RSAPublicKey', RSAPublicKey),
	public_key:pem_encode([PEMEntry]).

to_pem(Password, RSAPrivateKey=#'RSAPrivateKey'{}) ->
	jose_jwk_pem:to_binary(Password, 'RSAPrivateKey', RSAPrivateKey);
to_pem(Password, RSAPublicKey=#'RSAPublicKey'{}) ->
	jose_jwk_pem:to_binary(Password, 'RSAPublicKey', RSAPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
from_map_rsa_private_key(F = #{ <<"d">> := D }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"d">>, F), Key#'RSAPrivateKey'{ privateExponent = crypto:bytes_to_integer(base64url:decode(D)) });
from_map_rsa_private_key(F = #{ <<"dp">> := DP }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"dp">>, F), Key#'RSAPrivateKey'{ exponent1 = crypto:bytes_to_integer(base64url:decode(DP)) });
from_map_rsa_private_key(F = #{ <<"dq">> := DQ }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"dq">>, F), Key#'RSAPrivateKey'{ exponent2 = crypto:bytes_to_integer(base64url:decode(DQ)) });
from_map_rsa_private_key(F = #{ <<"e">> := E }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"e">>, F), Key#'RSAPrivateKey'{ publicExponent = crypto:bytes_to_integer(base64url:decode(E)) });
from_map_rsa_private_key(F = #{ <<"n">> := N }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"n">>, F), Key#'RSAPrivateKey'{ modulus = crypto:bytes_to_integer(base64url:decode(N)) });
from_map_rsa_private_key(F = #{ <<"p">> := P }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"p">>, F), Key#'RSAPrivateKey'{ prime1 = crypto:bytes_to_integer(base64url:decode(P)) });
from_map_rsa_private_key(F = #{ <<"q">> := Q }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"q">>, F), Key#'RSAPrivateKey'{ prime2 = crypto:bytes_to_integer(base64url:decode(Q)) });
from_map_rsa_private_key(F = #{ <<"qi">> := QI }, Key) ->
	from_map_rsa_private_key(maps:remove(<<"qi">>, F), Key#'RSAPrivateKey'{ coefficient = crypto:bytes_to_integer(base64url:decode(QI)) });
from_map_rsa_private_key(F = #{ <<"oth">> := OTH }, Key) ->
	OtherPrimeInfos = [begin
		#'OtherPrimeInfo'{
			prime = crypto:bytes_to_integer(base64url:decode(OR)),
			exponent = crypto:bytes_to_integer(base64url:decode(OD)),
			coefficient = crypto:bytes_to_integer(base64url:decode(OT))}
	end || #{ <<"d">> := OD, <<"r">> := OR, <<"t">> := OT } <- OTH],
	from_map_rsa_private_key(maps:remove(<<"oth">>, F), Key#'RSAPrivateKey'{ version = 'multi', otherPrimeInfos = OtherPrimeInfos });
from_map_rsa_private_key(F, Key) ->
	{Key, F}.

%% @private
from_map_rsa_public_key(F = #{ <<"e">> := E }, Key) ->
	from_map_rsa_public_key(maps:remove(<<"e">>, F), Key#'RSAPublicKey'{ publicExponent = crypto:bytes_to_integer(base64url:decode(E)) });
from_map_rsa_public_key(F = #{ <<"n">> := N }, Key) ->
	from_map_rsa_public_key(maps:remove(<<"n">>, F), Key#'RSAPublicKey'{ modulus = crypto:bytes_to_integer(base64url:decode(N)) });
from_map_rsa_public_key(F, Key) ->
	{Key, F}.

%% @private
int_to_bin(X) when X < 0 -> int_to_bin_neg(X, []);
int_to_bin(X) -> int_to_bin_pos(X, []).

%% @private
int_to_bin_pos(0,Ds=[_|_]) ->
	list_to_binary(Ds);
int_to_bin_pos(X,Ds) ->
	int_to_bin_pos(X bsr 8, [(X band 255)|Ds]).

%% @private
int_to_bin_neg(-1, Ds=[MSB|_]) when MSB >= 16#80 ->
	list_to_binary(Ds);
int_to_bin_neg(X,Ds) ->
	int_to_bin_neg(X bsr 8, [(X band 255)|Ds]).

%% @private
int_to_bit_size(I) ->
	int_to_bit_size(I, 0).

%% @private
int_to_bit_size(0, B) ->
	B;
int_to_bit_size(I, B) ->
	int_to_bit_size(I bsr 1, B + 1).
