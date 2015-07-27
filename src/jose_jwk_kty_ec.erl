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
-module(jose_jwk_kty_ec).

-include_lib("public_key/include/public_key.hrl").

%% jose_jwk callbacks
-export([from_map/1]).
-export([to_key/1]).
-export([to_map/2]).
-export([to_public_map/2]).
-export([to_thumbprint_map/2]).
%% jose_jwk_kty callbacks
-export([block_encryptor/3]).
-export([derive_key/1]).
-export([derive_key/2]).
-export([key_encryptor/3]).
-export([public_encrypt/3]).
-export([private_decrypt/3]).
-export([sign/3]).
-export([signer/3]).
-export([verify/4]).
%% API
-export([from_key/1]).
-export([from_pem/1]).
-export([from_pem/2]).
-export([to_pem/1]).
-export([to_pem/2]).

%% Types
-type key() :: #'ECPrivateKey'{} | {#'ECPoint'{}, {namedCurve, Oid::tuple()} | #'ECParameters'{}}.

-export_type([key/0]).

%%====================================================================
%% jose_jwk callbacks
%%====================================================================

from_map(F = #{ <<"kty">> := <<"EC">>, <<"d">> := _ }) ->
	from_map_ec_private_key(maps:remove(<<"kty">>, F), #'ECPrivateKey'{ version = 1 });
from_map(F = #{ <<"kty">> := <<"EC">> }) ->
	from_map_ec_public_key(maps:remove(<<"kty">>, F), {#'ECPoint'{}, undefined}).

to_key(ECPrivateKey=#'ECPrivateKey'{}) ->
	ECPrivateKey;
to_key(ECPublicKey={#'ECPoint'{}, _}) ->
	ECPublicKey.

to_map(#'ECPrivateKey'{
		version = 1,
		privateKey = D,
		parameters = {namedCurve, Parameters},
		publicKey = PublicKey}, Fields) ->
	{X, Y} = public_key_to_x_y(PublicKey),
	Fields#{
		<<"d">> => base64url:encode(D),
		<<"crv">> => parameters_to_crv(Parameters),
		<<"kty">> => <<"EC">>,
		<<"x">> => base64url:encode(X),
		<<"y">> => base64url:encode(Y)
	};
to_map({#'ECPoint'{
		point = PublicKey },
		{namedCurve, Parameters}}, Fields) ->
	{X, Y} = public_key_to_x_y(PublicKey),
	Fields#{
		<<"crv">> => parameters_to_crv(Parameters),
		<<"kty">> => <<"EC">>,
		<<"x">> => base64url:encode(X),
		<<"y">> => base64url:encode(Y)
	}.

to_public_map(K=#'ECPrivateKey'{}, F) ->
	maps:without([<<"d">>], to_map(K, F));
to_public_map(K={#'ECPoint'{}, _}, F) ->
	to_map(K, F).

to_thumbprint_map(K, F) ->
	maps:with([<<"crv">>, <<"kty">>, <<"x">>, <<"y">>], to_public_map(K, F)).

%%====================================================================
%% jose_jwk_kty callbacks
%%====================================================================

block_encryptor(_KTY, _Fields, _PlainText) ->
	#{
		<<"alg">> => <<"ECDH-ES">>,
		<<"enc">> => <<"A128GCM">>
	}.

derive_key(_) ->
	erlang:error(not_supported).

derive_key({ECPoint=#'ECPoint'{}, _}, ECPrivateKey=#'ECPrivateKey'{}) ->
	public_key:compute_key(ECPoint, ECPrivateKey);
derive_key(#'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0}, ECPrivateKey=#'ECPrivateKey'{}) ->
	Octets = case Octets0 of
		{_, Octets1} ->
			Octets1;
		_ ->
			Octets0
	end,
	ECPoint = #'ECPoint'{point=Octets},
	ECPublicKey = {ECPoint, ECParameters},
	derive_key(ECPublicKey, ECPrivateKey).

key_encryptor(KTY, Fields, Key) ->
	jose_jwk_kty:key_encryptor(KTY, Fields, Key).

public_encrypt(_PlainText, _Options, _Key) ->
	erlang:error(not_supported).

private_decrypt(_CipherText, _Options, _Key) ->
	erlang:error(not_supported).

sign(Message, DigestType, ECPrivateKey=#'ECPrivateKey'{}) ->
	DERSignature = public_key:sign(Message, DigestType, ECPrivateKey),
	#'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', DERSignature),
	RBin = int_to_bin(R),
	SBin = int_to_bin(S),
	Signature = << RBin/binary, SBin/binary >>,
	Signature;
sign(_Message, _DigestType, {#'ECPoint'{}, _}) ->
	erlang:error(not_supported).

signer(#'ECPrivateKey'{}, _Fields, _PlainText) ->
	#{
		<<"alg">> => <<"ES256">>
	}.

verify(Message, DigestType, Signature, ECPublicKey={#'ECPoint'{}, _}) ->
	SignatureLen = byte_size(Signature),
	{RBin0, SBin0} = split_binary(Signature, (SignatureLen div 2)),
	R0 = crypto:bytes_to_integer(RBin0),
	S0 = crypto:bytes_to_integer(SBin0),
	DERSignature0 = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R0, s = S0 }),
	case {public_key:verify(Message, DigestType, DERSignature0, ECPublicKey), (SignatureLen rem 2)} of
		{false, 1} ->
			{RBin1, SBin1} = split_binary(Signature, (SignatureLen div 2) + (SignatureLen rem 2)),
			R1 = crypto:bytes_to_integer(RBin1),
			S1 = crypto:bytes_to_integer(SBin1),
			DERSignature1 = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R1, s = S1 }),
			public_key:verify(Message, DigestType, DERSignature1, ECPublicKey);
		{Verified, _} ->
			Verified
	end;
verify(Message, DigestType, Signature, #'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0}) ->
	Octets = case Octets0 of
		{_, Octets1} ->
			Octets1;
		_ ->
			Octets0
	end,
	ECPoint = #'ECPoint'{point=Octets},
	ECPublicKey = {ECPoint, ECParameters},
	verify(Message, DigestType, Signature, ECPublicKey).

%%====================================================================
%% API functions
%%====================================================================

from_key(ECPrivateKey=#'ECPrivateKey'{}) ->
	{ECPrivateKey, #{}};
from_key(ECPublicKey={#'ECPoint'{}, _}) ->
	{ECPublicKey, #{}}.

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

to_pem(ECPrivateKey=#'ECPrivateKey'{}) ->
	PEMEntry = public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey),
	public_key:pem_encode([PEMEntry]);
to_pem(ECPublicKey={#'ECPoint'{}, _ECParameters}) ->
	erlang:error({badarg, [ECPublicKey]}).

to_pem(Password, ECPrivateKey=#'ECPrivateKey'{}) ->
	jose_jwk_pem:to_binary(Password, 'ECPrivateKey', ECPrivateKey);
to_pem(Password, ECPublicKey={#'ECPoint'{}, _ECParameters}) ->
	erlang:error({badarg, [Password, ECPublicKey]}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
from_map_ec_private_key(F = #{ <<"d">> := D }, Key) ->
	from_map_ec_private_key(maps:remove(<<"d">>, F), Key#'ECPrivateKey'{ privateKey = base64url:decode(D) });
from_map_ec_private_key(F = #{ <<"crv">> := <<"P-256">> }, Key) ->
	from_map_ec_private_key(maps:remove(<<"crv">>, F), Key#'ECPrivateKey'{ parameters = {namedCurve, pubkey_cert_records:namedCurves(secp256r1)} });
from_map_ec_private_key(F = #{ <<"crv">> := <<"P-384">> }, Key) ->
	from_map_ec_private_key(maps:remove(<<"crv">>, F), Key#'ECPrivateKey'{ parameters = {namedCurve, pubkey_cert_records:namedCurves(secp384r1)} });
from_map_ec_private_key(F = #{ <<"crv">> := <<"P-521">> }, Key) ->
	from_map_ec_private_key(maps:remove(<<"crv">>, F), Key#'ECPrivateKey'{ parameters = {namedCurve, pubkey_cert_records:namedCurves(secp521r1)} });
from_map_ec_private_key(F = #{ <<"x">> := X, <<"y">> := Y }, Key) ->
	from_map_ec_private_key(maps:without([<<"x">>, <<"y">>], F), Key#'ECPrivateKey'{ publicKey = << 16#04, (base64url:decode(X))/binary, (base64url:decode(Y))/binary >>});
from_map_ec_private_key(F, Key) ->
	{Key, F}.

%% @private
from_map_ec_public_key(F = #{ <<"crv">> := <<"P-256">> }, {Point, _Params}) ->
	from_map_ec_public_key(maps:remove(<<"crv">>, F), {Point, {namedCurve, pubkey_cert_records:namedCurves(secp256r1)}});
from_map_ec_public_key(F = #{ <<"crv">> := <<"P-384">> }, {Point, _Params}) ->
	from_map_ec_public_key(maps:remove(<<"crv">>, F), {Point, {namedCurve, pubkey_cert_records:namedCurves(secp384r1)}});
from_map_ec_public_key(F = #{ <<"crv">> := <<"P-521">> }, {Point, _Params}) ->
	from_map_ec_public_key(maps:remove(<<"crv">>, F), {Point, {namedCurve, pubkey_cert_records:namedCurves(secp521r1)}});
from_map_ec_public_key(F = #{ <<"x">> := X, <<"y">> := Y }, {Point, Params}) ->
	from_map_ec_public_key(maps:without([<<"x">>, <<"y">>], F), {Point#'ECPoint'{ point = << 16#04, (base64url:decode(X))/binary, (base64url:decode(Y))/binary >> }, Params});
from_map_ec_public_key(F, Key) ->
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
parameters_to_crv(secp256r1) ->
	<<"P-256">>;
parameters_to_crv(secp384r1) ->
	<<"P-384">>;
parameters_to_crv(secp521r1) ->
	<<"P-521">>;
parameters_to_crv(Parameters) when is_tuple(Parameters) ->
	parameters_to_crv(pubkey_cert_records:namedCurves(Parameters)).

%% @private
public_key_to_x_y(<< 16#04, X:32/binary, Y:32/binary >>) ->
	{X, Y};
public_key_to_x_y(<< 16#04, X:48/binary, Y:48/binary >>) ->
	{X, Y};
public_key_to_x_y(<< 16#04, X:64/binary, Y:64/binary >>) ->
	{X, Y}.
