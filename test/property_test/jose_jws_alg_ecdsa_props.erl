%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jws_alg_ecdsa_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% % -compile(export_all).

base64url_binary() ->
	?LET(Binary,
		binary(),
		jose_jwa_base64url:encode(Binary)).

binary_map() ->
	?LET(List,
		list({base64url_binary(), base64url_binary()}),
		maps:from_list(List)).

alg() ->
	oneof([
		<<"ES256">>,
		<<"ES384">>,
		<<"ES512">>
	]).

alg(secp256r1) -> return(<<"ES256">>);
alg(secp384r1) -> return(<<"ES384">>);
alg(secp521r1) -> return(<<"ES512">>).

opt_map() ->
	oneof([
		#{},
		#{ <<"b64">> => true  },
		#{ <<"b64">> => false }
	]).

ec_curve() ->
	oneof([
		secp256r1,
		secp384r1,
		secp521r1
	]).

ec_keypair(CurveId) ->
	ECPrivateKey = #'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0} = public_key:generate_key({namedCurve, pubkey_cert_records:namedCurves(CurveId)}),
	Octets = case Octets0 of
		{_, Octets1} ->
			Octets1;
		_ ->
			Octets0
	end,
	ECPoint = #'ECPoint'{point=Octets},
	ECPublicKey = {ECPoint, ECParameters},
	{ECPrivateKey, ECPublicKey}.

jwk_jws_maps() ->
	?LET({CurveId, ALG, {PrivateKey, PublicKey}, Opts},
		?LET(CurveId,
			ec_curve(),
			{CurveId, alg(CurveId), ec_keypair(CurveId), opt_map()}),
		begin
			JWKSigner = jose_jwk:from_key(PrivateKey),
			JWKVerifier = jose_jwk:from_key(PublicKey),
			JWSMap = maps:merge(Opts, #{
				<<"alg">> => ALG
			}),
			{CurveId, {JWKSigner, JWKVerifier}, JWSMap}
		end).

jwk_jws_gen() ->
	?LET({CurveId, JWKs, JWSMap},
		jwk_jws_maps(),
		{CurveId, JWKs, jose_jws:from_map(JWSMap)}).

prop_from_map_and_to_map() ->
	?FORALL(JWSMap,
		?LET({ALG, Opts, Extras},
			{alg(), opt_map(), binary_map()},
			maps:merge(maps:merge(Extras, Opts), #{ <<"alg">> => ALG })),
		begin
			JWS = jose_jws:from_map(JWSMap),
			JWSMap =:= element(2, jose_jws:to_map(JWS))
		end).

prop_sign_and_verify() ->
	?FORALL({{_CurveId, {JWKSigner, JWKVerifier}, JWS}, Message},
		{jwk_jws_gen(), binary()},
		begin
			Signed = jose_jws:sign(JWKSigner, Message, JWS),
			CompactSigned = jose_jws:compact(Signed),
			{true, Message, JWS} =:= jose_jws:verify(JWKVerifier, Signed)
			andalso {true, Message, JWS} =:= jose_jws:verify(JWKVerifier, CompactSigned)
		end).

%% RFC 7518 3.4 fixes the ECDSA JWS Signature to the octet sequence R || S,
%% each half zero-padded to the byte length of the curve order.  Prepending
%% (or stripping) leading zero octets on both halves keeps the encoded
%% integers identical, so a verifier that splits on byte_size div 2 accepts an
%% unbounded family of distinct signatures for the same key and payload.
%% See GHSA-44hw-rpw9-mwg4.
prop_verify_rejects_non_canonical_signature_length() ->
	?FORALL({{_CurveId, {JWKSigner, JWKVerifier}, JWS}, Message, Pad},
		{jwk_jws_gen(), binary(), integer(1, 8)},
		begin
			{Modules, SignedMap = #{ <<"signature">> := SignatureB64 }} = jose_jws:sign(JWKSigner, Message, JWS),
			Signature = jose_jwa_base64url:decode(SignatureB64),
			HalfSize = byte_size(Signature) div 2,
			<< R:HalfSize/binary, S:HalfSize/binary >> = Signature,
			Zeros = binary:copy(<< 0 >>, Pad),
			Repadded = << Zeros/binary, R/binary, Zeros/binary, S/binary >>,
			Malleable = {Modules, SignedMap#{ <<"signature">> => jose_jwa_base64url:encode(Repadded) }},
			{true, Message, JWS} =:= jose_jws:verify(JWKVerifier, {Modules, SignedMap})
			andalso false =:= element(1, jose_jws:verify(JWKVerifier, Malleable))
		end).
