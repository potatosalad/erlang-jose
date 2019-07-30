%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jws_alg_eddsa_props).

-include_lib("public_key/include/public_key.hrl").

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

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
		<<"Ed25519">>,
		<<"Ed25519ph">>,
		<<"Ed448">>,
		<<"Ed448ph">>,
		<<"EdDSA">>
	]).

opt_map() ->
	oneof([
		#{},
		#{ <<"b64">> => true  },
		#{ <<"b64">> => false }
	]).

okp_type(<<"EdDSA">>, PK) when byte_size(PK) =:= 32 ->
	oneof([
		'Ed25519',
		'Ed25519ph'
	]);
okp_type(<<"EdDSA">>, PK) when byte_size(PK) =:= 57 ->
	oneof([
		'Ed448',
		'Ed448ph'
	]);
okp_type(<<"Ed25519">>, PK) when byte_size(PK) =:= 32 ->
	'Ed25519';
okp_type(<<"Ed25519ph">>, PK) when byte_size(PK) =:= 32 ->
	'Ed25519ph';
okp_type(<<"Ed448">>, PK) when byte_size(PK) =:= 57 ->
	'Ed448';
okp_type(<<"Ed448ph">>, PK) when byte_size(PK) =:= 57 ->
	'Ed448ph'.

ed_curve_module(<< "EdDSA" >>) ->
	oneof([
		jose_curve25519,
		jose_curve448
	]);
ed_curve_module(<< "Ed25519", _/binary >>) ->
	jose_curve25519;
ed_curve_module(<< "Ed448", _/binary >>) ->
	jose_curve448.

eddsa_secret(jose_curve25519) ->
	binary(32);
eddsa_secret(jose_curve448) ->
	binary(57).

eddsa_keypair(EdCurveModule, Secret) ->
	{PK, SK} = EdCurveModule:eddsa_keypair(Secret),
	{SK, PK}.

eddsa_keypair_gen(ALG) ->
	?LET({EdCurveModule, Secret},
		?LET(EdCurveModule,
			ed_curve_module(ALG),
			{EdCurveModule, eddsa_secret(EdCurveModule)}),
		eddsa_keypair(EdCurveModule, Secret)).

jwk_jws_maps() ->
	?LET({{SK, PK}, Opts, OKP, ALG},
		?LET({{SK, PK}, ALG},
			?LET(ALG,
				alg(),
				{eddsa_keypair_gen(ALG), ALG}),
			{{SK, PK}, opt_map(), okp_type(ALG, PK), ALG}),
		begin
			JWKSigner = jose_jwk:from_okp({OKP, SK}),
			JWKVerifier = jose_jwk:from_okp({OKP, PK}),
			JWSMap = maps:merge(Opts, #{
				<<"alg">> => ALG
			}),
			{JWKSigner, JWKVerifier, JWSMap}
		end).

jwk_jws_gen() ->
	?LET({JWKSigner, JWKVerifier, JWSMap},
		jwk_jws_maps(),
		{JWKSigner, JWKVerifier, jose_jws:from_map(JWSMap)}).

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
	?FORALL({{JWKSigner, JWKVerifier, JWS}, Message},
		{jwk_jws_gen(), binary()},
		begin
			Signed = jose_jws:sign(JWKSigner, Message, JWS),
			CompactSigned = jose_jws:compact(Signed),
			{true, Message, JWS} =:= jose_jws:verify(JWKVerifier, Signed)
			andalso {true, Message, JWS} =:= jose_jws:verify(JWKVerifier, CompactSigned)
		end).
