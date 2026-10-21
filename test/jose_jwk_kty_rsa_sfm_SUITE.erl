%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @doc
%%% Regression tests for the (n, e, d) -> CRT prime recovery performed
%%% by jose_jwk_kty_rsa:from_map/1 when an RSA private JWK omits every
%%% CRT parameter.  See GHSA-3m45-vrpj-xmrq: a JWK holding integers
%%% that cannot come from a real RSA key used to keep the recovery
%%% search running until an internal 1000 ms watchdog killed it, and an
%%% oversized modulus could run far past that watchdog because a single
%%% crypto:mod_pow/3 NIF cannot be interrupted.
%%% @end
%%%-------------------------------------------------------------------
-module(jose_jwk_kty_rsa_sfm_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ct.
-export([all/0]).

%% Tests.
-export([sfm_key_still_recovers_crt_parameters/1]).
-export([sfm_prime_modulus_is_rejected_quickly/1]).
-export([sfm_consistent_prime_modulus_is_rejected_quickly/1]).
-export([sfm_oversized_modulus_is_rejected_quickly/1]).
-export([sfm_structurally_invalid_key_is_rejected_quickly/1]).
-export([sfm_large_consistent_primes_have_a_work_budget/1]).
-export([sfm_large_exponents_have_a_work_budget/1]).
-export([sfm_recovered_factors_validate_exponents/1]).
-export([sfm_small_base_residue_key_still_imports/1]).
-export([sfm_large_valid_keys_still_import_and_operate/1]).

%% Every rejection must land before the 1000 ms watchdog, which is the
%% whole point: reaching it means the search ran.  Kept just under the
%% watchdog rather than at the measured cost (14 - 120 ms for the most
%% expensive case) so that a slow or loaded machine cannot flake.
-define(REJECT_TIMEOUT_MS, 900).

all() ->
	[
		sfm_key_still_recovers_crt_parameters,
		sfm_prime_modulus_is_rejected_quickly,
		sfm_consistent_prime_modulus_is_rejected_quickly,
		sfm_oversized_modulus_is_rejected_quickly,
		sfm_structurally_invalid_key_is_rejected_quickly,
		sfm_large_consistent_primes_have_a_work_budget,
		sfm_large_exponents_have_a_work_budget,
		sfm_recovered_factors_validate_exponents,
		sfm_small_base_residue_key_still_imports,
		sfm_large_valid_keys_still_import_and_operate
	].

%%====================================================================
%% Tests
%%====================================================================

%% A genuine private key that omits p, q, dp, dq and qi must still be
%% recovered, byte for byte, into the same key as the full CRT JWK.
sfm_key_still_recovers_crt_parameters(_Config) ->
	PrivateKey = #'RSAPrivateKey'{} = public_key:generate_key({rsa, 1024, 65537}),
	CRTMap = #{
		<<"kty">> => <<"RSA">>,
		<<"n">> => b64(PrivateKey#'RSAPrivateKey'.modulus),
		<<"e">> => b64(PrivateKey#'RSAPrivateKey'.publicExponent),
		<<"d">> => b64(PrivateKey#'RSAPrivateKey'.privateExponent),
		<<"p">> => b64(PrivateKey#'RSAPrivateKey'.prime1),
		<<"q">> => b64(PrivateKey#'RSAPrivateKey'.prime2),
		<<"dp">> => b64(PrivateKey#'RSAPrivateKey'.exponent1),
		<<"dq">> => b64(PrivateKey#'RSAPrivateKey'.exponent2),
		<<"qi">> => b64(PrivateKey#'RSAPrivateKey'.coefficient)
	},
	SFMMap = maps:without([<<"p">>, <<"q">>, <<"dp">>, <<"dq">>, <<"qi">>], CRTMap),
	{CRTKey, #{}} = jose_jwk_kty_rsa:from_map(CRTMap),
	{SFMKey, #{}} = jose_jwk_kty_rsa:from_map(SFMMap),
	CRTKey = SFMKey,
	PrivateKey = SFMKey,
	ok.

%% GHSA-3m45-vrpj-xmrq proof of concept: n is prime, e = 65537, d = 3.
%% The primes can never be recovered, so the key has to be rejected
%% without running the search.
sfm_prime_modulus_is_rejected_quickly(_Config) ->
	Prime = prime_1024(),
	rejects_quickly(#{
		<<"kty">> => <<"RSA">>,
		<<"n">> => b64(Prime),
		<<"e">> => b64(65537),
		<<"d">> => b64(3)
	}).

%% Harder variant: n is prime and (n, e, d) is self consistent, so
%% 2^(ed-1) = 1 (mod n) holds and only the bound on the search base
%% stops the loop.
sfm_consistent_prime_modulus_is_rejected_quickly(_Config) ->
	Prime = prime_1024(),
	{E, D} = consistent_ed(Prime, 3),
	1 = jose_jwa_math:expmod(2, D * E - 1, Prime),
	rejects_quickly(#{
		<<"kty">> => <<"RSA">>,
		<<"n">> => b64(Prime),
		<<"e">> => b64(E),
		<<"d">> => b64(D)
	}).

%% An oversized modulus makes one modular exponentiation cost more than
%% the whole watchdog window, so it has to be rejected before any
%% modular arithmetic happens.
sfm_oversized_modulus_is_rejected_quickly(_Config) ->
	rejects_quickly(#{
		<<"kty">> => <<"RSA">>,
		<<"n">> => b64(odd_of(16384)),
		<<"e">> => b64(odd_of(16384)),
		<<"d">> => b64(odd_of(16384))
	}).

%% e = 2 and d = 1 make d*e-1 odd, which used to spin the search
%% forever without doing any work at all.
sfm_structurally_invalid_key_is_rejected_quickly(_Config) ->
	Prime = prime_1024(),
	rejects_quickly(#{
		<<"kty">> => <<"RSA">>,
		<<"n">> => b64(Prime),
		<<"e">> => b64(2),
		<<"d">> => b64(1)
	}).

%% Public imports: the Proth prime has a very long squaring chain; the
%% Mersenne primes have long odd exponents. Both exhausted the old search.
%% 900 ms leaves scheduler/NIF tolerance above the 200/500 ms work deadlines,
%% while failing if the import reaches the inherited 1000 ms watchdog.
sfm_large_consistent_primes_have_a_work_budget(_Config) ->
	Primes = [(1 bsl 4423) - 1,
		549755814211 * (1 bsl 2008) + 1, (1 bsl 8191) - 1],
	lists:foreach(fun(N) ->
		{E, D} = consistent_ed(N, 65537),
		rejects_public_quickly(sfm_map(N, E, D))
	end, Primes).

sfm_large_exponents_have_a_work_budget(_Config) ->
	lists:foreach(fun(N) ->
		rejects_public_quickly(sfm_map(N, N - 2, N - 2))
	end, [(1 bsl 8192) - 1, (1 bsl 8191) - 1]).

%% Random gcd recovery must not accept factors with incompatible d/e or
%% a repeated prime (whose CRT coefficient has no multiplicative inverse).
sfm_recovered_factors_validate_exponents(_Config) ->
	rejects_public_quickly(sfm_map(21, 5, 3)),
	rejects_public_quickly(sfm_map(9, 5, 5)),
	{_, #{}} = jose_jwk_kty_rsa:from_map(sfm_map(21, 5, 5)),
	ok.

%% These two primes have matching characters for all 50 old even bases.
%% The original unbounded search imports the key; the inherited finite
%% deterministic search rejects it. Pair public recovery with real use.
sfm_small_base_residue_key_still_imports(_Config) ->
	P = 16#965afc7ec3d0075fd7caffc21ca876053a86577b73632df5c8eb17bb18880e83855ac6b9396594fc94f09a1a609aae8cc81d8a70b6f33df18593535e53209fbf,
	Q = 16#95d8b95692268bdee09ace199a4aa89e12a0aed4e9b63f852e1938332d4ca10691409b2b41133c89b2be86b9c6ea82e69ed7ff58f8d93d8698e2a8c4c20f6acf,
	E = 65537,
	L = ((P - 1) * (Q - 1)) div gcd(P - 1, Q - 1),
	D = mod_inverse(E, L),
	Map = sfm_map(P * Q, E, D),
	lists:foreach(fun(_) -> import_and_operate(Map) end, lists:seq(1, 16)).

sfm_large_valid_keys_still_import_and_operate(_Config) ->
	lists:foreach(fun(Bits) ->
		Key = public_key:generate_key({rsa, Bits, 65537}),
		CRT = jose_jwk_kty_rsa:to_map(Key, #{}),
		SFM = maps:without([<<"p">>, <<"q">>, <<"dp">>, <<"dq">>, <<"qi">>], CRT),
		Recovered = import_and_operate(SFM),
		Recovered = import_and_operate(CRT),
		Key = Recovered
	end, [2048, 4096, 8192]).

%% @private
import_and_operate(Map) ->
	{ok, _} = application:ensure_all_started(jose),
	{US, JWK} = timer:tc(fun() -> jose_jwk:from_map(Map) end),
	Public = jose_jwk:to_public(JWK),
	Message = <<"recovered RSA key control">>,
	Signed = jose_jws:sign(JWK, Message, #{<<"alg">> => <<"RS256">>}),
	{true, Message, _} = jose_jws:verify(Public, Signed),
	Encrypted = jose_jwe:block_encrypt(Public, Message,
		#{<<"alg">> => <<"RSA-OAEP">>, <<"enc">> => <<"A256GCM">>}),
	{Message, _} = jose_jwe:block_decrypt(JWK, Encrypted),
	{_, Key} = jose_jwk:to_key(JWK),
	ct:pal("valid RSA modulus_bytes=~p recovered/imported in ~p us", [byte_size(binary:encode_unsigned(Key#'RSAPrivateKey'.modulus)), US]),
	Key.

%% @private
rejects_public_quickly(Map) ->
	{US, Result} = timer:tc(fun() ->
		try jose_jwk:from_map(Map) of
			Other -> {returned, Other}
		catch
			Class:Reason -> {Class, Reason}
		end
	end),
	{error, {badarg, [#'RSAPrivateKey'{}]}} = Result,
	ct:pal("public import rejected ~p-byte JWK in ~p us", [byte_size(jose:encode(Map)), US]),
	true = (US < ?REJECT_TIMEOUT_MS * 1000),
	ok.

%% @private
sfm_map(N, E, D) ->
	#{<<"kty">> => <<"RSA">>, <<"n">> => b64(N), <<"e">> => b64(E), <<"d">> => b64(D)}.

%% @private
gcd(A, 0) -> A;
gcd(A, B) -> gcd(B, A rem B).

%%====================================================================
%% Internal functions
%%====================================================================

%% @private
b64(Integer) when is_integer(Integer) ->
	jose_jwa_base64url:encode(binary:encode_unsigned(Integer)).

%% @private
consistent_ed(N, E) ->
	case mod_inverse(E, N - 1) of
		D when is_integer(D) andalso D > 2 ->
			{E, D};
		_ ->
			consistent_ed(N, E + 2)
	end.

%% @private
egcd(0, B) ->
	{B, 0, 1};
egcd(A, B) ->
	{G, Y, X} = egcd(B rem A, A),
	{G, X - (B div A) * Y, Y}.

%% @private
mod_inverse(A, M) ->
	case egcd(A, M) of
		{1, X, _Y} ->
			jose_jwa_math:mod(X, M);
		_ ->
			no_inverse
	end.

%% @private
odd_of(Bits) ->
	((1 bsl (Bits - 1)) bor 1) + 2 * rand:uniform(1 bsl (Bits - 2)).

%% @private
prime_1024() ->
	PrivateKey = #'RSAPrivateKey'{} = public_key:generate_key({rsa, 2048, 65537}),
	PrivateKey#'RSAPrivateKey'.prime1.

%% @private
rejects_quickly(Map) ->
	{Elapsed, Result} = timer:tc(fun() ->
		try jose_jwk_kty_rsa:from_map(Map) of
			Other -> {returned, Other}
		catch
			Class:Reason -> {Class, Reason}
		end
	end),
	{error, {badarg, [#'RSAPrivateKey'{}]}} = Result,
	ct:pal("rejected in ~p us", [Elapsed]),
	true = (Elapsed < ?REJECT_TIMEOUT_MS * 1000),
	ok.
