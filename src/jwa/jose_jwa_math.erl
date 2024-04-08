%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_math).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

%% Public API
-export([
    expmod/3,
    exprem/3,
    intpow/2,
    mod/2,
    mod_pow/3
]).

%% Private API
-export([
    expmod_fast/3,
    expmod_slow/3,
    exprem_fast/3,
    exprem_slow/3
]).

%%%=============================================================================
%%% Public API
%%%=============================================================================

-spec expmod(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
expmod(B, E, M) ->
    expmod_fast(B, E, M).

-spec exprem(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
exprem(B, E, M) ->
    exprem_fast(B, E, M).

-spec intpow(Base, Exponent) -> Result when Base :: integer(), Exponent :: non_neg_integer(), Result :: integer().
intpow(B, E) when is_integer(B) andalso is_integer(E) andalso E >= 0 ->
    case B of
        0 ->
            0;
        1 ->
            1;
        2 ->
            1 bsl E;
        _ ->
            intpow(B, E, 1)
    end.

-spec mod(Base, Modulus) -> Result when Base :: integer(), Modulus :: integer(), Result :: integer().
mod(B, M) ->
    (B rem M + M) rem M.

-spec mod_pow(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
mod_pow(B, E, M) ->
    Bytes = crypto:mod_pow(B, E, M),
    Size = byte_size(Bytes),
    <<((crypto:bytes_to_integer(Bytes) + M) rem M):Size/signed-big-integer-unit:8>>.

%%%=============================================================================
%%% Private API
%%%=============================================================================

% @private
-spec expmod_fast(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
expmod_fast(B, E, M) ->
    (exprem_fast(B, E, M) + M) rem M.

% @private
-spec expmod_slow(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
expmod_slow(B, E, M) ->
    (exprem_slow(B, E, M) + M) rem M.

% @private
-spec exprem_fast(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
exprem_fast(B, E, M) when B < 0 andalso E rem 2 =/= 0 ->
    -exprem_fast(abs(B), E, M);
exprem_fast(B, E, M) when B < 0 ->
    exprem_fast(abs(B), E, M);
exprem_fast(B, E, M) ->
    crypto:bytes_to_integer(crypto:mod_pow(B, E, M)).

%% @private
-spec exprem_slow(Base, Exponent, Modulus) -> Result when
    Base :: integer(), Exponent :: integer(), Modulus :: integer(), Result :: integer().
exprem_slow(_B, 0, _M) ->
    1;
exprem_slow(B, E, M) ->
    T0 = exprem_slow(B, E div 2, M),
    T = (T0 * T0) rem M,
    case E rem 2 of
        0 ->
            T band M;
        _ ->
            (T * B) rem M
    end.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------

%% @private
-spec intpow(Base, Exponent, Remainder) -> Result when
    Base :: integer(), Exponent :: non_neg_integer(), Remainder :: integer(), Result :: integer().
intpow(B, E, R) when (E rem 2) =:= 0 ->
    intpow(B * B, E div 2, R);
intpow(B, E, R) when (E div 2) =:= 0 ->
    B * R;
intpow(B, E, R) ->
    intpow(B * B, E div 2, B * R).
