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
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_hchacha20_crypto).

-behaviour(jose_provider).
-behaviour(jose_hchacha20).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_hchacha20 callbacks
-export([
    hchacha20_subkey/2
]).
%% Internal API
-export([
    hchacha20/2
]).

%%%=============================================================================
%%% jose_provider callbacks
%%%=============================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_hchacha20,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%%=============================================================================
%%% jose_chacha20 callbacks
%%%=============================================================================

-spec hchacha20_subkey(Nonce, Key) -> Subkey when
    Nonce :: jose_hchacha20:hchacha20_nonce(),
    Key :: jose_hchacha20:hchacha20_key(),
    Subkey :: jose_hchacha20:hchacha20_subkey().
hchacha20_subkey(Nonce, Key) when
    bit_size(Nonce) =:= 128 andalso
        bit_size(Key) =:= 256
->
    hchacha20(Key, Nonce).

%%%-----------------------------------------------------------------------------
%%% Internal HChaCha20 functions
%%%-----------------------------------------------------------------------------

%% @doc Short example of why this works: `HChaCha20 = ChaCha20 - State0'
%%
%% Longer example of why this works:
%%
%% ```
%% K  = 256-bit key
%% C  = 32-bit counter
%% N  = 96-bit nonce
%% X  = 128-bit nonce
%% || = concatenation
%% ++ = 32-bit word little endian addition
%% -- = 32-bit word little endian subtraction
%%
%% ChaCha20(K, C, N) =
%%     State0 = "expand 32-byte k" || K || C || N
%%     State1 = Rounds(State0, 10)
%%     State2 = State1 ++ State2
%%     return State2
%%
%% HChaCha20(K, X) =
%%     State0 = "expand 32-byte k" || K || X
%%     State1 = Rounds(State0, 10)
%%     return FirstBits(State1, 128) || LastBits(State1, 128)
%%
%% # Let's rewrite HChaCha20 to use ChaCha20 with State0 subtraction:
%%
%% HChaCha20(K, X) =
%%     C = FirstBits(X, 32)
%%     N = LastBits(X, 96)
%%     State0 = "expand 32-byte k" || K || X
%%     State2 = ChaCha20(K, C, N)
%%     State1 = State2 -- State0
%%     return FirstBits(State1, 128) || LastBits(State1, 128)
%%
%% # Let's further reduce to not use K and use a Mask for blinding:
%%
%% HChaCha20(K, X) =
%%     Mask = CSPRNG(512)
%%     C = FirstBits(X, 32)
%%     N = LastBits(X, 96)
%%     KeyStream = ChaCha20(K, C, N) ^ Mask
%%     State2 = (FirstBits(KeyStream, 128) || LastBits(KeyStream, 128)) ^
%%         (FirstBits(Mask, 128) || LastBits(Mask, 128))
%%     State0 = "expand 32-byte k" || X
%%     State1 = State2 -- State0
%%     return State1
%% '''
%%
%% See: [https://tools.ietf.org/html/rfc7539#section-2.3]
%% See: [https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03#section-2.2]
-spec hchacha20(Key, Nonce) -> Subkey when
    Key :: jose_hchacha20:hchacha20_key(),
    Nonce :: jose_hchacha20:hchacha20_nonce(),
    Subkey :: jose_hchacha20:hchacha20_subkey().
hchacha20(<<Key:256/bitstring>>, <<Nonce:128/bitstring>>) ->
    %% ChaCha20 has an internal blocksize of 512-bits (64-bytes).
    %% Let's use a Mask of random 64-bytes to blind the intermediate keystream.
    Mask = <<MaskH:128/bits, _:256/bits, MaskT:128/bits>> = crypto:strong_rand_bytes(64),
    <<State2H:128/bits, _:256/bits, State2T:128/bits>> = crypto:crypto_one_time(chacha20, Key, Nonce, Mask, true),
    <<
        X00:32/unsigned-little-integer-unit:1,
        X01:32/unsigned-little-integer-unit:1,
        X02:32/unsigned-little-integer-unit:1,
        X03:32/unsigned-little-integer-unit:1,
        X12:32/unsigned-little-integer-unit:1,
        X13:32/unsigned-little-integer-unit:1,
        X14:32/unsigned-little-integer-unit:1,
        X15:32/unsigned-little-integer-unit:1
    >> = crypto:exor(<<MaskH:128/bits, MaskT:128/bits>>, <<State2H:128/bits, State2T:128/bits>>),
    %% The final step of ChaCha20 is `State2 = State0 + State1', so let's
    %% recover `State1' with subtraction: `State1 = State2 - State0'
    <<
        Y00:32/unsigned-little-integer-unit:1,
        Y01:32/unsigned-little-integer-unit:1,
        Y02:32/unsigned-little-integer-unit:1,
        Y03:32/unsigned-little-integer-unit:1,
        Y12:32/unsigned-little-integer-unit:1,
        Y13:32/unsigned-little-integer-unit:1,
        Y14:32/unsigned-little-integer-unit:1,
        Y15:32/unsigned-little-integer-unit:1
    >> = <<"expand 32-byte k", Nonce:128/bits>>,
    <<
        (X00 - Y00):32/unsigned-little-integer-unit:1,
        (X01 - Y01):32/unsigned-little-integer-unit:1,
        (X02 - Y02):32/unsigned-little-integer-unit:1,
        (X03 - Y03):32/unsigned-little-integer-unit:1,
        (X12 - Y12):32/unsigned-little-integer-unit:1,
        (X13 - Y13):32/unsigned-little-integer-unit:1,
        (X14 - Y14):32/unsigned-little-integer-unit:1,
        (X15 - Y15):32/unsigned-little-integer-unit:1
    >>.
