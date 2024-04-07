%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305
%%% See https://tools.ietf.org/html/draft-irtf-cfrg-xchacha
%%% @end
%%% Created :  14 Sep 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_hchacha20).

-behaviour(jose_provider).
-behaviour(jose_hchacha20).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_hchacha20 callbacks
-export([
    hchacha20_subkey/2
]).
%% API
-export([hash/2]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_hchacha20,
        priority => low,
        requirements => [
            {app, crypto},
            crypto,
            {app, jose},
            jose_jwa_chacha20
        ]
    }.

%%====================================================================
%% jose_chacha20 callbacks
%%====================================================================

-spec hchacha20_subkey(Nonce, Key) -> Subkey when
    Nonce :: jose_hchacha20:hchacha20_nonce(),
    Key :: jose_hchacha20:hchacha20_key(),
    Subkey :: jose_hchacha20:hchacha20_subkey().
hchacha20_subkey(Nonce, Key) when
    bit_size(Nonce) =:= 128 andalso
        bit_size(Key) =:= 256
->
    hash(Key, Nonce).

%%====================================================================
%% API functions
%%====================================================================

hash(Key, Nonce) when
    is_binary(Key) andalso
        bit_size(Key) =:= 256 andalso
        is_binary(Nonce) andalso
        bit_size(Nonce) =:= 128
->
    State = <<
        "expand 32-byte k",
        Key:256/bitstring,
        Nonce:128/bitstring
    >>,
    WS0 = list_to_tuple([Word || <<Word:32/unsigned-little-integer-unit:1>> <= State]),
    WS1 = rounds(WS0, 10),
    serialize(WS1).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
inner_block(State0) when
    is_tuple(State0) andalso
        tuple_size(State0) =:= 16
->
    State1 = jose_jwa_chacha20:column_round(State0),
    State2 = jose_jwa_chacha20:diagonal_round(State1),
    State2.

%% @private
rounds(S, 0) ->
    S;
rounds(S, N) when
    is_integer(N) andalso
        N > 0
->
    rounds(inner_block(S), N - 1).

%% @private
serialize({Z00, Z01, Z02, Z03, _Z04, _Z05, _Z06, _Z07, _Z08, _Z09, _Z10, _Z11, Z12, Z13, Z14, Z15}) ->
    <<
        Z00:32/unsigned-little-integer-unit:1,
        Z01:32/unsigned-little-integer-unit:1,
        Z02:32/unsigned-little-integer-unit:1,
        Z03:32/unsigned-little-integer-unit:1,
        Z12:32/unsigned-little-integer-unit:1,
        Z13:32/unsigned-little-integer-unit:1,
        Z14:32/unsigned-little-integer-unit:1,
        Z15:32/unsigned-little-integer-unit:1
    >>.
