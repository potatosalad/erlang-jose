%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_xchacha20_crypto).

-behaviour(jose_provider).
-behaviour(jose_xchacha20).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_xchacha20 callbacks
-export([
    xchacha20_exor/4,
    xchacha20_stream_init/3,
    xchacha20_stream_exor/2,
    xchacha20_stream_final/1
]).

%% Records
-record(jose_xchacha20_crypto, {
    crypto_state = undefined :: undefined | crypto:crypto_state()
}).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_xchacha20,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%====================================================================
%% jose_xchacha20 callbacks
%%====================================================================

-spec xchacha20_exor(Input, Count, Nonce, Key) -> Output when
    Input :: jose_xchacha20:input(),
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Output :: jose_xchacha20:output().
xchacha20_exor(Input, Count, Nonce, Key) when
    is_binary(Input) andalso
        bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    IV = make_iv(Count, Nonce),
    crypto:crypto_one_time(xchacha20, Key, IV, Input, true).

-spec xchacha20_stream_init(Count, Nonce, Key) -> Xchacha20State when
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Xchacha20State :: jose_xchacha20:xchacha20_state().
xchacha20_stream_init(Count, Nonce, Key) when
    bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 96 andalso
        bit_size(Key) =:= 256
->
    IV = make_iv(Count, Nonce),
    #jose_xchacha20_crypto{crypto_state = crypto:crypto_init(xchacha20, Key, IV, true)}.

-spec xchacha20_stream_exor(Xchacha20State, Input) -> {NewXchacha20State, Output} when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Input :: jose_xchacha20:input(),
    NewXchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_exor(State = #jose_xchacha20_crypto{}, Input = <<>>) ->
    {State, Input};
xchacha20_stream_exor(State = #jose_xchacha20_crypto{crypto_state = CryptoState}, Input) when byte_size(Input) > 0 ->
    Output = crypto:crypto_update(CryptoState, Input),
    {State, Output}.

-spec xchacha20_stream_final(Xchacha20State) -> Output when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_final(_State = #jose_xchacha20_crypto{crypto_state = CryptoState}) ->
    crypto:crypto_final(CryptoState).

%%%-------------------------------------------------------------------
%%% Internal Xchacha20 functions
%%%-------------------------------------------------------------------

%% @private
-spec make_iv(Count, Nonce) -> IV when
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    IV :: <<_:256>>.
make_iv(Count, Nonce) when
    bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 192
->
    <<Count:32/bits, Nonce:192/bits>>.
