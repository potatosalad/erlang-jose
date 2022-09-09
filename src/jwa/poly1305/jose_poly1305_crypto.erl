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
-module(jose_poly1305_crypto).

-behaviour(jose_provider).
-behaviour(jose_poly1305).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_poly1305 callbacks
-export([
    poly1305_mac/2
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_poly1305,
        priority => high,
        requirements => [
            {app, crypto},
            crypto
        ]
    }.

%%====================================================================
%% jose_poly1305 callbacks
%%====================================================================

-spec poly1305_mac(Message, OneTimeKey) -> Tag when
    Message :: jose_poly1305:message(),
    OneTimeKey :: jose_poly1305:poly1305_one_time_key(),
    Tag :: jose_poly1305:poly1305_tag().
poly1305_mac(Message, OneTimeKey) when bit_size(OneTimeKey) =:= 256 ->
    crypto:mac(poly1305, OneTimeKey, Message).
