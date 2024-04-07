%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  16 Mar 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_use_sig).

-callback sign(Message, Options, KTY) -> Signature when
    Message :: iodata(),
    Options :: any(),
    KTY :: any(),
    Signature :: iodata().
-callback signer(KTY, Fields) -> JWSMap when
    KTY :: any(),
    Fields :: map(),
    JWSMap :: map().
-callback verifier(KTY, Fields) -> [JWSALG] when
    KTY :: any(),
    Fields :: map(),
    JWSALG :: iodata().
-callback verify(Message, Options, Signature, KTY) -> boolean() when
    Message :: iodata(),
    Options :: any(),
    Signature :: iodata(),
    KTY :: any().

%%====================================================================
%% API functions
%%====================================================================

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
