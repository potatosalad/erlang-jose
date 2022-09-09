%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  21 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------

-ifndef(JOSE_JWK_HRL).

-record(jose_jwk, {
	keys   = undefined :: undefined | {module(), any()},
	kty    = undefined :: undefined | {module(), any()},
	fields = #{}       :: map()
}).

-define(JOSE_JWK_HRL, 1).

-endif.
