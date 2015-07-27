%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  21 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa).

%% API
-export([constant_time_compare/2]).

%%====================================================================
%% API functions
%%====================================================================

constant_time_compare(<<>>, _) ->
	false;
constant_time_compare(_, <<>>) ->
	false;
constant_time_compare(A, B)
		when is_binary(A) andalso is_binary(B)
		andalso (byte_size(A) =/= byte_size(B)) ->
	false;
constant_time_compare(A, B)
		when is_binary(A) andalso is_binary(B)
		andalso (byte_size(A) =:= byte_size(B)) ->
	constant_time_compare(A, B, 0).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
constant_time_compare(<< AH, AT/binary >>, << BH, BT/binary >>, R) ->
	constant_time_compare(AT, BT, R bor (BH bxor AH));
constant_time_compare(<<>>, <<>>, R) ->
	R =:= 0.
