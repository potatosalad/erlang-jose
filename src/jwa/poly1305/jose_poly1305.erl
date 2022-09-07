%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_poly1305).

-include("jose_support.hrl").

-behaviour(jose_support).

%% Types
-type message() :: binary().
-type poly1305_one_time_key() :: <<_:256>>.
-type poly1305_tag() :: <<_:128>>.

-export_type([
	message/0,
    poly1305_one_time_key/0,
    poly1305_tag/0
]).

-callback poly1305_mac(Message, OneTimeKey) -> Tag when
	Message :: jose_poly1305:message(),
    OneTimeKey :: jose_poly1305:poly1305_one_time_key(),
    Tag :: jose_poly1305:poly1305_tag().

-optional_callbacks([
	poly1305_mac/2
]).

%% jose_support callbacks
-export([
	support_info/0,
	support_check/3
]).
%% jose_poly1305 callbacks
-export([
	poly1305_mac/2
]).

%% Macros
-define(TV_Message(), <<"abcdefghijklmnopqrstuvwxyz012345">>). % 2 x 128-bit AES blocks
-define(TV_POLY1305_OneTimeKey(), ?b16d("0101010101010101010101010101010101010101010101010101010101010101")).
-define(TV_POLY1305_Tag(), ?b16d("dd2d06b9037d9e7ab9ec5cc55bec11c5")).

%%====================================================================
%% jose_support callbacks
%%====================================================================

-spec support_info() -> jose_support:info().
support_info() ->
	#{
		stateful => [],
		callbacks => [
			{{poly1305_mac, 2}, []}
		]
	}.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) -> jose_support:support_check_result().
support_check(Module, poly1305_mac, 2) ->
	Message = ?TV_Message(),
    OneTimeKey = ?TV_POLY1305_OneTimeKey(),
    Tag = ?TV_POLY1305_Tag(),
	?expect(Tag, Module, poly1305_mac, [Message, OneTimeKey]).

%%====================================================================
%% jose_poly1305 callbacks
%%====================================================================

-spec poly1305_mac(Message, OneTimeKey) -> Tag when
	Message :: jose_poly1305:message(),
    OneTimeKey :: jose_poly1305:poly1305_one_time_key(),
    Tag :: jose_poly1305:poly1305_tag().
poly1305_mac(Message, OneTimeKey) when bit_size(OneTimeKey) =:= 256 ->
	?resolve([Message, OneTimeKey]).
