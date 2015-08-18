%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  18 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_oct).

%% API
-export([from_binary/1]).

%%====================================================================
%% API functions
%%====================================================================

from_binary(OCTBinary) when is_binary(OCTBinary) ->
	jose_jwk_kty:from_oct(OCTBinary).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
