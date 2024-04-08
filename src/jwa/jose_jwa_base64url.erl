%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc RFC 4648, Section 5: https://tools.ietf.org/html/rfc4648#section-5
%%%
%%% @end
%%% Created :  29 Jul 2019 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_base64url).

%% API
-export([decode/1]).
-export([encode/1]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

decode(Input) ->
    jose_base64url:'decode!'(Input).

encode(Input) ->
    jose_base64url:encode(Input, #{padding => false}).
