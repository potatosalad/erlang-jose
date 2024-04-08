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
%%% Created :  21 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwk_set).

-include("jose_jwk.hrl").

%% API
-export([from_map/1]).
-export([to_map/2]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

from_map(F = #{<<"keys">> := Keys}) ->
    {[jose_jwk:from_map(Key) || Key <- Keys], maps:remove(<<"keys">>, F)}.

to_map(Keys, F) ->
    F#{
        <<"keys">> => [element(2, jose_jwk:to_map(Key)) || Key <- Keys]
    }.
