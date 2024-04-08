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
%%% Created :  18 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwk_oct).

-callback from_oct(OCTBinary) -> {KTY, Fields} when
    OCTBinary :: binary(),
    KTY :: any(),
    Fields :: map().
-callback to_oct(KTY) -> OCTBinary when
    KTY :: any(),
    OCTBinary :: binary().

%% API
-export([from_binary/1]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

from_binary(OCTBinary) when is_binary(OCTBinary) ->
    jose_jwk_kty:from_oct(OCTBinary).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
