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
%%% Created :  11 May 2017 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-ifndef(JOSE_BASE_HRL).

-define(bnotzero(X),
    ((((X) bor ((bnot (X)) + 1)) bsr 7) band 1)
).

-define(is_iodata(I),
    (is_binary(I) orelse is_list(I))
).

-define(to_binary(I),
    (case I of
        _ when is_binary(I) ->
            I;
        _ when is_list(I) ->
            erlang:iolist_to_binary(I)
    end)
).

-define(JOSE_BASE_HRL, 1).

-endif.
