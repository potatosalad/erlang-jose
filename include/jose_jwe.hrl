%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-ifndef(JOSE_JWE_HRL).

-record(jose_jwe, {
    alg = undefined :: undefined | {module(), any()},
    enc = undefined :: undefined | {module(), any()},
    zip = undefined :: undefined | {module(), any()},
    fields = #{} :: map()
}).

-define(JOSE_JWE_HRL, 1).

-endif.
