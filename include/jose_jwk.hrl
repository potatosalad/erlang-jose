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
-ifndef(JOSE_JWK_HRL).

-record(jose_jwk, {
    keys = undefined :: undefined | {module(), any()},
    kty = undefined :: undefined | {module(), any()},
    fields = #{} :: map()
}).

-define(JOSE_JWK_HRL, 1).

-endif.
