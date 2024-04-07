%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  23 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------

-ifndef(JOSE_JWS_HRL).

-record(jose_jws, {
    alg = undefined :: undefined | {module(), any()},
    b64 = undefined :: undefined | boolean(),
    fields = #{} :: map()
}).

-define(JOSE_JWS_HRL, 1).

-endif.
