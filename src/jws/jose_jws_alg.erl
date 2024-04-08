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
%%% Created :  29 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jws_alg).

-callback generate_key(ALG, Fields) -> JWK when
    ALG :: any(),
    Fields :: map(),
    JWK :: jose_jwk:key().
-callback sign(Key, Message, ALG) -> Signature when
    Key :: any(),
    Message :: iodata(),
    ALG :: any(),
    Signature :: iodata().
-callback verify(Key, Message, Signature, ALG) -> boolean() when
    Key :: any(),
    Message :: iodata(),
    Signature :: iodata(),
    ALG :: any().

-callback presign(Key, ALG) -> NewALG when
    Key :: any(),
    ALG :: any(),
    NewALG :: any().

-optional_callbacks([presign/2]).

%% API
-export([generate_key/2]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

generate_key(Parameters, Algorithm) ->
    jose_jwk:merge(jose_jwk:generate_key(Parameters), #{
        <<"alg">> => Algorithm,
        <<"use">> => <<"sig">>
    }).
