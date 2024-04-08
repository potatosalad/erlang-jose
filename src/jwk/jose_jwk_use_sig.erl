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
%%% Created :  16 Mar 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwk_use_sig).

-callback sign(Message, Options, KTY) -> Signature when
    Message :: iodata(),
    Options :: any(),
    KTY :: any(),
    Signature :: iodata().
-callback signer(KTY, Fields) -> JWSMap when
    KTY :: any(),
    Fields :: map(),
    JWSMap :: map().
-callback verifier(KTY, Fields) -> [JWSALG] when
    KTY :: any(),
    Fields :: map(),
    JWSALG :: iodata().
-callback verify(Message, Options, Signature, KTY) -> boolean() when
    Message :: iodata(),
    Options :: any(),
    Signature :: iodata(),
    KTY :: any().

%%%=============================================================================
%%% API functions
%%%=============================================================================

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
