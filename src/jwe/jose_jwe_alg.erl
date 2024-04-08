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
%%% Created :  23 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwe_alg).

-callback key_decrypt(Key, {ENCModule, ENC, EncryptedKey}, ALG) -> DecryptedKey when
    Key :: any(),
    ENCModule :: module(),
    ENC :: any(),
    EncryptedKey :: iodata(),
    ALG :: any(),
    DecryptedKey :: iodata().
-callback key_encrypt(Key, DecryptedKey, ALG) -> {EncryptedKey, NewALG} when
    Key :: any(),
    DecryptedKey :: iodata(),
    ALG :: any(),
    EncryptedKey :: iodata(),
    NewALG :: any().
-callback next_cek(Key, {ENCModule, ENC}, ALG) -> {DecryptedKey, NewALG} when
    Key :: any(),
    ENCModule :: module(),
    ENC :: any(),
    ALG :: any(),
    DecryptedKey :: iodata(),
    NewALG :: any().

%% API
-export([generate_key/3]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

generate_key(Parameters, Algorithm, Encryption) ->
    jose_jwk:merge(jose_jwk:generate_key(Parameters), #{
        <<"alg">> => Algorithm,
        <<"enc">> => Encryption,
        <<"use">> => <<"enc">>
    }).
