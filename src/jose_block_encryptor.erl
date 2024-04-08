%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
%%%-----------------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  10 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
-module(jose_block_encryptor).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-callback block_decrypt(Cipher, Key, CipherText) -> PlainText | error when
    Cipher :: {atom(), pos_integer()},
    Key :: bitstring(),
    CipherText :: binary(),
    PlainText :: binary().
-callback block_encrypt(Cipher, Key, PlainText) -> CipherText when
    Cipher :: {atom(), pos_integer()},
    Key :: bitstring(),
    PlainText :: binary(),
    CipherText :: binary().

-optional_callbacks([
    block_decrypt/3,
    block_encrypt/3
]).

-callback block_decrypt(Cipher, Key, IV, CipherText) -> PlainText | error when
    Cipher :: {atom(), pos_integer()},
    Key :: bitstring(),
    IV :: bitstring(),
    CipherText :: binary() | {binary(), binary(), binary()},
    PlainText :: binary().
-callback block_encrypt(Cipher, Key, IV, PlainText) -> CipherText when
    Cipher :: {atom(), pos_integer()},
    Key :: bitstring(),
    IV :: bitstring(),
    PlainText :: binary() | {binary(), binary()},
    CipherText :: binary() | {binary(), binary()}.
