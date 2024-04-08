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
%%% Created :  10 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwa_unsupported).
-behaviour(jose_block_encryptor).

%% jose_block_encryptor callbacks
-export([block_decrypt/3]).
-export([block_decrypt/4]).
-export([block_encrypt/3]).
-export([block_encrypt/4]).
%% Public Key API
-export([decrypt_private/3]).
-export([encrypt_public/3]).
-export([sign/4]).
-export([verify/5]).

%%%=============================================================================
%%% jose_block_encryptor callbacks
%%%=============================================================================

block_decrypt(Cipher, _Key, _CipherText) ->
    erlang:error({cipher_unsupported, [Cipher]}).

block_decrypt(Cipher, _Key, _IV, _CipherText) ->
    erlang:error({cipher_unsupported, [Cipher]}).

block_encrypt(Cipher, _Key, _PlainText) ->
    erlang:error({cipher_unsupported, [Cipher]}).

block_encrypt(Cipher, _Key, _IV, _PlainText) ->
    erlang:error({cipher_unsupported, [Cipher]}).

%%%=============================================================================
%%% Public Key API functions
%%%=============================================================================

decrypt_private(_CipherText, _PrivateKey, Options) ->
    erlang:error({crypt_unsupported, [Options]}).

encrypt_public(_PlainText, _PublicKey, Options) ->
    erlang:error({crypt_unsupported, [Options]}).

sign(_Message, _DigestType, _PrivateKey, Options) ->
    erlang:error({sign_unsupported, [Options]}).

verify(_Message, _DigestType, _Signature, _PublicKey, Options) ->
    erlang:error({sign_unsupported, [Options]}).

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
