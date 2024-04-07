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
%%% Created :  29 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_jwe_enc).

%% Types
-type algorithm() :: binary().
-type key_bit_size() :: non_neg_integer().

-type additional_authenticated_data() :: binary().
-type cipher_tag() :: binary().
-type cipher_text() :: binary().
-type content_encryption_key() :: binary().
-type nonce() :: binary().
-type plain_text() :: binary().

-type internal_state() :: internal_state(term()).
-type internal_state(T) :: T.
-type state() :: state(term()).
-type state(T) :: {module(), internal_state(T)}.

-export_type([
    algorithm/0,
    key_bit_size/0,

    additional_authenticated_data/0,
    cipher_tag/0,
    cipher_text/0,
    content_encryption_key/0,
    nonce/0,
    plain_text/0,

    internal_state/0,
    internal_state/1,
    state/0,
    state/1
]).

%% Callbacks
-callback algorithm(ENC) -> Algorithm when
    ENC :: jose_jwe_enc:internal_state(),
    Algorithm :: jose_jwe_enc:algorithm().
-callback key_bit_size(ENC) -> KeyBitSize when
    ENC :: jose_jwe_enc:internal_state(),
    KeyBitSize :: jose_jwe_enc:key_bit_size().

-callback content_decrypt(ENC, CipherText, CipherTag, AAD, Nonce, CEK) -> PlainText | error when
    ENC :: jose_jwe_enc:internal_state(),
    CipherText :: jose_jwe_enc:cipher_text(),
    CipherTag :: jose_jwe_enc:cipher_tag(),
    AAD :: jose_jwe_enc:additional_authenticated_data(),
    Nonce :: jose_jwe_enc:nonce(),
    CEK :: jose_jwe_enc:content_encryption_key(),
    PlainText :: jose_jwe_enc:plain_text().
-callback content_encrypt(ENC, PlainText, AAD, Nonce, CEK) -> {CipherText, CipherTag} when
    ENC :: jose_jwe_enc:internal_state(),
    PlainText :: jose_jwe_enc:plain_text(),
    AAD :: jose_jwe_enc:additional_authenticated_data(),
    Nonce :: jose_jwe_enc:nonce(),
    CEK :: jose_jwe_enc:content_encryption_key(),
    CipherText :: jose_jwe_enc:cipher_text(),
    CipherTag :: jose_jwe_enc:cipher_tag().

-callback generate_content_encryption_key(ENC) -> CEK when
    ENC :: jose_jwe_enc:internal_state(),
    CEK :: jose_jwe_enc:content_encryption_key().
-callback generate_nonce(ENC) -> Nonce when
    ENC :: jose_jwe_enc:internal_state(),
    Nonce :: jose_jwe_enc:nonce().
