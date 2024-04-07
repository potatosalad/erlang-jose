%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_rsa).

-include("jose_rsa.hrl").

-behaviour(jose_provider).
-behaviour(jose_rsa).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_rsa callbacks
-export([
    rsa_private_to_public/1,
    rsaes_pkcs1_v1_5_private_decrypt/2,
    rsaes_pkcs1_v1_5_public_encrypt/2,
    rsaes_oaep_private_decrypt/2,
    rsaes_oaep_public_encrypt/2,
    rsaes_oaep_sha256_mgf1_sha256_private_decrypt/2,
    rsaes_oaep_sha256_mgf1_sha256_public_encrypt/2,
    rsaes_oaep_sha384_mgf1_sha384_private_decrypt/2,
    rsaes_oaep_sha384_mgf1_sha384_public_encrypt/2,
    rsaes_oaep_sha512_mgf1_sha512_private_decrypt/2,
    rsaes_oaep_sha512_mgf1_sha512_public_encrypt/2,
    rsassa_pkcs1_v1_5_sha1_sign/2,
    rsassa_pkcs1_v1_5_sha1_verify/3,
    rsassa_pkcs1_v1_5_sha256_sign/2,
    rsassa_pkcs1_v1_5_sha256_verify/3,
    rsassa_pkcs1_v1_5_sha384_sign/2,
    rsassa_pkcs1_v1_5_sha384_verify/3,
    rsassa_pkcs1_v1_5_sha512_sign/2,
    rsassa_pkcs1_v1_5_sha512_verify/3,
    rsassa_pss_sha256_mgf1_sha256_sign/2,
    rsassa_pss_sha256_mgf1_sha256_verify/3,
    rsassa_pss_sha384_mgf1_sha384_sign/2,
    rsassa_pss_sha384_mgf1_sha384_verify/3,
    rsassa_pss_sha512_mgf1_sha512_sign/2,
    rsassa_pss_sha512_mgf1_sha512_verify/3
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
    #{
        behaviour => jose_rsa,
        priority => low,
        requirements => [
            {app, crypto},
            crypto,
            {app, jose},
            jose_jwa_pkcs1
        ]
    }.

%%====================================================================
%% jose_rsa callbacks
%%====================================================================

-spec rsa_private_to_public(PrivateKey) -> PublicKey when
    PrivateKey :: jose_rsa:rsa_private_key(),
    PublicKey :: jose_rsa:rsa_public_key().
rsa_private_to_public(_PrivateKey = #jose_rsa_private_key{e = PublicExponent, n = Modulus}) ->
    #jose_rsa_public_key{e = PublicExponent, n = Modulus}.

-spec rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
    CipherText :: jose_rsa:cipher_text(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    PlainText :: jose_rsa:plain_text().
rsaes_pkcs1_v1_5_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
    case jose_jwa_pkcs1:rsaes_pkcs1_decrypt(CipherText, PrivateKey) of
        PlainText when is_binary(PlainText) ->
            PlainText;
        {error, _Reason} ->
            error
    end.

-spec rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
    PlainText :: jose_rsa:plain_text(),
    PublicKey :: jose_rsa:rsa_public_key(),
    CipherText :: jose_rsa:cipher_text(),
    Reason :: message_too_long.
rsaes_pkcs1_v1_5_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
    case jose_jwa_pkcs1:rsaes_pkcs1_encrypt(PlainText, PublicKey) of
        {ok, CipherText} ->
            CipherText;
        Error = {error, _Reason} ->
            Error
    end.

-spec rsaes_oaep_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
    CipherText :: jose_rsa:cipher_text(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    PlainText :: jose_rsa:plain_text().
rsaes_oaep_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when is_binary(CipherText) ->
    case jose_jwa_pkcs1:rsaes_oaep_decrypt(sha, CipherText, <<>>, PrivateKey) of
        PlainText when is_binary(PlainText) ->
            PlainText;
        {error, _Reason} ->
            error
    end.

-spec rsaes_oaep_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
    PlainText :: jose_rsa:plain_text(),
    PublicKey :: jose_rsa:rsa_public_key(),
    CipherText :: jose_rsa:cipher_text(),
    Reason :: message_too_long.
rsaes_oaep_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
    case jose_jwa_pkcs1:rsaes_oaep_encrypt(sha, PlainText, <<>>, PublicKey) of
        {ok, CipherText} ->
            CipherText;
        Error = {error, _Reason} ->
            Error
    end.

-spec rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
    CipherText :: jose_rsa:cipher_text(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha256_mgf1_sha256_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when
    is_binary(CipherText)
->
    case jose_jwa_pkcs1:rsaes_oaep_decrypt(sha256, CipherText, <<>>, PrivateKey) of
        PlainText when is_binary(PlainText) ->
            PlainText;
        {error, _Reason} ->
            error
    end.

-spec rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
    PlainText :: jose_rsa:plain_text(),
    PublicKey :: jose_rsa:rsa_public_key(),
    CipherText :: jose_rsa:cipher_text(),
    Reason :: message_too_long.
rsaes_oaep_sha256_mgf1_sha256_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
    case jose_jwa_pkcs1:rsaes_oaep_encrypt(sha256, PlainText, <<>>, PublicKey) of
        {ok, CipherText} ->
            CipherText;
        Error = {error, _Reason} ->
            Error
    end.

-spec rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
    CipherText :: jose_rsa:cipher_text(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha384_mgf1_sha384_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when
    is_binary(CipherText)
->
    case jose_jwa_pkcs1:rsaes_oaep_decrypt(sha384, CipherText, <<>>, PrivateKey) of
        PlainText when is_binary(PlainText) ->
            PlainText;
        {error, _Reason} ->
            error
    end.

-spec rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
    PlainText :: jose_rsa:plain_text(),
    PublicKey :: jose_rsa:rsa_public_key(),
    CipherText :: jose_rsa:cipher_text(),
    Reason :: message_too_long.
rsaes_oaep_sha384_mgf1_sha384_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
    case jose_jwa_pkcs1:rsaes_oaep_encrypt(sha384, PlainText, <<>>, PublicKey) of
        {ok, CipherText} ->
            CipherText;
        Error = {error, _Reason} ->
            Error
    end.

-spec rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey) -> PlainText | error when
    CipherText :: jose_rsa:cipher_text(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    PlainText :: jose_rsa:plain_text().
rsaes_oaep_sha512_mgf1_sha512_private_decrypt(CipherText, PrivateKey = #jose_rsa_private_key{}) when
    is_binary(CipherText)
->
    case jose_jwa_pkcs1:rsaes_oaep_decrypt(sha512, CipherText, <<>>, PrivateKey) of
        PlainText when is_binary(PlainText) ->
            PlainText;
        {error, _Reason} ->
            error
    end.

-spec rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey) -> CipherText | {error, Reason} when
    PlainText :: jose_rsa:plain_text(),
    PublicKey :: jose_rsa:rsa_public_key(),
    CipherText :: jose_rsa:cipher_text(),
    Reason :: message_too_long.
rsaes_oaep_sha512_mgf1_sha512_public_encrypt(PlainText, PublicKey = #jose_rsa_public_key{}) when is_binary(PlainText) ->
    case jose_jwa_pkcs1:rsaes_oaep_encrypt(sha512, PlainText, <<>>, PublicKey) of
        {ok, CipherText} ->
            CipherText;
        Error = {error, _Reason} ->
            Error
    end.

-spec rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha1_signature().
rsassa_pkcs1_v1_5_sha1_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pkcs1_sign(sha, Message, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha1_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha1_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pkcs1_verify(sha, Message, Signature, PublicKey).

-spec rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha256_signature().
rsassa_pkcs1_v1_5_sha256_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pkcs1_sign(sha256, Message, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha256_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha256_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pkcs1_verify(sha256, Message, Signature, PublicKey).

-spec rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha384_signature().
rsassa_pkcs1_v1_5_sha384_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pkcs1_sign(sha384, Message, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha384_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha384_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pkcs1_verify(sha384, Message, Signature, PublicKey).

-spec rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pkcs1_v1_5_sha512_signature().
rsassa_pkcs1_v1_5_sha512_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pkcs1_sign(sha512, Message, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pkcs1_v1_5_sha512_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pkcs1_v1_5_sha512_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pkcs1_verify(sha512, Message, Signature, PublicKey).

-spec rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature().
rsassa_pss_sha256_mgf1_sha256_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pss_sign(sha256, Message, -1, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha256_mgf1_sha256_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha256_mgf1_sha256_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pss_verify(sha256, Message, Signature, -1, PublicKey).

-spec rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature().
rsassa_pss_sha384_mgf1_sha384_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pss_sign(sha384, Message, -1, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha384_mgf1_sha384_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha384_mgf1_sha384_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pss_verify(sha384, Message, Signature, -1, PublicKey).

-spec rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey) -> Signature when
    Message :: jose_rsa:message(),
    PrivateKey :: jose_rsa:rsa_private_key(),
    Signature :: jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature().
rsassa_pss_sha512_mgf1_sha512_sign(Message, PrivateKey = #jose_rsa_private_key{}) when is_binary(Message) ->
    case jose_jwa_pkcs1:rsassa_pss_sign(sha512, Message, -1, PrivateKey) of
        {ok, Signature} ->
            Signature
    end.

-spec rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_rsa:maybe_invalid_signature(jose_rsa:rsassa_pss_sha512_mgf1_sha512_signature()),
    Message :: jose_rsa:message(),
    PublicKey :: jose_rsa:rsa_public_key().
rsassa_pss_sha512_mgf1_sha512_verify(Signature, Message, PublicKey = #jose_rsa_public_key{}) when
    is_binary(Signature) andalso
        is_binary(Message)
->
    jose_jwa_pkcs1:rsassa_pss_verify(sha512, Message, Signature, -1, PublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
