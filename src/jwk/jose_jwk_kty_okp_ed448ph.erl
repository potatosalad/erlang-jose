%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  15 Jan 2016 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_kty_okp_ed448ph).
-behaviour(jose_jwk).
-behaviour(jose_jwk_kty).
-behaviour(jose_jwk_use_sig).

%% jose_jwk callbacks
-export([from_map/1]).
-export([to_key/1]).
-export([to_map/2]).
-export([to_public_map/2]).
-export([to_thumbprint_map/2]).
%% jose_jwk_kty callbacks
-export([generate_key/1]).
-export([generate_key/2]).
-export([key_encryptor/3]).
%% jose_jwk_use_sig callbacks
-export([sign/3]).
-export([signer/2]).
-export([verifier/2]).
-export([verify/4]).
%% API
-export([from_okp/1]).
-export([from_openssh_key/1]).
-export([to_okp/1]).
-export([to_openssh_key/2]).

%% Macros
-define(crv, <<"Ed448ph">>).
-define(secretbytes, 57).
-define(publickeybytes, 57).
-define(secretkeybytes, 114).

%% Types
-type publickey() :: <<_:456>>.
-type secretkey() :: <<_:912>>.
-type key() :: publickey() | secretkey().

-export_type([key/0]).

%%====================================================================
%% jose_jwk callbacks
%%====================================================================

from_map(F = #{<<"kty">> := <<"OKP">>, <<"crv">> := ?crv, <<"d">> := D, <<"x">> := X}) ->
    <<Secret:?secretbytes/binary>> = jose_jwa_base64url:decode(D),
    <<PK:?publickeybytes/binary>> = jose_jwa_base64url:decode(X),
    SK = <<Secret/binary, PK/binary>>,
    {SK, maps:without([<<"crv">>, <<"d">>, <<"kty">>, <<"x">>], F)};
from_map(F = #{<<"kty">> := <<"OKP">>, <<"crv">> := ?crv, <<"x">> := X}) ->
    <<PK:?publickeybytes/binary>> = jose_jwa_base64url:decode(X),
    {PK, maps:without([<<"crv">>, <<"kty">>, <<"x">>], F)}.

to_key(PK = <<_:?publickeybytes/binary>>) ->
    PK;
to_key(SK = <<_:?secretkeybytes/binary>>) ->
    SK.

to_map(PK = <<_:?publickeybytes/binary>>, F) ->
    F#{
        <<"crv">> => ?crv,
        <<"kty">> => <<"OKP">>,
        <<"x">> => jose_jwa_base64url:encode(PK)
    };
to_map(<<Secret:?secretbytes/binary, PK:?publickeybytes/binary>>, F) ->
    F#{
        <<"crv">> => ?crv,
        <<"d">> => jose_jwa_base64url:encode(Secret),
        <<"kty">> => <<"OKP">>,
        <<"x">> => jose_jwa_base64url:encode(PK)
    }.

to_public_map(PK = <<_:?publickeybytes/binary>>, F) ->
    to_map(PK, F);
to_public_map(<<_:?secretbytes/binary, PK:?publickeybytes/binary>>, F) ->
    to_public_map(PK, F).

to_thumbprint_map(K, F) ->
    maps:with([<<"crv">>, <<"kty">>, <<"x">>], to_public_map(K, F)).

%%====================================================================
%% jose_jwk_kty callbacks
%%====================================================================

generate_key(Seed = <<_:?secretbytes/binary>>) ->
    {_PK, SK} = jose_curve448:eddsa_keypair(Seed),
    {SK, #{}};
generate_key({okp, 'Ed448ph', Seed = <<_:?secretbytes/binary>>}) ->
    generate_key(Seed);
generate_key({okp, 'Ed448ph'}) ->
    {_PK, SK} = jose_curve448:eddsa_keypair(),
    {SK, #{}}.

generate_key(KTY, Fields) when
    is_binary(KTY) andalso
        (byte_size(KTY) =:= ?publickeybytes orelse
            byte_size(KTY) =:= ?secretkeybytes)
->
    {NewKTY, OtherFields} = generate_key({okp, 'Ed448ph'}),
    {NewKTY, maps:merge(maps:remove(<<"kid">>, Fields), OtherFields)}.

key_encryptor(KTY, Fields, Key) ->
    jose_jwk_kty:key_encryptor(KTY, Fields, Key).

%%====================================================================
%% jose_jwk_use_sig callbacks
%%====================================================================

sign(Message, ALG, SK = <<_:?secretkeybytes/binary>>) when
    ALG =:= 'Ed448ph' orelse ALG =:= 'EdDSA'
->
    jose_curve448:ed448ph_sign(Message, SK).

signer(<<_:?secretkeybytes/binary>>, #{<<"alg">> := ALG, <<"use">> := <<"sig">>}) ->
    #{
        <<"alg">> => ALG
    };
signer(<<_:?secretkeybytes/binary>>, _Fields) ->
    #{
        <<"alg">> => <<"EdDSA">>
    }.

verifier(<<_:?publickeybytes/binary>>, #{<<"alg">> := ALG, <<"use">> := <<"sig">>}) ->
    [ALG];
verifier(<<_:?secretbytes/binary, PK:?publickeybytes/binary>>, Fields) ->
    verifier(PK, Fields);
verifier(<<_:?publickeybytes/binary>>, _Fields) ->
    [?crv, <<"EdDSA">>].

verify(Message, ALG, Signature, <<_:?secretbytes/binary, PK:?publickeybytes/binary>>) when
    ALG =:= 'Ed448ph' orelse ALG =:= 'EdDSA'
->
    verify(Message, ALG, Signature, PK);
verify(Message, ALG, Signature, PK = <<_:?publickeybytes/binary>>) when
    ALG =:= 'Ed448ph' orelse ALG =:= 'EdDSA'
->
    jose_curve448:ed448ph_verify(Signature, Message, PK).

%%====================================================================
%% API functions
%%====================================================================

from_okp({'Ed448ph', SK = <<Secret:?secretbytes/binary, PK:?publickeybytes/binary>>}) ->
    case jose_curve448:eddsa_secret_to_public(Secret) of
        PK ->
            {SK, #{}};
        _ ->
            erlang:error(badarg)
    end;
from_okp({'Ed448ph', PK = <<_:?publickeybytes/binary>>}) ->
    {PK, #{}}.

from_openssh_key({<<"ssh-ed448ph">>, _PK, SK, Comment}) ->
    {KTY, OtherFields} = from_okp({'Ed448ph', SK}),
    case Comment of
        <<>> ->
            {KTY, OtherFields};
        _ ->
            {KTY, maps:merge(#{<<"kid">> => Comment}, OtherFields)}
    end.

to_okp(SK = <<_:?secretkeybytes/binary>>) ->
    {'Ed448ph', SK};
to_okp(PK = <<_:?publickeybytes/binary>>) ->
    {'Ed448ph', PK}.

to_openssh_key(SK = <<_:?secretbytes/binary, PK:?publickeybytes/binary>>, F) ->
    Comment = maps:get(<<"kid">>, F, <<>>),
    jose_jwk_openssh_key:to_binary([[{{<<"ssh-ed448ph">>, PK}, {<<"ssh-ed448ph">>, PK, SK, Comment}}]]).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
