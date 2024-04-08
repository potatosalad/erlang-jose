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
%%% Created :  07 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_xchacha20).

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type input() :: binary().
-type output() :: binary().
-type xchacha20_key() :: <<_:256>>.
-type xchacha20_nonce() :: <<_:192>>.
-type xchacha20_count() :: <<_:32>>.
-type xchacha20_state() :: term().

-export_type([
    input/0,
    output/0,
    xchacha20_key/0,
    xchacha20_nonce/0,
    xchacha20_count/0,
    xchacha20_state/0
]).

%% Callbacks
-callback xchacha20_exor(Input, Count, Nonce, Key) -> Output when
    Input :: jose_xchacha20:input(),
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Output :: jose_xchacha20:output().
-callback xchacha20_stream_init(Count, Nonce, Key) -> Xchacha20State when
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Xchacha20State :: jose_xchacha20:xchacha20_state().
-callback xchacha20_stream_exor(Xchacha20State, Input) -> {NewXchacha20State, Output} when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Input :: jose_xchacha20:input(),
    NewXchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
-callback xchacha20_stream_final(Xchacha20State) -> Output when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().

-optional_callbacks([
    xchacha20_exor/4,
    xchacha20_stream_init/3,
    xchacha20_stream_exor/2,
    xchacha20_stream_final/1
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_xchacha20 callbacks
-export([
    xchacha20_exor/4,
    xchacha20_stream_init/3,
    xchacha20_stream_exor/2,
    xchacha20_stream_final/1
]).

%% Macros

% 4 x 128-bit AES blocks
-define(TV_PlainText0(), <<"abcdefghijklmnopqrstuvwxyz012345abcdefghijklmnopqrstuvwxyz012345">>).
% 1/2 x 128-bit AES block
-define(TV_PlainText1(), <<"abcdefgh">>).
% 1 x 128-bit AES block
-define(TV_PlainText2(), <<"abcdefghijklmnop">>).
-define(TV_XCHACHA20_Count(), ?b16d("00000000")).
-define(TV_XCHACHA20_Nonce(), ?b16d("000000000000000000000000000000000000000000000000")).
-define(TV_XCHACHA20_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_XCHACHA20_CipherText0(),
    ?b16d(
        "ddb2497cda5966b9fbf8b55ccac692dcd5c42d24d3765bbf55ace2c6fb29f7e013ede084cfb4d8a7f3d74641d8e1c1ad14732eac4ab6ec6b675d207233adba3a"
    )
).
-define(TV_XCHACHA20_CipherText1(), ?b16d("19fcf5ed8046ea17")).
-define(TV_XCHACHA20_CipherText2(), ?b16d("b88390a1d05278208672ca522ce7f7dd")).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [
            [
                {xchacha20_stream_init, 3},
                {xchacha20_stream_exor, 2},
                {xchacha20_stream_final, 1}
            ]
        ],
        callbacks => [
            {{xchacha20_exor, 4}, [
                {jose_hchacha20, [{hchacha20_subkey, 2}]},
                {jose_xchacha20, [{xchacha20_stream_init, 3}, {xchacha20_stream_exor, 2}, {xchacha20_stream_final, 1}]}
            ]},
            {{xchacha20_stream_init, 3}, [{jose_hchacha20, [{hchacha20_subkey, 2}]}]},
            {{xchacha20_stream_exor, 2}, [
                {jose_hchacha20, [{hchacha20_subkey, 2}]}, {jose_xchacha20, [{xchacha20_stream_init, 3}]}
            ]},
            {{xchacha20_stream_final, 1}, [
                {jose_hchacha20, [{hchacha20_subkey, 2}]},
                {jose_xchacha20, [{xchacha20_stream_init, 3}, {xchacha20_stream_exor, 2}]}
            ]}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, xchacha20_exor, 4) ->
    Count = ?TV_XCHACHA20_Count(),
    Nonce = ?TV_XCHACHA20_Nonce(),
    Key = ?TV_XCHACHA20_Key(),
    PlainText0 = ?TV_PlainText0(),
    PlainText1 = ?TV_PlainText1(),
    PlainText2 = ?TV_PlainText2(),
    CipherText0 = ?TV_XCHACHA20_CipherText0(),
    CipherText1 = ?TV_XCHACHA20_CipherText1(),
    CipherText2 = ?TV_XCHACHA20_CipherText2(),
    PlainText = <<PlainText0/binary, PlainText1/binary, PlainText2/binary>>,
    CipherText = <<CipherText0/binary, CipherText1/binary, CipherText2/binary>>,
    ?expect(CipherText, Module, xchacha20_exor, [PlainText, Count, Nonce, Key]);
support_check(Module, xchacha20_stream_init, 3) ->
    Count = ?TV_XCHACHA20_Count(),
    Nonce = ?TV_XCHACHA20_Nonce(),
    Key = ?TV_XCHACHA20_Key(),
    State = Module:xchacha20_stream_init(Count, Nonce, Key),
    _ = Module:xchacha20_stream_final(State),
    ok;
support_check(Module, xchacha20_stream_exor, 2) ->
    Count = ?TV_XCHACHA20_Count(),
    Nonce = ?TV_XCHACHA20_Nonce(),
    Key = ?TV_XCHACHA20_Key(),
    PlainText0 = ?TV_PlainText0(),
    PlainText1 = ?TV_PlainText1(),
    PlainText2 = ?TV_PlainText2(),
    CipherText0 = ?TV_XCHACHA20_CipherText0(),
    CipherText1 = ?TV_XCHACHA20_CipherText1(),
    CipherText2 = ?TV_XCHACHA20_CipherText2(),
    State0 = Module:xchacha20_stream_init(Count, Nonce, Key),
    {State1, ActualCipherText0} = Module:xchacha20_stream_exor(State0, PlainText0),
    {State2, ActualCipherText1} = Module:xchacha20_stream_exor(State1, PlainText1),
    {State3, ActualCipherText2} = Module:xchacha20_stream_exor(State2, PlainText2),
    _ = Module:xchacha20_stream_final(State3),
    ?expect([
        {{State1, CipherText0}, {State1, ActualCipherText0}, Module, xchacha20_stream_exor, [State0, PlainText0]},
        {{State2, CipherText1}, {State2, ActualCipherText1}, Module, xchacha20_stream_exor, [State1, PlainText1]},
        {{State3, CipherText2}, {State3, ActualCipherText2}, Module, xchacha20_stream_exor, [State2, PlainText2]}
    ]);
support_check(Module, xchacha20_stream_final, 1) ->
    Count = ?TV_XCHACHA20_Count(),
    Nonce = ?TV_XCHACHA20_Nonce(),
    Key = ?TV_XCHACHA20_Key(),
    PlainText0 = ?TV_PlainText0(),
    PlainText1 = ?TV_PlainText1(),
    PlainText2 = ?TV_PlainText2(),
    State0 = Module:xchacha20_stream_init(Count, Nonce, Key),
    {State1, _ActualCipherText0} = Module:xchacha20_stream_exor(State0, PlainText0),
    {State2, _ActualCipherText1} = Module:xchacha20_stream_exor(State1, PlainText1),
    {State3, _ActualCipherText2} = Module:xchacha20_stream_exor(State2, PlainText2),
    ?expect(<<>>, Module, xchacha20_stream_final, [State3]).

%%%=============================================================================
%%% jose_xchacha20 callbacks
%%%=============================================================================

-spec xchacha20_exor(Input, Count, Nonce, Key) -> Output when
    Input :: jose_xchacha20:input(),
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Output :: jose_xchacha20:output().
xchacha20_exor(Input, Count, Nonce, Key) when
    is_binary(Input) andalso
        bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    ?resolve([Input, Count, Nonce, Key]).

-spec xchacha20_stream_init(Count, Nonce, Key) -> Xchacha20State when
    Count :: jose_xchacha20:xchacha20_count(),
    Nonce :: jose_xchacha20:xchacha20_nonce(),
    Key :: jose_xchacha20:xchacha20_key(),
    Xchacha20State :: jose_xchacha20:xchacha20_state().
xchacha20_stream_init(Count, Nonce, Key) when
    bit_size(Count) =:= 32 andalso
        bit_size(Nonce) =:= 192 andalso
        bit_size(Key) =:= 256
->
    ?resolve([Count, Nonce, Key]).

-spec xchacha20_stream_exor(Xchacha20State, Input) -> {NewXchacha20State, Output} when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Input :: jose_xchacha20:input(),
    NewXchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_exor(State, Input) ->
    ?resolve([State, Input]).

-spec xchacha20_stream_final(Xchacha20State) -> Output when
    Xchacha20State :: jose_xchacha20:xchacha20_state(),
    Output :: jose_xchacha20:output().
xchacha20_stream_final(State) ->
    ?resolve([State]).
