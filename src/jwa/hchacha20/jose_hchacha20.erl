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
-module(jose_hchacha20).

-include_lib("jose/include/jose_support.hrl").

-behaviour(jose_support).

%% Types
-type hchacha20_key() :: <<_:256>>.
-type hchacha20_nonce() :: <<_:128>>.
-type hchacha20_subkey() :: <<_:256>>.

-export_type([
    hchacha20_key/0,
    hchacha20_nonce/0,
    hchacha20_subkey/0
]).

%% Callbacks
-callback hchacha20_subkey(Nonce, Key) -> Subkey when
    Nonce :: jose_hchacha20:hchacha20_nonce(),
    Key :: jose_hchacha20:hchacha20_key(),
    Subkey :: jose_hchacha20:hchacha20_subkey().

-optional_callbacks([
    hchacha20_subkey/2
]).

%% jose_support callbacks
-export([
    support_info/0,
    support_check/3
]).
%% jose_hchacha20 callbacks
-export([
    hchacha20_subkey/2
]).

%% Macros
-define(TV_HCHACHA20_Nonce(), ?b16d("00000000000000000000000000000000")).
-define(TV_HCHACHA20_Key(), ?b16d("0000000000000000000000000000000000000000000000000000000000000000")).
-define(TV_HCHACHA20_Subkey(), ?b16d("1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586")).

%%%=============================================================================
%%% jose_support callbacks
%%%=============================================================================

-spec support_info() -> jose_support:info().
support_info() ->
    #{
        stateful => [],
        callbacks => [
            {{hchacha20_subkey, 2}, []}
        ]
    }.

-spec support_check(Module :: module(), FunctionName :: jose_support:function_name(), Arity :: arity()) ->
    jose_support:support_check_result().
support_check(Module, hchacha20_subkey, 2) ->
    Nonce = ?TV_HCHACHA20_Nonce(),
    Key = ?TV_HCHACHA20_Key(),
    Subkey = ?TV_HCHACHA20_Subkey(),
    ?expect(Subkey, Module, hchacha20_subkey, [Nonce, Key]).

%%%=============================================================================
%%% jose_hchacha20 callbacks
%%%=============================================================================

-spec hchacha20_subkey(Nonce, Key) -> Subkey when
    Nonce :: jose_hchacha20:hchacha20_nonce(),
    Key :: jose_hchacha20:hchacha20_key(),
    Subkey :: jose_hchacha20:hchacha20_subkey().
hchacha20_subkey(Nonce, Key) when
    bit_size(Nonce) =:= 128 andalso
        bit_size(Key) =:= 256
->
    ?resolve([Nonce, Key]).
