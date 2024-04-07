%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
-module(jose_jwt_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("jose.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([from_map_and_to_map/1]).
-export([encrypt_and_decrypt/1]).
-export([sign_and_verify/1]).

all() ->
    [
        {group, jose_jwt}
    ].

groups() ->
    [
        {jose_jwt, [parallel], [
            from_map_and_to_map,
            encrypt_and_decrypt,
            sign_and_verify
        ]}
    ].

init_per_suite(Config) ->
    application:set_env(jose, crypto_fallback, true),
    application:set_env(jose, unsecured_signing, true),
    _ = application:ensure_all_started(jose),
    ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
    _ = application:stop(jose),
    ok.

init_per_group(Group, Config) ->
    jose_ct:start(Group, Config).

end_per_group(_Group, Config) ->
    jose_ct:stop(Config),
    ok.

%%%=============================================================================
%% Tests
%%%=============================================================================

from_map_and_to_map(Config) ->
    ct_property_test:quickcheck(
        jose_jwt_props:prop_from_map_and_to_map(),
        Config
    ).

encrypt_and_decrypt(Config) ->
    ct_property_test:quickcheck(
        jose_jwt_props:prop_encrypt_and_decrypt(),
        Config
    ).

sign_and_verify(Config) ->
    ct_property_test:quickcheck(
        jose_jwt_props:prop_sign_and_verify(),
        Config
    ).
