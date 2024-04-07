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
%%% Created :  06 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_provider).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

%% Types
-type info() :: #{
    behaviour := jose_support:behaviour(),
    priority := jose_support:priority(),
    requirements := list(jose_support:requirement())
}.

-export_type([
    info/0
]).

%% Callbacks
-callback provider_info() -> jose_provider:info().
