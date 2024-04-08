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
%%% Created :  02 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-ifndef(JOSE_SUPPORT_HRL).

-define(b16d(X), jose_base16:'decode!'(X)).
-define(b16e(X), jose_base16:encode(X, #{'case' => lower})).
-define(expect(ExpectationSpec), jose_support:expect(ExpectationSpec)).
-define(expect(Expected, Module, Function, Arguments), jose_support:expect(Expected, Module, Function, Arguments)).
-define(expect(Expected, Actual, Module, Function, Arguments),
    jose_support:expect(Expected, Actual, Module, Function, Arguments)
).
-define(expect_report(Module, Function, Arguments, Actual, Expected),
    jose_support:expect_report(Module, Function, Arguments, Actual, Expected)
).
-define(format(Format, Arguments), lists:flatten(io_lib:format(Format, Arguments))).
-define(resolve(Arguments),
    case ets:whereis(jose_jwa_resolved) of
        undefined ->
            case jose_support_statem:resolve({?MODULE, {?FUNCTION_NAME, ?FUNCTION_ARITY}}) of
                {ok, ResolvedModule} ->
                    erlang:apply(ResolvedModule, ?FUNCTION_NAME, Arguments);
                error ->
                    erlang:error(operation_not_supported)
            end;
        ResolvedTableId when is_reference(ResolvedTableId) ->
            case ets:lookup(ResolvedTableId, {?MODULE, {?FUNCTION_NAME, ?FUNCTION_ARITY}}) of
                [{_, {_, ResolvedModule}}] ->
                    erlang:apply(ResolvedModule, ?FUNCTION_NAME, Arguments);
                [] ->
                    erlang:error(operation_not_supported)
            end
    end
).

-define(JOSE_SUPPORT_HRL, 1).

-endif.
