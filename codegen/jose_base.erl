%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%% % @format
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  24 Feb 2018 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_base).

%% API
-export([calculate_shift/1]).
-export([calculate_pairs/2]).

%% parse_transform callbacks
-export([parse_transform/2]).

%%%===================================================================
%%% API functions
%%%===================================================================

calculate_shift(Table) when is_list(Table) ->
    erlang:round(math:log2(length(Table))).

calculate_pairs(Table, Type) when Type == sensitive orelse Type == upper ->
    Shift = calculate_shift(Table),
    do_calculate_pairs(Table, Table, Shift, []).

%% @private
do_calculate_pairs([{V0, C0} | Rest], Table, Shift, Acc0) ->
    Acc1 = do_calculate_pairs_permutation(V0 bsl Shift, C0 bsl 8, Table, Acc0),
    do_calculate_pairs(Rest, Table, Shift, Acc1);
do_calculate_pairs([], _Table, _Shift, Acc) ->
    lists:reverse(Acc).

%% @private
do_calculate_pairs_permutation(V0, C0, [{V1, C1} | Rest], Acc0) ->
    V = V0 + V1,
    C = C0 + C1,
    Acc1 = [{V, C} | Acc0],
    do_calculate_pairs_permutation(V0, C0, Rest, Acc1);
do_calculate_pairs_permutation(_, _, [], Acc) ->
    Acc.

%%%===================================================================
%%% parse_transform callbacks
%%%===================================================================

parse_transform(Ast0, _Options) ->
    Ast1 = walk_ast([], Ast0),
    [Module] = [Module || {attribute, _Line, module, Module} <- Ast1],
    % io:format("Module = ~p~n", [Module]),
    Forms = epp:restore_typed_record_fields(
        revert([Form || Form = {function, _Line, Name, _Arity, _Clauses} <- Ast1, Name =:= encode_char orelse Name =:= encode_pair])
    ),
    ok = lists:foreach(fun(Form = {function, _Line, Name, _Arity, _Clauses}) ->
        Filename = unicode:characters_to_list(io_lib:format("~s.~s.erl", [Module, Name])),
        Body = erlang:iolist_to_binary(binary:split(unicode:characters_to_binary(erl_pp:form(Form)), <<"\n">>, [global, trim_all])),
        ok = file:write_file(Filename, <<"%%% % @format\n", Body/binary>>),
        io:format("Wrote to ~s~n", [Filename]),
        ok
    end, Forms),
    % Str = [
    %     io_lib:fwrite(
    %         "~s~n",
    %         [
    %             lists:flatten([
    %                 erl_pp:form(Fm)
    %              || Fm <- Forms
    %             ])
    %         ]
    %     )
    % ],
    % io:format("~s~n", [Str]),
    Ast1.

revert(Tree) ->
    [erl_syntax:revert(T) || T <- lists:flatten(Tree)].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
walk_ast(Acc, []) ->
    lists:reverse(Acc);
walk_ast(Acc, [{function, Line, Name, Arity, Clauses} | Ast]) ->
    walk_ast([{function, Line, Name, Arity, walk_clauses([], Clauses)} | Acc], Ast);
walk_ast(Acc, [Form | Ast]) ->
    walk_ast([Form | Acc], Ast).

%% @private
walk_clauses(Acc, []) ->
    lists:reverse(Acc);
walk_clauses(Acc, [{clause, Line, Arguments, Guards, Body} | Ast]) ->
    walk_clauses([{clause, Line, Arguments, Guards, walk_body([], Body)} | Acc], Ast).

%% @private
walk_body(Acc, []) ->
    lists:reverse(Acc);
walk_body(Acc, [Statement | Ast]) ->
    walk_body([transform_statement(Statement) | Acc], Ast).

%% @private
transform_statement(Statement = {call, Line, {remote, _Line1, {atom, _Line2, ?MODULE}, {atom, _Line3, Function}}, Arguments}) ->
    case transform_call(Function, Line, Arguments) of
        {ok, NewStatement} ->
            NewStatement;
        error ->
            Statement
    end;
transform_statement({match, Line, Pattern, Expression}) ->
    {match, Line, Pattern, transform_expression(Expression)};
transform_statement(Statement) ->
    Statement.

%% @private
transform_expression({bc, Line1, {bin, Line2, Elements}, Qualifiers}) ->
    {bc, Line1, {bin, Line2, walk_elements([], Elements)}, Qualifiers};
transform_expression(Expression) ->
    Expression.

%% @private
walk_elements(Acc, []) ->
    lists:reverse(Acc);
walk_elements(Acc, [{bin_element, Line, Statement, Size, Type} | Ast]) ->
    walk_elements([{bin_element, Line, transform_statement(Statement), Size, Type} | Acc], Ast);
walk_elements(Acc, [Element | Ast]) ->
    walk_elements([Element | Acc], Ast).

%% @private
transform_call(encode_char_as_case, _Line, [
    Case = {'case', _Line1, _Var, [{clause, _Line2, [{integer, _Line3, 0}], [], [{char, _Line4, _}]} | _]}
]) ->
    {ok, Case};
transform_call(encode_pair_as_case, Line, [
    {'case', _Line1, Var, Clauses0 = [{clause, _Line2, [{integer, _Line3, 0}], [], [{char, _Line4, _}]} | _]}, {atom, _Line5, Type}
]) ->
    Table = calculate_pairs([{Index, Value} || {clause, _, [{integer, _, Index}], [], [{char, _, Value}]} <- Clauses0], Type),
    Clauses1 = [{clause, Line, [{integer, Line, Index}], [], [{integer, Line, Value}]} || {Index, Value} <- Table],
    Case = {'case', Line, Var, Clauses1},
    {ok, Case};
transform_call(encode_char_as_tuple_element_call, Line, [
    {'case', _Line1, Var, Clauses0 = [{clause, _Line2, [{integer, _Line3, 0}], [], [{char, _Line4, _}]} | _]}
]) ->
    Pairs = [{Index, Value} || {clause, _, [{integer, _, Index}], [], [{char, _, Value}]} <- Clauses0],
    encode_as_tuple_element_call(Line, Var, Pairs);
transform_call(encode_pair_as_tuple_element_call, Line, [
    {'case', _Line1, Var, Clauses0 = [{clause, _Line2, [{integer, _Line3, 0}], [], [{char, _Line4, _}]} | _]}, {atom, _Line5, Type}
]) ->
    Pairs = calculate_pairs([{Index, Value} || {clause, _, [{integer, _, Index}], [], [{char, _, Value}]} <- Clauses0], Type),
    encode_as_tuple_element_call(Line, Var, Pairs);
transform_call(_Function, _Line, _Arguments) ->
    error.

%% @private
encode_as_tuple_element_call(Line, Var, Pairs) ->
    Table = maps:from_list(Pairs),
    Elements = [{char, Line, maps:get(Index, Table)} || Index <- lists:seq(0, maps:size(Table) - 1)],
    VarPlusOne = {op, Line, '+', Var, {integer, Line, 1}},
    Tuple = {tuple, Line, Elements},
    Call = {call, Line, {atom, Line, element}, [VarPlusOne, Tuple]},
    {ok, Call}.
