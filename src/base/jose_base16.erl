%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @doc RFC 4648, Section 8: https://tools.ietf.org/html/rfc4648#section-8
%%%
%%% @end
%%% Created :  11 May 2017 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_base16).
-compile(warn_missing_spec_all).
-author("potatosaladx@gmail.com").

-include_lib("jose/include/jose_base.hrl").

%% API
-export([
    decode/1,
    decode/2,
    'decode!'/1,
    'decode!'/2,
    encode/1,
    encode/2,
    random/1,
    random/2
]).
%% Errors API
-export([
    format_error/2
]).

%% Types
-type decode_options() :: #{
    'case' => 'lower' | 'mixed' | 'upper'
}.
-type decode_options_list() :: [
    {'case', 'lower' | 'mixed' | 'upper'}
].
-type encode_options() :: #{
    'case' => 'lower' | 'upper'
}.
-type encode_options_list() :: [
    {'case', 'lower' | 'upper'}
].

-export_type([
    decode_options/0,
    decode_options_list/0,
    encode_options/0,
    encode_options_list/0
]).

%% Macros
-define(LC_B16_TO_INT(C),
    case C of
        $0 ->
            16#0;
        $1 ->
            16#1;
        $2 ->
            16#2;
        $3 ->
            16#3;
        $4 ->
            16#4;
        $5 ->
            16#5;
        $6 ->
            16#6;
        $7 ->
            16#7;
        $8 ->
            16#8;
        $9 ->
            16#9;
        $a ->
            16#A;
        $b ->
            16#B;
        $c ->
            16#C;
        $d ->
            16#D;
        $e ->
            16#E;
        $f ->
            16#F;
        _ ->
            error_with_info(badarg, [Input, DecodeOptions], #{
                1 => {invalid_decode_character, #{'case' => 'lower', 'char' => (C)}}
            })
    end
).
-define(MC_B16_TO_INT(C),
    case C of
        $0 ->
            16#0;
        $1 ->
            16#1;
        $2 ->
            16#2;
        $3 ->
            16#3;
        $4 ->
            16#4;
        $5 ->
            16#5;
        $6 ->
            16#6;
        $7 ->
            16#7;
        $8 ->
            16#8;
        $9 ->
            16#9;
        $a ->
            16#A;
        $b ->
            16#B;
        $c ->
            16#C;
        $d ->
            16#D;
        $e ->
            16#E;
        $f ->
            16#F;
        $A ->
            16#A;
        $B ->
            16#B;
        $C ->
            16#C;
        $D ->
            16#D;
        $E ->
            16#E;
        $F ->
            16#F;
        _ ->
            error_with_info(badarg, [Input, DecodeOptions], #{
                1 => {invalid_decode_character, #{'case' => 'mixed', 'char' => (C)}}
            })
    end
).
-define(UC_B16_TO_INT(C),
    case C of
        $0 ->
            16#0;
        $1 ->
            16#1;
        $2 ->
            16#2;
        $3 ->
            16#3;
        $4 ->
            16#4;
        $5 ->
            16#5;
        $6 ->
            16#6;
        $7 ->
            16#7;
        $8 ->
            16#8;
        $9 ->
            16#9;
        $A ->
            16#A;
        $B ->
            16#B;
        $C ->
            16#C;
        $D ->
            16#D;
        $E ->
            16#E;
        $F ->
            16#F;
        _ ->
            error_with_info(badarg, [Input, DecodeOptions], #{
                1 => {invalid_decode_character, #{'case' => 'upper', 'char' => (C)}}
            })
    end
).
-define(LC_INT_TO_B16(C),
    case C of
        16#0 -> $0;
        16#1 -> $1;
        16#2 -> $2;
        16#3 -> $3;
        16#4 -> $4;
        16#5 -> $5;
        16#6 -> $6;
        16#7 -> $7;
        16#8 -> $8;
        16#9 -> $9;
        16#A -> $a;
        16#B -> $b;
        16#C -> $c;
        16#D -> $d;
        16#E -> $e;
        16#F -> $f
    end
).
-define(UC_INT_TO_B16(C),
    case C of
        16#0 -> $0;
        16#1 -> $1;
        16#2 -> $2;
        16#3 -> $3;
        16#4 -> $4;
        16#5 -> $5;
        16#6 -> $6;
        16#7 -> $7;
        16#8 -> $8;
        16#9 -> $9;
        16#A -> $A;
        16#B -> $B;
        16#C -> $C;
        16#D -> $D;
        16#E -> $E;
        16#F -> $F
    end
).

%%%=============================================================================
%%% API functions
%%%=============================================================================

-spec decode(Input) -> {ok, Output} | error when Input :: iodata(), Output :: binary().
decode(Input) when ?is_iodata(Input) ->
    decode(Input, #{}).

-spec decode(Input, DecodeOptions | DecodeOptionsList) -> {ok, Output} | error when
    Input :: iodata(),
    DecodeOptions :: decode_options(),
    DecodeOptionsList :: decode_options_list(),
    Output :: binary().
decode(Input, Opts) when ?is_iodata(Input) andalso is_map(Opts) ->
    try 'decode!'(Input, Opts) of
        Output when is_binary(Output) ->
            {ok, Output}
    catch
        error:badarg ->
            error
    end;
decode(Input, Opts) when ?is_iodata(Input) andalso is_list(Opts) ->
    decode(Input, maps:from_list(Opts)).

-spec 'decode!'(Input) -> Output when Input :: iodata(), Output :: binary().
'decode!'(Input) when ?is_iodata(Input) ->
    'decode!'(Input, #{}).

-spec 'decode!'(Input, DecodeOptions | DecodeOptionsList) -> Output when
    Input :: iodata(),
    DecodeOptions :: decode_options(),
    DecodeOptionsList :: decode_options_list(),
    Output :: binary().
'decode!'([], DecodeOptions) when is_map(DecodeOptions) ->
    <<>>;
'decode!'(<<>>, DecodeOptions) when is_map(DecodeOptions) ->
    <<>>;
'decode!'(Input, DecodeOptions) when ?is_iodata(Input) andalso is_map(DecodeOptions) ->
    Case = maps:get('case', DecodeOptions, 'mixed'),
    case {Case, erlang:iolist_size(Input) rem 2} of
        {'lower', 0} ->
            <<<<((?LC_B16_TO_INT(X) bsl 4) + ?LC_B16_TO_INT(Y))>> || <<X, Y>> <= ?to_binary(Input)>>;
        {'mixed', 0} ->
            <<<<((?MC_B16_TO_INT(X) bsl 4) + ?MC_B16_TO_INT(Y))>> || <<X, Y>> <= ?to_binary(Input)>>;
        {'upper', 0} ->
            <<<<((?UC_B16_TO_INT(X) bsl 4) + ?UC_B16_TO_INT(Y))>> || <<X, Y>> <= ?to_binary(Input)>>;
        {Case, _ExtraLength} when Case =:= 'lower' orelse Case =:= 'mixed' orelse Case =:= 'upper' ->
            error_with_info(badarg, [Input, DecodeOptions], #{
                1 => {invalid_decode_input_length, erlang:iolist_size(Input)}
            });
        _ ->
            error_with_info(badarg, [Input, DecodeOptions], #{2 => {invalid_decode_option_case, Case}})
    end;
'decode!'(Input, DecodeOptionsList) when ?is_iodata(Input) andalso is_list(DecodeOptionsList) ->
    'decode!'(Input, maps:from_list(DecodeOptionsList)).

-spec encode(Input) -> Output when Input :: iodata(), Output :: binary().
encode(Input) when ?is_iodata(Input) ->
    encode(Input, #{}).

-spec encode(Input, EncodeOptions | EncodeOptionsList) -> Output when
    Input :: iodata(),
    EncodeOptions :: encode_options(),
    EncodeOptionsList :: encode_options_list(),
    Output :: binary().
encode(Input, EncodeOptions) when ?is_iodata(Input) andalso is_map(EncodeOptions) ->
    Case = maps:get('case', EncodeOptions, 'upper'),
    case Case of
        'lower' ->
            <<<<(?LC_INT_TO_B16(V bsr 4)), (?LC_INT_TO_B16(V band 16#F))>> || <<V>> <= ?to_binary(Input)>>;
        'upper' ->
            <<<<(?UC_INT_TO_B16(V bsr 4)), (?UC_INT_TO_B16(V band 16#F))>> || <<V>> <= ?to_binary(Input)>>;
        _ ->
            error_with_info(badarg, [Input, EncodeOptions], #{2 => {invalid_encode_option_case, Case}})
    end;
encode(Input, EncodeOptionsList) when ?is_iodata(Input) andalso is_list(EncodeOptionsList) ->
    encode(Input, maps:from_list(EncodeOptionsList)).

-spec random(OutputLength) -> Output when OutputLength :: non_neg_integer(), Output :: binary().
random(OutputLength) when is_integer(OutputLength) andalso OutputLength >= 0 ->
    random(OutputLength, #{}).

-spec random(OutputLength, EncodeOptions | EncodeOptionsList) -> Output when
    OutputLength :: non_neg_integer(),
    EncodeOptions :: encode_options(),
    EncodeOptionsList :: encode_options_list(),
    Output :: binary().
random(0, EncodeOptions) when is_map(EncodeOptions) ->
    <<>>;
random(OutputLength, EncodeOptions) when
    (OutputLength =:= 1 orelse (OutputLength rem 2) =/= 0) andalso is_map(EncodeOptions)
->
    error_with_info(badarg, [OutputLength, EncodeOptions], #{1 => {invalid_output_length, OutputLength}});
random(OutputLength, EncodeOptions) when
    is_integer(OutputLength) andalso OutputLength > 0 andalso is_map(EncodeOptions)
->
    Size = OutputLength div 2,
    Input = crypto:strong_rand_bytes(Size),
    encode(Input, EncodeOptions);
random(OutputLength, EncodeOptionsList) when
    is_integer(OutputLength) andalso OutputLength >= 0 andalso is_list(EncodeOptionsList)
->
    random(OutputLength, maps:from_list(EncodeOptionsList)).

%%%=============================================================================
%%% Errors API functions
%%%=============================================================================

%% @private
-compile({inline, [error_with_info/3]}).
-spec error_with_info(dynamic(), dynamic(), dynamic()) -> no_return().
error_with_info(Reason, Args, Cause) ->
    erlang:error(Reason, Args, [{error_info, #{module => ?MODULE, cause => Cause}}]).

-spec format_error(dynamic(), dynamic()) -> dynamic().
format_error(_Reason, [{_M, _F, _As, Info} | _]) ->
    ErrorInfo = proplists:get_value(error_info, Info, #{}),
    ErrorDescription1 = maps:get(cause, ErrorInfo),
    ErrorDescription2 = maps:map(fun format_error_description/2, ErrorDescription1),
    ErrorDescription2.

%% @private
-spec format_error_description(dynamic(), dynamic()) -> dynamic().
format_error_description(_Key, {invalid_decode_character, #{'case' := Case, 'char' := Char}}) ->
    Requirements =
        case Case of
            'lower' ->
                " (must be one of 0..9 or a..f)";
            'mixed' ->
                " (must be one of 0..9, A..F, or a..f)";
            'upper' ->
                " (must be one of 0..9 or A..F)"
        end,
    io_lib:format("invalid decode character for 'case' mode '~ts': ~0tp~ts", [Case, [Char], Requirements]);
format_error_description(_Key, {invalid_decode_input_length, InputLength}) ->
    io_lib:format("invalid decode input length (must be divisible by 2, but was ~0tp)", [InputLength]);
format_error_description(_Key, {invalid_decode_option_case, Case}) ->
    io_lib:format("invalid decode option for 'case' (must be either 'lower', 'mixed', or 'upper', but was ~0tP)", [
        Case, 5
    ]);
format_error_description(_Key, {invalid_encode_option_case, Case}) ->
    io_lib:format("invalid encode option for 'case' (must be either 'lower' or 'upper', but was ~0tP)", [Case, 5]);
format_error_description(_Key, {invalid_output_length, OutputLength}) ->
    io_lib:format("invalid output length (must be 0 or greater than 1 and divisible by 2, but was ~0tP)", [
        OutputLength, 5
    ]);
format_error_description(_Key, Value) ->
    Value.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
