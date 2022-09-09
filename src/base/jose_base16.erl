%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: nil; st-rulers: [132] -*-
%% vim: ts=4 sw=4 ft=erlang et
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc RFC 4648, Section 8: https://tools.ietf.org/html/rfc4648#section-8
%%%
%%% @end
%%% Created :  11 May 2017 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_base16).

-include("jose_base.hrl").

%% API
-export([decode/1]).
-export([decode/2]).
-export(['decode!'/1]).
-export(['decode!'/2]).
-export([encode/1]).
-export([encode/2]).
-export([random/1]).
-export([random/2]).

%% Macros
-define(LC_B16_TO_INT(C),
	case C of
		$0 -> 16#0;
		$1 -> 16#1;
		$2 -> 16#2;
		$3 -> 16#3;
		$4 -> 16#4;
		$5 -> 16#5;
		$6 -> 16#6;
		$7 -> 16#7;
		$8 -> 16#8;
		$9 -> 16#9;
		$a -> 16#A;
		$b -> 16#B;
		$c -> 16#C;
		$d -> 16#D;
		$e -> 16#E;
		$f -> 16#F
	end).

-define(MC_B16_TO_INT(C),
	case C of
		$0 -> 16#0;
		$1 -> 16#1;
		$2 -> 16#2;
		$3 -> 16#3;
		$4 -> 16#4;
		$5 -> 16#5;
		$6 -> 16#6;
		$7 -> 16#7;
		$8 -> 16#8;
		$9 -> 16#9;
		$a -> 16#A;
		$b -> 16#B;
		$c -> 16#C;
		$d -> 16#D;
		$e -> 16#E;
		$f -> 16#F;
		$A -> 16#A;
		$B -> 16#B;
		$C -> 16#C;
		$D -> 16#D;
		$E -> 16#E;
		$F -> 16#F
	end).

-define(UC_B16_TO_INT(C),
	case C of
		$0 -> 16#0;
		$1 -> 16#1;
		$2 -> 16#2;
		$3 -> 16#3;
		$4 -> 16#4;
		$5 -> 16#5;
		$6 -> 16#6;
		$7 -> 16#7;
		$8 -> 16#8;
		$9 -> 16#9;
		$A -> 16#A;
		$B -> 16#B;
		$C -> 16#C;
		$D -> 16#D;
		$E -> 16#E;
		$F -> 16#F
	end).

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
	end).

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
	end).

%%%===================================================================
%%% API functions
%%%===================================================================

decode(Input) when ?is_iodata(Input) ->
	decode(Input, #{}).

decode(Input, Opts) when ?is_iodata(Input) andalso is_map(Opts) ->
	try 'decode!'(Input, Opts) of
		Output when is_binary(Output) ->
			{ok, Output}
	catch
		_:_ ->
			error
	end;
decode(Input, Opts) when ?is_iodata(Input) andalso is_list(Opts) ->
	decode(Input, maps:from_list(Opts)).

'decode!'(Input) when ?is_iodata(Input) ->
	'decode!'(Input, #{}).

'decode!'([], #{}) ->
	<<>>;
'decode!'(<<>>, #{}) ->
	<<>>;
'decode!'(Input, Opts) when ?is_iodata(Input) andalso is_map(Opts) ->
	Case = maps:get('case', Opts, 'mixed'),
	case {Case, erlang:iolist_size(Input) rem 2} of
		{'lower', 0} ->
			<< << ((?LC_B16_TO_INT(X) bsl 4) + ?LC_B16_TO_INT(Y)) >> || << X, Y >> <= ?to_binary(Input) >>;
		{'mixed', 0} ->
			<< << ((?MC_B16_TO_INT(X) bsl 4) + ?MC_B16_TO_INT(Y)) >> || << X, Y >> <= ?to_binary(Input) >>;
		{'upper', 0} ->
			<< << ((?UC_B16_TO_INT(X) bsl 4) + ?UC_B16_TO_INT(Y)) >> || << X, Y >> <= ?to_binary(Input) >>;
		_ ->
			erlang:error({badarg, [Input, Opts]})
	end;
'decode!'(Input, Opts) when ?is_iodata(Input) andalso is_list(Opts) ->
	'decode!'(Input, maps:from_list(Opts)).

encode(Input) when ?is_iodata(Input) ->
	encode(Input, #{}).

encode(Input, Opts) when ?is_iodata(Input) andalso is_map(Opts) ->
	Case = maps:get('case', Opts, 'upper'),
	case Case of
		'lower' ->
			<< << (?LC_INT_TO_B16(V bsr 4)), (?LC_INT_TO_B16(V band 16#F)) >> || << V >> <= ?to_binary(Input) >>;
		'upper' ->
			<< << (?UC_INT_TO_B16(V bsr 4)), (?UC_INT_TO_B16(V band 16#F)) >> || << V >> <= ?to_binary(Input) >>;
		_ ->
			erlang:error({badarg, [Input, Opts]})
	end;
encode(Input, Opts) when ?is_iodata(Input) andalso is_list(Opts) ->
	encode(Input, maps:from_list(Opts)).

random(Bytes) when is_integer(Bytes) andalso Bytes >= 0 ->
	random(Bytes, #{}).

random(0, Opts) when is_map(Opts) ->
	<<>>;
random(Bytes, Opts) when (Bytes =:= 1 orelse (Bytes rem 2) =/= 0) andalso is_map(Opts) ->
	erlang:error({badarg, [Bytes, Opts]});
random(Bytes, Opts) when is_integer(Bytes) andalso Bytes > 0 andalso is_map(Opts) ->
	Size = Bytes div 2,
	Binary = crypto:strong_rand_bytes(Size),
	encode(Binary, Opts);
random(Bytes, Opts) when is_integer(Bytes) andalso Bytes >= 0 andalso is_list(Opts) ->
	random(Bytes, maps:from_list(Opts)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
