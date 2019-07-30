%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2017-2019, Andrew Bennett
%%% @doc RFC 4648, Section 4: https://tools.ietf.org/html/rfc4648#section-4
%%%
%%% @end
%%% Created :  11 May 2017 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_base64).
-compile({parse_transform, jose_base}).

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

% Macros
-define(B64_TO_INT(C),
	case C of
		$A -> 16#00;
		$B -> 16#01;
		$C -> 16#02;
		$D -> 16#03;
		$E -> 16#04;
		$F -> 16#05;
		$G -> 16#06;
		$H -> 16#07;
		$I -> 16#08;
		$J -> 16#09;
		$K -> 16#0A;
		$L -> 16#0B;
		$M -> 16#0C;
		$N -> 16#0D;
		$O -> 16#0E;
		$P -> 16#0F;
		$Q -> 16#10;
		$R -> 16#11;
		$S -> 16#12;
		$T -> 16#13;
		$U -> 16#14;
		$V -> 16#15;
		$W -> 16#16;
		$X -> 16#17;
		$Y -> 16#18;
		$Z -> 16#19;
		$a -> 16#1A;
		$b -> 16#1B;
		$c -> 16#1C;
		$d -> 16#1D;
		$e -> 16#1E;
		$f -> 16#1F;
		$g -> 16#20;
		$h -> 16#21;
		$i -> 16#22;
		$j -> 16#23;
		$k -> 16#24;
		$l -> 16#25;
		$m -> 16#26;
		$n -> 16#27;
		$o -> 16#28;
		$p -> 16#29;
		$q -> 16#2A;
		$r -> 16#2B;
		$s -> 16#2C;
		$t -> 16#2D;
		$u -> 16#2E;
		$v -> 16#2F;
		$w -> 16#30;
		$x -> 16#31;
		$y -> 16#32;
		$z -> 16#33;
		$0 -> 16#34;
		$1 -> 16#35;
		$2 -> 16#36;
		$3 -> 16#37;
		$4 -> 16#38;
		$5 -> 16#39;
		$6 -> 16#3A;
		$7 -> 16#3B;
		$8 -> 16#3C;
		$9 -> 16#3D;
		$+ -> 16#3E;
		$/ -> 16#3F
	end).

-define(INT_TO_B64(C),
	case C of
		16#00 -> $A;
		16#01 -> $B;
		16#02 -> $C;
		16#03 -> $D;
		16#04 -> $E;
		16#05 -> $F;
		16#06 -> $G;
		16#07 -> $H;
		16#08 -> $I;
		16#09 -> $J;
		16#0A -> $K;
		16#0B -> $L;
		16#0C -> $M;
		16#0D -> $N;
		16#0E -> $O;
		16#0F -> $P;
		16#10 -> $Q;
		16#11 -> $R;
		16#12 -> $S;
		16#13 -> $T;
		16#14 -> $U;
		16#15 -> $V;
		16#16 -> $W;
		16#17 -> $X;
		16#18 -> $Y;
		16#19 -> $Z;
		16#1A -> $a;
		16#1B -> $b;
		16#1C -> $c;
		16#1D -> $d;
		16#1E -> $e;
		16#1F -> $f;
		16#20 -> $g;
		16#21 -> $h;
		16#22 -> $i;
		16#23 -> $j;
		16#24 -> $k;
		16#25 -> $l;
		16#26 -> $m;
		16#27 -> $n;
		16#28 -> $o;
		16#29 -> $p;
		16#2A -> $q;
		16#2B -> $r;
		16#2C -> $s;
		16#2D -> $t;
		16#2E -> $u;
		16#2F -> $v;
		16#30 -> $w;
		16#31 -> $x;
		16#32 -> $y;
		16#33 -> $z;
		16#34 -> $0;
		16#35 -> $1;
		16#36 -> $2;
		16#37 -> $3;
		16#38 -> $4;
		16#39 -> $5;
		16#3A -> $6;
		16#3B -> $7;
		16#3C -> $8;
		16#3D -> $9;
		16#3E -> $+;
		16#3F -> $/
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
	Padding = maps:get('padding', Opts, nil),
	Size = erlang:iolist_size(Input),
	Offset =
		case Padding of
			_ when (Padding == false orelse Padding == nil) andalso Size =< 4 ->
				0;
			_ when (Padding == false orelse Padding == nil) andalso (Size rem 4) =/= 0 ->
				Size - (Size rem 4);
			_ when (Padding == false orelse Padding == nil) ->
				Size - 4;
			_ when (Padding == true orelse Padding == nil) andalso Size >= 4 ->
				Size - 4;
			_ ->
				erlang:error({badarg, [Input, Opts]})
		end,
	<< Head0:Offset/binary, Tail0/binary >> = ?to_binary(Input),
	Head = << << (?B64_TO_INT(V)):6 >> || << V >> <= Head0 >>,
	Tail =
		case Padding of
			false ->
				case Tail0 of
					<< T0:8, T1:8 >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1) bsr 4):2 >>;
					<< T0:8, T1:8, T2:8 >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1)):6, (?B64_TO_INT(T2) bsr 2):4 >>;
					<< T:4/binary >> ->
						<< << (?B64_TO_INT(V)):6 >> || << V >> <= T >>;
					<<>> ->
						<<>>;
					_ ->
						erlang:error({badarg, [Input, Opts]})
				end;
			nil ->
				case Tail0 of
					<< T0:8, T1:8, $=, $= >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1) bsr 4):2 >>;
					<< T0:8, T1:8, T2:8, $= >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1)):6, (?B64_TO_INT(T2) bsr 2):4 >>;
					<< T0:8, T1:8 >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1) bsr 4):2 >>;
					<< T0:8, T1:8, T2:8 >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1)):6, (?B64_TO_INT(T2) bsr 2):4 >>;
					<< T:4/binary >> ->
						<< << (?B64_TO_INT(V)):6 >> || << V >> <= T >>;
					<<>> ->
						<<>>
				end;
			true ->
				case Tail0 of
					<< T0:8, T1:8, $=, $= >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1) bsr 4):2 >>;
					<< T0:8, T1:8, T2:8, $= >> ->
						<< (?B64_TO_INT(T0)):6, (?B64_TO_INT(T1)):6, (?B64_TO_INT(T2) bsr 2):4 >>;
					<< T:4/binary >> ->
						<< << (?B64_TO_INT(V)):6 >> || << V >> <= T >>;
					<<>> ->
						<<>>;
					_ ->
						erlang:error({badarg, [Input, Opts]})
				end
		end,
	<< Head/binary, Tail/binary >>;
'decode!'(Input, Opts) when ?is_iodata(Input) andalso is_list(Opts) ->
	'decode!'(Input, maps:from_list(Opts)).

encode(Input) when ?is_iodata(Input) ->
	encode(Input, #{}).

encode(Input, Opts) when ?is_iodata(Input) andalso is_map(Opts) ->
	Padding = maps:get('padding', Opts, true),
	Offset = 6 * (erlang:iolist_size(Input) div 6),
	<< Head:Offset/binary, Tail/binary >> = ?to_binary(Input),
	H = << << (encode_pair(V0)):16, (encode_pair(V1)):16, (encode_pair(V2)):16, (encode_pair(V3)):16 >> || << V0:12, V1:12, V2:12, V3:12 >> <= Head >>,
	{T, Pad} =
		case Tail of
			<< T0:12, T1:12, T2:12, T3:4 >> ->
				{<< (encode_pair(T0)):16, (encode_pair(T1)):16, (encode_pair(T2)):16, (encode_char(T3 bsl 2)):8 >>, << $= >>};
			<< T0:12, T1:12, T2:8 >> ->
				{<< (encode_pair(T0)):16, (encode_pair(T1)):16, (encode_pair(T2 bsl 4)):16 >>, << $=, $= >>};
			<< T0:12, T1:12 >> ->
				{<< (encode_pair(T0)):16, (encode_pair(T1)):16 >>, <<>>};
			<< T0:12, T1:4 >> ->
				{<< (encode_pair(T0)):16, (encode_char(T1 bsl 2)):8 >>, <<>>};
			<< T0:8 >> ->
				{<< (encode_pair(T0 bsl 4)):16 >>, << $=, $= >>};
			<<>> ->
				{<<>>, <<>>}
		end,
	case Padding of
		true ->
			<< H/binary, T/binary, Pad/binary >>;
		false ->
			<< H/binary, T/binary >>;
		_ ->
			erlang:error({badarg, [Input, Opts]})
	end;
encode(Input, Opts) when ?is_iodata(Input) andalso is_list(Opts) ->
	encode(Input, maps:from_list(Opts)).

random(Bytes) when is_integer(Bytes) andalso Bytes >= 0 ->
	random(Bytes, #{}).

random(0, Opts) when is_map(Opts) ->
	<<>>;
random(Bytes, Opts) when (Bytes =:= 1) andalso is_map(Opts) ->
	erlang:error({badarg, [Bytes, Opts]});
random(Bytes, Opts) when is_integer(Bytes) andalso Bytes > 0 andalso is_map(Opts) ->
	Padding = maps:get('padding', Opts, true),
	R = (Bytes rem 4),
	Size =
		case Padding of
			true when R =:= 0 ->
				(Bytes * 3) div 4;
			false when R =:= 0 orelse R =:= 2 orelse R =:= 3 ->
				(Bytes * 3) div 4;
			_ ->
				erlang:error({badarg, [Bytes, Opts]})
		end,
	Binary = crypto:strong_rand_bytes(Size),
	encode(Binary, Opts);
random(Bytes, Opts) when is_integer(Bytes) andalso Bytes >= 0 andalso is_list(Opts) ->
	random(Bytes, maps:from_list(Opts)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
encode_char(V) ->
	jose_base:encode_char(?INT_TO_B64(V)).

%% @private
encode_pair(V) ->
	jose_base:encode_pair(?INT_TO_B64(V), sensitive).
