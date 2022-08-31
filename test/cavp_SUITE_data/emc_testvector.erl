%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  12 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(emc_testvector).

%% API
-export([from_binary/1]).
-export([from_file/1]).
-export([to_binary/1]).
-export([to_file/2]).

%%====================================================================
%% API functions
%%====================================================================

from_binary(Binary) ->
	Lines = [Line || Line <- binary:split(Binary, [<< $\n >>, << $\r >>], [global, trim]), Line =/= <<>>],
	parse_lines(Lines, []).

from_file(File) ->
	case file:read_file(File) of
		{ok, Binary} ->
			from_binary(Binary);
		ReadError ->
			ReadError
	end.

to_binary(Vectors) when is_list(Vectors) ->
	<<
		<<
			(case Vector of
				divider ->
					<<
						$\n,
						"# =============================================\n",
						$\n
					>>;
				{example, Example} ->
					ExampleLen = byte_size(Example),
					Bar = binary:copy(<<"=">>, ExampleLen),
					<<
						$\n,
						"# ", Bar/binary, $\n,
						"# ", Example/binary, $\n,
						"# ", Bar/binary, $\n,
						$\n
					>>;
				{component, Component} ->
					ComponentLen = byte_size(Component),
					Bar = binary:copy(<<"-">>, ComponentLen),
					<<
						$\n,
						"# ", Bar/binary, $\n,
						"# ", Component/binary, $\n,
						"# ", Bar/binary, $\n,
						$\n
					>>;
				{vector, {Key, Val}} ->
					Hex = hex:bin_to_hex(Val),
					HexLines = to_hex_lines(Hex, <<>>, []),
					HexBlocks = << << HexLine/binary, $\n >> || HexLine <- HexLines >>,
					<<
						"# ", Key/binary, $:, $\n,
						HexBlocks/binary,
						$\n
					>>
			end)/binary
		>>
		|| Vector <- Vectors
	>>.

to_file(File, State={_, _, _}) ->
	Binary = to_binary(State),
	file:write_file(File, Binary).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
parse_lines([], Acc) ->
	lists:reverse(Acc);
parse_lines([
			<< "# =======", _/binary >>,
			<< "# Example", Example/binary >>,
			<< "# =======", _/binary >>
			| Lines
		], Acc) ->
	parse_lines(Lines, [{example, << "Example", Example/binary >>} | Acc]);
parse_lines([
			<< "# ----", _/binary >>,
			<< "# ", Component/binary >>,
			<< "# ----", _/binary >>
			| Lines
		], Acc) ->
	parse_lines(Lines, [{component, Component} | Acc]);
parse_lines([
			<< " ----", _/binary >>,
			<< "# ", Component/binary >>,
			<< " ----", _/binary >>
			| Lines
		], Acc) ->
	parse_lines(Lines, [{component, Component} | Acc]);
parse_lines([<<"# =============================================">> | Lines], Acc) ->
	parse_lines(Lines, [divider | Acc]);
parse_lines([<< "# ", Key/binary >> | Lines], Acc) when length(Acc) > 0 ->
	case parse_key(Key) of
		skip ->
			parse_lines(Lines, Acc);
		NewKey ->
			parse_vector(Lines, NewKey, <<>>, Acc)
	end;
parse_lines([_Line | Lines], Acc) ->
	parse_lines(Lines, Acc).

%% @private
parse_key(Key) ->
	case binary:match(Key, << $: >>) of
		{Pos, 1} ->
			binary:part(Key, 0, Pos);
		nomatch ->
			skip
	end.

%% @private
parse_vector(Lines = [<< $#, _/binary >> | _], Key, Hex, Acc) ->
	Val = hex:hex_to_bin(Hex),
	parse_lines(Lines, [{vector, {Key, Val}} | Acc]);
parse_vector(Lines = [<< "# ----", _/binary >> | _], Key, Hex, Acc) ->
	Val = hex:hex_to_bin(Hex),
	parse_lines(Lines, [{vector, {Key, Val}} | Acc]);
parse_vector(Lines = [<< " ----", _/binary >> | _], Key, Hex, Acc) ->
	Val = hex:hex_to_bin(Hex),
	parse_lines(Lines, [{vector, {Key, Val}} | Acc]);
parse_vector([HexLine | Lines], Key, Hex, Acc) ->
	case parse_vector_hexline(HexLine, Hex) of
		{ok, NewHex} ->
			Val = hex:hex_to_bin(NewHex),
			parse_lines([HexLine | Lines], [{vector, {Key, Val}} | Acc]);
		{next, NewHex} ->
			parse_vector(Lines, Key, NewHex, Acc)
	end.

%% @private
parse_vector_hexline(<< $\s, Rest/binary >>, Hex) ->
	parse_vector_hexline(Rest, Hex);
parse_vector_hexline(<< C, Rest/binary >>, Hex)
		when (C >= $A andalso C =< $Z)
		orelse (C >= $a andalso C =< $z)
		orelse (C >= $0 andalso C =< $9) ->
	parse_vector_hexline(Rest, << Hex/binary, C >>);
parse_vector_hexline(<<>>, Hex) ->
	{next, Hex};
parse_vector_hexline(Rest, Hex) ->
	erlang:error({badarg, [Rest, Hex]}).

%% @private
to_hex_lines(Rest, Line, Lines) when byte_size(Line) >= 48 ->
	to_hex_lines(Rest, <<>>, [Line | Lines]);
to_hex_lines(<< A, B, Rest/binary >>, Line, Lines) ->
	to_hex_lines(Rest, << Line/binary, A, B, $\s >>, Lines);
to_hex_lines(<<>>, <<>>, Lines) ->
	lists:reverse(Lines);
to_hex_lines(<<>>, Line, Lines) ->
	lists:reverse([Line | Lines]).
