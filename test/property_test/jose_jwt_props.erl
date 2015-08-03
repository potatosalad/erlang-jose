%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwt_props).

-include_lib("triq/include/triq.hrl").

-compile(export_all).

prop_one_plus_one() ->
	_ = application:ensure_all_started(cutkey),
	?FORALL(One,
		oneof([1]),
		begin
			(One + One) =:= 2
		end).
