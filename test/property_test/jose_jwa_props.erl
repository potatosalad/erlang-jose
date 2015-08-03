%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_props).

-include_lib("triq/include/triq.hrl").

-compile(export_all).

prop_constant_time_compare() ->
	?FORALL(Binary,
		?SUCHTHAT(Binary,
			binary(),
			byte_size(Binary) >= 1),
		begin
			jose_jwa:constant_time_compare(Binary, Binary)
		end).
