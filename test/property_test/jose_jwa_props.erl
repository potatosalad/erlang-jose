%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
-module(jose_jwa_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

prop_constant_time_compare() ->
    ?FORALL(
        Binary,
        ?SUCHTHAT(
            Binary,
            binary(),
            byte_size(Binary) >= 1
        ),
        begin
            jose_jwa:constant_time_compare(Binary, Binary)
        end
    ).
