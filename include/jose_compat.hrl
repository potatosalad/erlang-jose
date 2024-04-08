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
%%% Created :  19 Nov 2018 by Emil Falk <emil.falk@textalk.se>
%%%-----------------------------------------------------------------------------
%%% % @format
-ifndef(JOSE_COMPAT_HRL).

%% this implies OTP 21 or higher
-ifdef(OTP_RELEASE).
-define(COMPAT_CATCH(Class, Reason, Stacktrace), Class:Reason:Stacktrace).
-define(COMPAT_GET_STACKTRACE(Stacktrace), Stacktrace).

-if(?OTP_RELEASE >= 23).
-define(JOSE_CRYPTO_OTP_23, 1).
-endif.
-else.
-define(COMPAT_CATCH(Class, Reason, _), Class:Reason).
-define(COMPAT_GET_STACKTRACE(_), erlang:get_stacktrace()).
-endif.

-define(JOSE_COMPAT_HRL, 1).

-endif.
