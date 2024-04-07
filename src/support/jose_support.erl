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
%%% Created :  04 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-module(jose_support).

%% API
-export([
    builtin_support_modules/0,
    builtin_provider_modules/0,
    deps/0,
    expect/1,
    expect/4,
    expect/5,
    expect_report/5
]).

-type behaviour() :: module().
-type callback() :: {function_name(), arity()}.
-type callback_requirement() :: {behaviour(), list(callback())}.
-type callback_spec() :: {callback(), list(callback_requirement())}.
-type function_name() :: atom().
-type key() :: {behaviour(), callback()}.
-type priority() :: low | normal | high | max.
-type requirement() :: {app, atom()} | module().

-type support_check_result() :: ok | {error, expect_report()}.
-type expect_report() :: #{
    mfa := {module(), function_name(), arity()},
    actual := term(),
    expected := term()
}.
-type impl() :: #{
    behaviour := behaviour(),
    priority := priority(),
    requirements := list(requirement()),
    callbacks := list(callback_spec())
}.

-type info() :: #{
    stateful := [[callback()]],
    callbacks := list(callback_spec())
}.

-export_type([
    behaviour/0,
    callback/0,
    callback_requirement/0,
    callback_spec/0,
    function_name/0,
    key/0,
    priority/0,
    requirement/0,
    support_check_result/0,
    expect_report/0,
    impl/0,
    info/0
]).

%% Callbacks
-callback check(Module :: module(), FunctionName :: function_name(), Arity :: arity()) ->
    Result :: support_check_result().
-callback support_info() -> jose_support:info().
-callback support_check(Module :: module(), FunctionName :: function_name(), Arity :: arity()) ->
    Result :: support_check_result().

-optional_callbacks([
    check/3,
    support_info/0,
    support_check/3
]).

builtin_support_modules() ->
    [
        jose_aes_cbc,
        jose_aes_cbc_hmac,
        jose_aes_ctr,
        jose_aes_ecb,
        jose_aes_gcm,
        jose_aes_kw,
        jose_chacha20,
        jose_chacha20_poly1305,
        jose_csprng,
        jose_curve25519,
        jose_curve448,
        jose_ec,
        jose_hchacha20,
        jose_hmac,
        jose_json,
        jose_pbkdf2_hmac,
        jose_poly1305,
        jose_rsa,
        jose_sha1,
        jose_sha2,
        jose_sha3,
        jose_xchacha20,
        jose_xchacha20_poly1305
    ].

builtin_provider_modules() ->
    [
        %% AES-CBC
        jose_jwa_aes_cbc,
        jose_aes_cbc_crypto,
        %% AES-CBC-HMAC
        jose_jwa_aes_cbc_hmac,
        %% AES-CTR
        jose_jwa_aes_ctr,
        jose_aes_ctr_crypto,
        %% AES-ECB
        jose_jwa_aes_ecb,
        jose_aes_ecb_crypto,
        %% AES-GCM
        jose_jwa_aes_gcm,
        jose_aes_gcm_crypto,
        jose_aes_gcm_libsodium,
        %% AES-KW
        jose_jwa_aes_kw,
        %% ChaCha20
        jose_jwa_chacha20,
        jose_chacha20_crypto,
        jose_chacha20_libsodium,
        %% ChaCha20-Poly1305
        jose_jwa_chacha20_poly1305,
        jose_chacha20_poly1305_crypto,
        jose_chacha20_poly1305_libsodium,
        %% CSPRNG
        jose_csprng_crypto,
        jose_csprng_libdecaf,
        jose_csprng_libsodium,
        %% Curve25519
        jose_jwa_curve25519,
        jose_curve25519_crypto,
        jose_curve25519_libdecaf,
        jose_curve25519_libsodium,
        %% Curve448
        jose_jwa_curve448,
        jose_curve448_crypto,
        jose_curve448_libdecaf,
        %% EC
        jose_ec_crypto,
        %% HChaCha20
        jose_jwa_hchacha20,
        jose_hchacha20_crypto,
        jose_hchacha20_libsodium,
        %% HMAC
        jose_hmac_crypto,
        %% JSON
        jose_json_jason,
        jose_json_jiffy,
        jose_json_jsone,
        jose_json_jsx,
        jose_json_ojson,
        % jose_json_poison,
        jose_json_poison_compat_encoder,
        jose_json_poison_lexical_encoder,
        jose_json_thoas,
        %% PBKDF2-HMAC
        jose_jwa_pbkdf2_hmac,
        jose_pbkdf2_hmac_crypto,
        %% Poly1305
        jose_jwa_poly1305,
        jose_poly1305_crypto,
        jose_poly1305_libsodium,
        %% RSA
        jose_jwa_rsa,
        jose_rsa_crypto,
        %% SHA-1
        jose_sha1_crypto,
        %% SHA-2
        jose_sha2_crypto,
        jose_sha2_libdecaf,
        jose_sha2_libsodium,
        %% SHA-3
        jose_jwa_sha3,
        jose_sha3_crypto,
        jose_sha3_keccakf1600_driver,
        jose_sha3_keccakf1600_nif,
        jose_sha3_libdecaf,
        %% XChaCha20
        jose_jwa_xchacha20,
        % jose_xchacha20_crypto,
        jose_xchacha20_libsodium,
        %% XChaCha20-Poly1305
        jose_jwa_xchacha20_poly1305,
        jose_xchacha20_poly1305_crypto,
        jose_xchacha20_poly1305_libsodium
    ].

deps() ->
    graph(builtin_support_modules(), builtin_provider_modules()).

expect([{Expected, Module, Function, Arguments} | Rest]) when
    is_atom(Module) andalso
        is_atom(Function) andalso
        is_list(Arguments)
->
    case expect(Expected, Module, Function, Arguments) of
        ok ->
            expect(Rest);
        Error = {error, _Reason} ->
            Error
    end;
expect([{Expected, Actual, Module, Function, Arguments} | Rest]) when
    is_atom(Module) andalso
        is_atom(Function) andalso
        is_list(Arguments)
->
    case expect(Expected, Actual, Module, Function, Arguments) of
        ok ->
            expect(Rest);
        Error = {error, _Reason} ->
            Error
    end;
expect([]) ->
    ok.

expect(Expected, Module, Function, Arguments) when
    is_atom(Module) andalso
        is_atom(Function) andalso
        is_list(Arguments)
->
    Actual = erlang:apply(Module, Function, Arguments),
    expect(Expected, Actual, Module, Function, Arguments).

expect(Expected, Actual, Module, Function, Arguments) when
    is_atom(Module) andalso
        is_atom(Function) andalso
        is_list(Arguments)
->
    case Actual =:= Expected of
        true ->
            ok;
        false ->
            {error, expect_report(Module, Function, Arguments, Actual, Expected)}
    end.

expect_report(Module, Function, Arguments, Actual, Expected) ->
    MFA = {Module, Function, Arguments},
    {EncodedActual, EncodedExpected} =
        case {Actual, Expected} of
            {<<_/binary>>, <<_/binary>>} ->
                {jose_base16:encode(Actual, #{'case' => lower}), jose_base16:encode(Expected, #{'case' => lower})};
            {{A = <<_/binary>>, B = <<_/binary>>}, {C = <<_/binary>>, D = <<_/binary>>}} ->
                Enc = fun(X) -> jose_base16:encode(X, #{'case' => lower}) end,
                {{Enc(A), Enc(B)}, {Enc(C), Enc(D)}};
            {{A, B = <<_/binary>>}, {C, D = <<_/binary>>}} ->
                Enc = fun(X) -> jose_base16:encode(X, #{'case' => lower}) end,
                {{A, Enc(B)}, {C, Enc(D)}};
            _ ->
                {Actual, Expected}
        end,
    #{mfa => MFA, actual => EncodedActual, expected => EncodedExpected}.

%% @private
priority_to_integer(low) ->
    3;
priority_to_integer(normal) ->
    2;
priority_to_integer(high) ->
    1;
priority_to_integer(max) ->
    0.

%% @private
graph(SupportModules, ProviderModules) when is_list(SupportModules) andalso is_list(ProviderModules) ->
    Graph = digraph:new(),
    Failures = ets:new(failures, [set, protected]),
    Behaviours = ets:new(behaviours, [set, protected]),
    Providers = ets:new(providers, [bag, protected]),
    try
        graph(Graph, Failures, Providers, Behaviours, SupportModules, ProviderModules)
    after
        ets:delete(Providers),
        ets:delete(Behaviours),
        ets:delete(Failures),
        digraph:delete(Graph)
    end.

%% @private
graph(Graph, Failures, Providers, Behaviours, SupportModules, ProviderModules) ->
    ok = lists:foreach(
        fun(SupportModule) ->
            _ = code:ensure_loaded(SupportModule),
            case erlang:function_exported(SupportModule, support_info, 0) of
                true ->
                    try SupportModule:support_info() of
                        #{
                            stateful := Stateful,
                            callbacks := Callbacks
                        } ->
                            true = ets:insert(Behaviours, {SupportModule, {Stateful, Callbacks}}),
                            lists:foreach(
                                fun({Callback, _CallbackRequirements}) ->
                                    digraph:add_vertex(Graph, {SupportModule, Callback})
                                end,
                                Callbacks
                            )
                    catch
                        Class:Reason:Stacktrace ->
                            ets:insert(Failures, {SupportModule, {exception, {Class, Reason, Stacktrace}}})
                    end;
                false ->
                    ets:insert(Failures, {SupportModule, {function_not_exported, {support_info, 0}}})
            end
        end,
        SupportModules
    ),
    ok = lists:foreach(
        fun({Behaviour, {_Stateful, Callbacks}}) ->
            lists:foreach(
                fun({Callback, CallbackRequirements}) ->
                    lists:foreach(
                        fun({RequiredBehaviour, RequiredCallbacks}) ->
                            lists:foreach(
                                fun(RequiredCallback) ->
                                    digraph:add_edge(
                                        Graph, {RequiredBehaviour, RequiredCallback}, {Behaviour, Callback}
                                    )
                                end,
                                RequiredCallbacks
                            )
                        end,
                        CallbackRequirements
                    )
                end,
                Callbacks
            )
        end,
        ets:tab2list(Behaviours)
    ),
    ok = lists:foreach(
        fun(ProviderModule) ->
            _ = code:ensure_loaded(ProviderModule),
            case erlang:function_exported(ProviderModule, provider_info, 0) of
                true ->
                    try ProviderModule:provider_info() of
                        #{
                            behaviour := Behaviour,
                            priority := Priority,
                            requirements := Requirements
                        } ->
                            case ensure_requirements_loaded(Requirements) of
                                true ->
                                    [{Behaviour, {_Stateful, Callbacks}}] = ets:lookup(Behaviours, Behaviour),
                                    lists:foreach(
                                        fun({Callback = {FunctionName, Arity}, _CallbackRequirements}) ->
                                            case erlang:function_exported(ProviderModule, FunctionName, Arity) of
                                                true ->
                                                    true = ets:insert(
                                                        Providers,
                                                        {{Behaviour, Callback}, {
                                                            priority_to_integer(Priority), ProviderModule
                                                        }}
                                                    ),
                                                    ok;
                                                false ->
                                                    ok
                                            end
                                        end,
                                        Callbacks
                                    );
                                false ->
                                    ets:insert(Failures, {ProviderModule, {requirements_not_met, Requirements}})
                            end
                    catch
                        Class:Reason:Stacktrace ->
                            ets:insert(Failures, {ProviderModule, {exception, {Class, Reason, Stacktrace}}})
                    end;
                false ->
                    ets:insert(Failures, {ProviderModule, {function_not_exported, {provider_info, 0}}})
            end
        end,
        ProviderModules
    ),
    BehavioursMap = maps:from_list(ets:tab2list(Behaviours)),
    FailuresMap = maps:from_list(ets:tab2list(Failures)),
    ProvidersMap =
        groups_from_list(
            fun({K, _}) -> K end,
            fun({_, V}) -> V end,
            ets:tab2list(Providers)
        ),
    NotSupported0 =
        lists:foldl(
            fun(V, Acc) ->
                case maps:is_key(V, ProvidersMap) andalso not maps:is_key(V, Acc) of
                    true ->
                        Acc;
                    false ->
                        MarkNotSupported = fun MarkNotSupported(BadV, Acc0) ->
                            OutVs = digraph:out_neighbours(Graph, BadV),
                            Acc1 = maps:put(BadV, [], Acc0),
                            true = digraph:del_vertex(Graph, BadV),
                            case OutVs of
                                [] ->
                                    Acc1;
                                OutVs = [_ | _] ->
                                    lists:foldl(MarkNotSupported, Acc1, OutVs)
                            end
                        end,
                        MarkNotSupported(V, Acc)
                end
            end,
            maps:new(),
            digraph:vertices(Graph)
        ),
    NotSupported = lists:usort(maps:keys(NotSupported0)),
    case digraph_utils:topsort(Graph) =/= false of
        true ->
            {ok, #{
                behaviours => BehavioursMap,
                failures => FailuresMap,
                not_supported => NotSupported,
                plan => topological_sort(Graph),
                providers => ProvidersMap
            }};
        false ->
            {error, badgraph}
    end.

topological_sort(G) ->
    topological_sort(digraph:vertices(G), [], [], queue:new(), G).

topological_sort(L0, P0, S0, G) ->
    case queue:out(S0) of
        {{value, Vn}, S1} ->
            case digraph:out_neighbours(G, Vn) of
                [] ->
                    true = digraph:del_vertex(G, Vn),
                    P1 = [Vn | P0],
                    topological_sort(L0, P1, S1, G);
                Vms = [_ | _] ->
                    % Also deletes all edges for Vn -> Vm
                    true = digraph:del_vertex(G, Vn),
                    L1 = [Vn | L0],
                    topological_sort(Vms, L1, P0, S1, G)
            end;
        {empty, S0} ->
            [] = digraph:vertices(G),
            [
                {serial, lists:reverse(L0)},
                {parallel, P0}
            ]
    end.

topological_sort([Vm | Vms], L0, P0, S0, G) ->
    S1 = topological_sort_maybe_enqueue_vertex(Vm, S0, G),
    topological_sort(Vms, L0, P0, S1, G);
topological_sort([], L0, P0, S0, G) ->
    topological_sort(L0, P0, S0, G).

topological_sort_maybe_enqueue_vertex(V, S, G) ->
    case digraph:in_degree(G, V) =:= 0 of
        true ->
            case digraph:out_degree(G, V) =:= 0 of
                true ->
                    queue:in(V, S);
                false ->
                    queue:in_r(V, S)
            end;
        false ->
            S
    end.

%% @private
ensure_requirements_loaded([{app, App} | Rest]) ->
    case application:ensure_all_started(App) of
        {ok, _} ->
            ensure_requirements_loaded(Rest);
        {error, _} ->
            false
    end;
ensure_requirements_loaded([Module | Rest]) when is_atom(Module) ->
    case code:ensure_loaded(Module) of
        {module, Module} ->
            ensure_requirements_loaded(Rest);
        {error, _} ->
            false
    end;
ensure_requirements_loaded([]) ->
    true.

%% NOTE: switch out for maps:groups_from_list/3 after minimum supported version is OTP 25+
%% @private
groups_from_list(Fun, ValueFun, List0) when
    is_function(Fun, 1),
    is_function(ValueFun, 1)
->
    try lists:reverse(List0) of
        List ->
            groups_from_list_2(Fun, ValueFun, List, #{})
    catch
        error:_ ->
            badarg_with_info([Fun, ValueFun, List0])
    end;
groups_from_list(Fun, ValueFun, List) ->
    badarg_with_info([Fun, ValueFun, List]).

%% @private
groups_from_list_2(Fun, ValueFun, [H | Tail], Acc) ->
    K = Fun(H),
    V = ValueFun(H),
    NewAcc =
        case Acc of
            #{K := Vs} -> Acc#{K := ordsets:add_element(V, Vs)};
            #{} -> Acc#{K => [V]}
        end,
    % NewAcc = case Acc of
    % 			 #{K := Vs} -> Acc#{K := [V | Vs]};
    % 			 #{} -> Acc#{K => [V]}
    % 		 end,
    groups_from_list_2(Fun, ValueFun, Tail, NewAcc);
groups_from_list_2(_Fun, _ValueFun, [], Acc) ->
    Acc.

%% @private
badarg_with_info(Args) ->
    erlang:error(badarg, Args, [{error_info, #{module => erl_stdlib_errors}}]).
