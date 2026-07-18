defmodule JOSEServerTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  defmodule BlockingCurve448 do
    def eddsa_keypair do
      maybe_block()
      delegate(:eddsa_keypair, [])
    end

    def ed448_sign(message, secret_key), do: delegate(:ed448_sign, [message, secret_key])

    def ed448_verify(signature, message, public_key),
      do: delegate(:ed448_verify, [signature, message, public_key])

    def ed448ph_sign(message, secret_key), do: delegate(:ed448ph_sign, [message, secret_key])

    def ed448ph_verify(signature, message, public_key),
      do: delegate(:ed448ph_verify, [signature, message, public_key])

    def x448_keypair, do: delegate(:x448_keypair, [])

    defp maybe_block do
      case Application.get_env(:jose, :crypto_supports_test_block) do
        {owner, reference} ->
          Application.delete_env(:jose, :crypto_supports_test_block)
          send(owner, {:crypto_supports_probe_blocked, self(), reference})

          receive do
            {^reference, :continue} -> :ok
          after
            5_000 -> raise "timed out waiting to release capability probe"
          end

        nil ->
          :ok
      end
    end

    defp delegate(function, arguments) do
      module = Application.fetch_env!(:jose, :crypto_supports_test_curve448_delegate)
      apply(module, function, arguments)
    end
  end

  test "serializes complete capability reads with configuration changes" do
    baseline = :jose_jwa.crypto_supports()
    parent = self()

    toggler =
      Task.async(fn ->
        send(parent, :ready)

        receive do
          :go -> Enum.each(1..100, fn _ -> assert :ok = :jose_server.config_change() end)
        end
      end)

    readers =
      for _ <- 1..4 do
        Task.async(fn ->
          send(parent, :ready)

          receive do
            :go -> Enum.each(1..250, fn _ -> assert :jose_jwa.crypto_supports() == baseline end)
          end
        end)
      end

    tasks = [toggler | readers]
    Enum.each(tasks, fn _task -> assert_receive :ready, 5_000 end)
    Enum.each(tasks, &send(&1.pid, :go))
    Enum.each(tasks, &Task.await(&1, 60_000))
  end

  test "slow capability probes do not block configuration changes" do
    original_module = :jose.curve448_module()
    reference = make_ref()

    Application.put_env(:jose, :crypto_supports_test_curve448_delegate, original_module)
    Application.put_env(:jose, :crypto_supports_test_block, {self(), reference})
    assert :ok = :jose.curve448_module(BlockingCurve448)

    on_exit(fn ->
      Application.delete_env(:jose, :crypto_supports_test_block)
      Application.delete_env(:jose, :crypto_supports_test_curve448_delegate)
      :ok = :jose.curve448_module(original_module)
    end)

    probe = Task.async(fn -> :jose_jwa.crypto_supports() end)

    assert_receive {:crypto_supports_probe_blocked, probe_process, ^reference}, 5_000

    setter = Task.async(fn -> :jose.curve448_module(original_module) end)
    assert :ok = Task.await(setter, 1_000)

    send(probe_process, {reference, :continue})
    assert Task.await(probe, 10_000) == :jose_jwa.crypto_supports()
  end

  test "rejects a stale capability probe after the server restarts" do
    original_module = :jose.curve448_module()
    reference = make_ref()

    Application.put_env(:jose, :crypto_supports_test_curve448_delegate, original_module)
    Application.put_env(:jose, :crypto_supports_test_block, {self(), reference})
    assert :ok = :jose.curve448_module(BlockingCurve448)

    on_exit(fn ->
      Application.delete_env(:jose, :crypto_supports_test_block)
      Application.delete_env(:jose, :crypto_supports_test_curve448_delegate)
      :ok = :jose.curve448_module(original_module)
    end)

    probe = Task.async(fn -> :jose_jwa.crypto_supports() end)

    assert_receive {:crypto_supports_probe_blocked, probe_process, ^reference}, 5_000

    old_server = Process.whereis(:jose_server)

    capture_log(fn ->
      Process.exit(old_server, :kill)
      assert wait_for_new_server(old_server)
    end)

    send(probe_process, {reference, :continue})
    assert Task.await(probe, 10_000) == :jose_jwa.crypto_supports()
  end

  test "lazily migrates a pre-generation capability cache" do
    baseline = :jose_jwa.crypto_supports()

    on_exit(fn -> :ok = :jose_server.config_change() end)

    :ets.delete(:jose_jwa, :crypto_supports_generation)
    :ets.delete(:jose_jwa, :crypto_fallback_applied)

    :ets.insert(
      :jose_jwa,
      {:crypto_supports_external, {:old_probe, false}, [:stale_hash], [:stale_key]}
    )

    assert :jose_jwa.crypto_supports() == baseline

    assert [{:crypto_supports_generation, generation}] =
             :ets.lookup(:jose_jwa, :crypto_supports_generation)

    assert is_reference(generation)
    refute :stale_hash in Keyword.fetch!(baseline, :hashs)
    refute :stale_key in Keyword.fetch!(baseline, :public_keys)
  end

  test "reconciles unapplied crypto fallback environment changes" do
    original_fallback = :jose.crypto_fallback()
    changed_fallback = not original_fallback
    :jose_jwa.crypto_supports()

    [{:crypto_supports_generation, original_generation}] =
      :ets.lookup(:jose_jwa, :crypto_supports_generation)

    on_exit(fn -> :ok = :jose.crypto_fallback(original_fallback) end)

    Application.put_env(:jose, :crypto_fallback, changed_fallback)
    assert is_list(:jose_jwa.crypto_supports())

    assert [{:crypto_fallback_applied, ^changed_fallback}] =
             :ets.lookup(:jose_jwa, :crypto_fallback_applied)

    assert [{:crypto_supports_generation, changed_generation}] =
             :ets.lookup(:jose_jwa, :crypto_supports_generation)

    refute changed_generation == original_generation

    Application.put_env(:jose, :crypto_fallback, original_fallback)
    :ets.delete(:jose_jwa, :crypto_supports_external)

    assert is_list(:jose_jwa.crypto_supports())

    assert [{:crypto_fallback_applied, ^original_fallback}] =
             :ets.lookup(:jose_jwa, :crypto_fallback_applied)
  end

  test "invalidates capability results when adapter code changes" do
    original_module = :jose.sha3_module()
    compiler_options = Code.compiler_options()

    Code.compiler_options(ignore_module_conflict: true)

    on_exit(fn ->
      Code.compiler_options(compiler_options)
      :ok = :jose.sha3_module(original_module)
      :code.purge(JOSEServerMutableSHA3)
      :code.delete(JOSEServerMutableSHA3)
    end)

    Code.compile_string("""
    defmodule JOSEServerMutableSHA3 do
      def shake256(_input, _output_byte_len), do: <<>>
    end
    """)

    assert :ok = :jose.sha3_module(JOSEServerMutableSHA3)
    :jose_jwa.crypto_supports()

    assert [{:crypto_supports_external, first_key, first_hashs, _public_keys}] =
             :ets.lookup(:jose_jwa, :crypto_supports_external)

    assert :shake256 in first_hashs

    Code.compile_string("""
    defmodule JOSEServerMutableSHA3 do
      def shake256(_input, _output_byte_len), do: raise("backend unavailable")
    end
    """)

    :jose_jwa.crypto_supports()

    assert [{:crypto_supports_external, second_key, second_hashs, _public_keys}] =
             :ets.lookup(:jose_jwa, :crypto_supports_external)

    refute first_key == second_key
    refute :shake256 in second_hashs
  end

  test "invalidates capability results when transitive fallback code changes" do
    {:jose_jwa_math, original_binary, original_path} = :code.get_object_code(:jose_jwa_math)
    compiler_options = Code.compiler_options()

    Code.compiler_options(ignore_module_conflict: true)

    on_exit(fn ->
      Code.compiler_options(compiler_options)

      {:module, :jose_jwa_math} =
        :code.load_binary(:jose_jwa_math, original_path, original_binary)

      :jose_jwa.crypto_supports()
    end)

    :jose_jwa.crypto_supports()

    assert [{:crypto_supports_external, first_key, _hashs, _public_keys}] =
             :ets.lookup(:jose_jwa, :crypto_supports_external)

    Code.compile_string("""
    defmodule :jose_jwa_math do
      def replacement_probe, do: :replacement
    end
    """)

    :jose_jwa.crypto_supports()

    assert [{:crypto_supports_external, second_key, _hashs, _public_keys}] =
             :ets.lookup(:jose_jwa, :crypto_supports_external)

    refute first_key == second_key
  end

  @native_ed448_support (fn ->
                           if :ed448 in Keyword.get(:crypto.supports(), :curves, []) do
                             try do
                               {public_key, private_key} = :crypto.generate_key(:eddsa, :ed448)
                               message = "native-ed448-capability-check"
                               signature = :crypto.sign(:eddsa, :none, message, [private_key, :ed448])

                               if :crypto.verify(
                                    :eddsa,
                                    :none,
                                    message,
                                    signature,
                                    [public_key, :ed448]
                                  ) do
                                 :supported
                               else
                                 {:error, "native Ed448 verification returned false"}
                               end
                             catch
                               kind, reason -> {:error, Exception.format_banner(kind, reason)}
                             end
                           else
                             {:skip, "OTP crypto does not advertise native Ed448 support"}
                           end
                         end).()

  case @native_ed448_support do
    :supported ->
      test "selects native Ed448 without crypto fallback or optional dependencies" do
        ebin = Application.app_dir(:jose, "ebin")

        expression = """
        ok = application:load({application, jose, [
          {description, "JOSE isolated native Ed448 test"},
          {vsn, "test"},
          {mod, {jose_app, []}},
          {registered, []},
          {applications, [kernel, stdlib, crypto, asn1, public_key]},
          {modules, []}
        ]}),
        ok = application:set_env(jose, crypto_fallback, false),
        WaitFor = fun
          Wait([]) -> ok;
          Wait([{Pid, Ref} | Rest]) ->
            receive
              {'DOWN', Ref, process, Pid, normal} -> Wait(Rest);
              {'DOWN', Ref, process, Pid, Reason} -> erlang:error({worker_failed, Reason})
            end
        end,
        Starter = spawn_monitor(fun() -> {ok, _} = application:ensure_all_started(jose) end),
        Parent = self(),
        StartupWorkers = [spawn_monitor(fun() ->
          Supports = jose_jwa:crypto_supports(),
          Parent ! {startup_supports, Supports}
        end)
          || _ <- lists:seq(1, 8)],
        ok = WaitFor([Starter | StartupWorkers]),
        CheckStartupSupports = fun
          Check(0) -> ok;
          Check(Remaining) ->
            receive
              {startup_supports, Supports} ->
                StartupPublicKeys = proplists:get_value(public_keys, Supports),
                true = lists:member(ed25519, StartupPublicKeys),
                true = lists:member(ed448, StartupPublicKeys),
                Check(Remaining - 1)
            end
        end,
        ok = CheckStartupSupports(8),
        jose_curve25519_crypto = jose:curve25519_module(),
        jose_curve448_crypto = jose:curve448_module(),
        jose_sha3_unsupported = jose:sha3_module(),
        {PublicKey25519, SecretKey25519} = jose_curve25519:eddsa_keypair(),
        Message25519 = <<\"native-ed25519\">>,
        Signature25519 = jose_curve25519:ed25519_sign(Message25519, SecretKey25519),
        true = jose_curve25519:ed25519_verify(Signature25519, Message25519, PublicKey25519),
        {PublicKey, SecretKey} = jose_curve448:eddsa_keypair(),
        Message = <<\"native-ed448\">>,
        Signature = jose_curve448:ed448_sign(Message, SecretKey),
        true = jose_curve448:ed448_verify(Signature, Message, PublicKey),
        PublicKeys = proplists:get_value(public_keys, jose_jwa:crypto_supports()),
        true = lists:member(ed25519, PublicKeys),
        true = lists:member(ed448, PublicKeys),
        false = lists:member(ed448ph, PublicKeys),
        false = lists:member(ed25519ph, PublicKeys),
        ok = jose:crypto_fallback(true),
        FallbackPublicKeys = proplists:get_value(public_keys, jose_jwa:crypto_supports()),
        true = lists:member(ed448ph, FallbackPublicKeys),
        true = lists:member(ed25519ph, FallbackPublicKeys),
        ok = jose:curve448_module(jose_curve448_unsupported),
        UnsupportedPublicKeys = proplists:get_value(public_keys, jose_jwa:crypto_supports()),
        false = lists:member(ed448, UnsupportedPublicKeys),
        false = lists:member(ed448ph, UnsupportedPublicKeys),
        ok = jose:curve448_module(crypto),
        RestoredPublicKeys = proplists:get_value(public_keys, jose_jwa:crypto_supports()),
        true = lists:member(ed448, RestoredPublicKeys),
        true = lists:member(ed448ph, RestoredPublicKeys),
        halt(0).
        """

        {output, status} =
          System.cmd(
            System.find_executable("erl"),
            [
              "-noshell",
              "-noinput",
              "-pa",
              ebin,
              "-eval",
              expression
            ],
            env: [
              {"ERL_LIBS", nil},
              {"ERL_FLAGS", nil},
              {"ERL_AFLAGS", nil},
              {"ERL_ZFLAGS", nil}
            ],
            stderr_to_stdout: true
          )

        assert status == 0, output
      end

    {:skip, reason} ->
      @tag skip: reason
      test "selects native Ed448 without crypto fallback or optional dependencies", do: :ok

    {:error, reason} ->
      @native_ed448_error reason

      test "selects native Ed448 without crypto fallback or optional dependencies" do
        flunk("OTP advertised native Ed448, but its operation probe failed: #{@native_ed448_error}")
      end
  end

  defp wait_for_new_server(old_server, attempts \\ 100)

  defp wait_for_new_server(_old_server, 0), do: false

  defp wait_for_new_server(old_server, attempts) do
    case Process.whereis(:jose_server) do
      nil ->
        Process.sleep(10)
        wait_for_new_server(old_server, attempts - 1)

      ^old_server ->
        Process.sleep(10)
        wait_for_new_server(old_server, attempts - 1)

      new_server ->
        Process.alive?(new_server)
    end
  end
end
