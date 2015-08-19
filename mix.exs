defmodule JOSE.Mixfile do
  use Mix.Project

  def project do
    [app: :jose,
     version: "1.2.0",
     elixir: "~> 1.0",
     erlc_options: erlc_options,
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps,
     name: "JOSE",
     source_url: "https://github.com/potatosalad/erlang-jose",
     docs: fn ->
       {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])
       [source_ref: ref, main: "README", readme: "README.md"]
     end,
     description: description,
     package: package]
  end

  def application do
    [mod: {:jose_app, []},
     applications: [:crypto, :asn1, :public_key, :base64url]]
  end

  defp deps do
    [{:base64url, "~> 0.0.1"},
     {:cutkey, github: "potatosalad/cutkey", only: [:dev, :test]},
     {:jsx, "~> 2.0", only: [:dev, :test]},
     {:poison, "~> 1.4", only: [:dev, :test]}]
  end

  defp description do
    "JSON Object Signing and Encryption (JOSE) for Erlang and Elixir."
  end

  def erlc_options do
    extra_options = try do
      case :erlang.list_to_integer(:erlang.system_info(:otp_release)) do
        v when v >= 18 ->
          [{:d, :optional_callbacks}]
        _ ->
          []
      end
    catch
      _ ->
        []
    end
    [:debug_info, :warnings_as_errors | extra_options]
  end

  defp package do
    [contributors: ["Andrew Bennett"],
     files: [
       "CHANGELOG*",
       "include",
       "lib",
       "LICENSE*",
       "priv",
       "mix.exs",
       "README*",
       "rebar.config",
       "src"
     ],
     licenses: ["Mozilla Public License Version 2.0"],
     links: %{"Github" => "https://github.com/potatosalad/erlang-jose"}]
  end
end
