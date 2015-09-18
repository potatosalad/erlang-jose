defmodule JOSE.Mixfile do
  use Mix.Project

  def project do
    [app: :jose,
     version: "1.2.0",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps,
     name: "JOSE",
     source_url: "https://github.com/potatosalad/erlang-jose",
     docs: fn ->
       {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])
       [source_ref: ref, readme: "README.md"]
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
     {:jsx, "~> 2.0", only: [:dev, :test]},
     {:poison, "~> 1.4", only: [:dev, :test]},
     {:ex_doc, "~> 0.9", only: :docs},
     {:earmark, "~> 0.1", only: :docs}]
  end

  defp description do
    "JSON Object Signing and Encryption (JOSE) for Erlang and Elixir."
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
     links: %{"Github" => "https://github.com/potatosalad/erlang-jose",
             "Docs" => "https://hexdocs.pm/erlang-jose"}]
  end
end
