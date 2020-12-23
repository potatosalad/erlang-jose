defmodule JOSE.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :jose,
      version: "1.11.1",
      elixir: "~> 1.4",
      erlc_options: erlc_options(),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "JOSE",
      source_url: "https://github.com/potatosalad/erlang-jose",
      docs: fn ->
        {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])
        [source_ref: ref, main: "JOSE", extras: ["README.md", "CHANGELOG.md", "examples/KEY-GENERATION.md", "ALGORITHMS.md"]]
      end,
      description: description(),
      package: package()
    ]
  end

  def application() do
    [mod: {:jose_app, []}, extra_applications: [:crypto, :asn1, :public_key]]
  end

  defp deps() do
    [
      # {:cutkey, github: "potatosalad/cutkey", only: [:dev, :test]},
      {:jason, "~> 1.1", only: [:dev, :test]},
      {:jsone, "~> 1.4", only: [:dev, :test]},
      {:jsx, "~> 2.9", only: [:dev, :test]},
      # {:keccakf1600, "~> 2.0.0", only: [:dev, :test]},
      {:libdecaf, "~> 1.0.0", only: [:dev, :test]},
      {:libsodium, "~> 0.0.10", only: [:dev, :test]},
      {:ojson, "~> 1.0", only: [:dev, :test]},
      {:poison, "~> 4.0", only: [:dev, :test]},
      {:ex_doc, "~> 0.19", only: :dev},
      {:earmark, "~> 1.3", only: :dev}
    ]
  end

  defp description() do
    "JSON Object Signing and Encryption (JOSE) for Erlang and Elixir."
  end

  def erlc_options() do
    extra_options = []

    [:debug_info | if(Mix.env() == :prod, do: [], else: [:warnings_as_errors]) ++ extra_options]
  end

  defp package() do
    [
      maintainers: ["Andrew Bennett"],
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
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/potatosalad/erlang-jose", "Docs" => "https://hexdocs.pm/jose"}
    ]
  end
end
