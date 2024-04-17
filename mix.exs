defmodule JOSE.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :jose,
      version: "1.11.10",
      elixir: "~> 1.13",
      erlc_options: erlc_options(),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "JOSE",
      source_url: "https://github.com/potatosalad/erlang-jose",
      docs: fn ->
        {ref, 0} = System.cmd("git", ["rev-parse", "--verify", "--quiet", "HEAD"])

        [
          source_ref: ref,
          main: "readme",
          extras: ["README.md", "CHANGELOG.md", "examples/KEY-GENERATION.md", "ALGORITHMS.md"],
          groups_for_modules: ["Elixir": [~r/JOSE/], Erlang: [~r/jose/]]
        ]
      end,
      description: description(),
      package: package(),
      aliases: [docs: ["compile", &edoc_chunks/1, "docs"]],
      dialyzer: [list_unused_filters: true]
    ]
  end

  def application() do
    [mod: {:jose_app, []}, extra_applications: extra_applications(Mix.env())]
  end

  defp extra_applications(env)
  defp extra_applications(:dev), do: [:crypto, :asn1, :public_key, :edoc, :xmerl]
  defp extra_applications(_env), do: [:crypto, :asn1, :public_key]

  defp deps() do
    [
      # {:cutkey, github: "potatosalad/cutkey", only: [:dev, :test]},
      {:jason, "~> 1.4", only: [:dev, :test]},
      {:jsone, "~> 1.8", only: [:dev, :test]},
      {:jsx, "~> 3.1", only: [:dev, :test]},
      # {:keccakf1600, "~> 2.0.0", only: [:dev, :test]},
      {:libdecaf, "~> 2.1.1", only: [:dev, :test]},
      {:libsodium, "~> 2.0.1", only: [:dev, :test]},
      {:ojson, "~> 1.0", only: [:dev, :test]},
      # Optionally used by JOSE.Poison.
      {:poison, "~> 3.0 or ~> 4.0 or ~> 5.0", only: [:dev, :test], optional: true},
      {:thoas, "~> 1.0", only: [:dev, :test]},
      {:ex_doc, "~> 0.30", only: :dev},
      {:earmark, "~> 1.4", only: :dev},
      {:dialyxir, "~> 1.4.3", only: [:dev, :test], runtime: false}
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

  defp edoc_chunks(_args) do
    base_path = Path.dirname(__ENV__.file)
    doc_chunk_path = Application.app_dir(:jose, "doc")

    :ok =
      :edoc.application(:jose, String.to_charlist(base_path),
        doclet: :edoc_doclet_chunks,
        layout: :edoc_layout_chunks,
        preprocess: true,
        dir: String.to_charlist(doc_chunk_path)
      )
  end
end
