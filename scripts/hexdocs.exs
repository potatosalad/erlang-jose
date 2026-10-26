# Pack and publish HexDocs without unpacking them on the host.
#
# ExDoc writes the Elixir JOSE module to JOSE.html and the Erlang jose module
# to jose.html. On a case-insensitive file system (the macOS default) one
# overwrites the other, so `make docker-docs` builds and packs the docs inside
# a container and `make hexdocs-publish` uploads that tarball unchanged, using
# the same Hex client call as `mix hex.publish docs`.
#
#     mix run --no-start scripts/hexdocs.exs pack OUT_DIR
#     mix run --no-start --no-compile --no-deps-check scripts/hexdocs.exs publish OUT_DIR

defmodule JOSE.HexDocs do
  def main(["pack", out_dir]) do
    # Same file selection as `mix hex.publish docs` (dotfiles are skipped).
    files =
      "doc/**"
      |> Path.wildcard()
      |> Enum.filter(&File.regular?/1)
      |> Enum.map(&{String.to_charlist(Path.relative_to(&1, "doc")), File.read!(&1)})

    {:ok, tarball} = :mix_hex_tarball.create_docs(files)
    check!(tarball)

    path = tarball_path(out_dir)
    File.write!(path, tarball)
    IO.puts("Wrote #{path} (#{byte_size(tarball)} bytes, #{length(files)} files)")
  end

  def main(["publish", out_dir]) do
    path = tarball_path(out_dir)

    unless File.regular?(path) do
      Mix.raise("#{path} not found; run `make docker-docs` first")
    end

    tarball = File.read!(path)
    check!(tarball)

    Hex.start()
    progress = Mix.Tasks.Hex.progress(byte_size(tarball))

    case Hex.API.ReleaseDocs.publish(nil, package_name(), version(), tarball, [], progress) do
      {:ok, {code, _headers, _body}} when code in 200..299 ->
        IO.puts("\nDocs will soon be available at #{Hex.Utils.hexdocs_url(nil, package_name(), version())}")

      {:ok, {404, _headers, _body}} ->
        Mix.raise("Publishing docs failed: #{package_name()} #{version()} is not published yet")

      other ->
        Hex.Utils.print_error_result(other)
        Mix.raise("Publishing docs failed")
    end
  end

  def main(_args) do
    Mix.raise("usage: mix run scripts/hexdocs.exs pack|publish OUT_DIR")
  end

  # Refuse a tarball in which JOSE.html and jose.html have collapsed into one.
  defp check!(tarball) do
    {:ok, entries} = :erl_tar.extract({:binary, tarball}, [:memory, :compressed])
    entries = Map.new(entries, fn {name, contents} -> {List.to_string(name), contents} end)

    for {file, title} <- [{"index.html", nil}, {"JOSE.html", "<title>JOSE "}, {"jose.html", "<title>jose "}] do
      contents = Map.get(entries, file) || Mix.raise("Docs tarball is missing #{file}")

      if title && not String.contains?(contents, title) do
        Mix.raise("Docs tarball has the wrong page in #{file}")
      end
    end

    :ok
  end

  defp tarball_path(out_dir), do: Path.join(out_dir, "#{package_name()}-#{version()}-docs.tar.gz")

  defp package_name() do
    config = Mix.Project.config()
    to_string(get_in(config, [:package, :name]) || config[:app])
  end

  defp version(), do: Mix.Project.config()[:version]
end

# `mix run` does not load archives, and Hex is installed as one.
Mix.Local.append_archives()
JOSE.HexDocs.main(System.argv())
