defmodule JOSE.Poison do
  alias JOSE.Poison.OrdEncoder

  @spec ord_encode!(Encoder.t, Keyword.t) :: iodata | no_return
  def ord_encode!(value, options \\ []) do
    iodata = OrdEncoder.encode(value, options)
    unless options[:iodata] do
      iodata |> IO.iodata_to_binary
    else
      iodata
    end
  end
end