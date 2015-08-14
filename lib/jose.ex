defmodule JOSE do

  # API
  def decode(binary), do: :jose.decode(binary)
  def encode(term), do: :jose.encode(term)
  def json_module(), do: :jose.json_module()
  def json_module(module), do: :jose.json_module(module)

end
