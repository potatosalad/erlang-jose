require Record

defmodule JOSE.JWS do

  record = Record.extract(:jose_jws, from_lib: "jose/include/jose_jws.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `JOSE.JWS` struct to a `:jose_jws` record.
  """
  def to_record(%JOSE.JWS{unquote_splicing(pairs)}) do
    {:jose_jws, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:jose_jws` record into a `JOSE.JWS`.
  """
  def from_record(jose_jws)
  def from_record({:jose_jws, unquote_splicing(vals)}) do
    %JOSE.JWS{unquote_splicing(pairs)}
  end

  # Decode API
  def from(jws=%JOSE.JWS{}), do: from(to_record(jws))
  def from(any), do: :jose_jws.from(any) |> from_record
  def from_binary(binary), do: :jose_jws.from_binary(binary) |> from_record
  def from_file(file), do: :jose_jws.from_file(file) |> from_record
  def from_map(map), do: :jose_jws.from_map(map) |> from_record

  # Encode API
  def to_binary(jws=%JOSE.JWS{}), do: to_binary(to_record(jws))
  def to_binary(any), do: :jose_jws.to_binary(any)
  def to_file(file, jws=%JOSE.JWS{}), do: to_file(file, to_record(jws))
  def to_file(file, any), do: :jose_jws.to_file(file, any)
  def to_map(jws=%JOSE.JWS{}), do: to_map(to_record(jws))
  def to_map(any), do: :jose_jws.to_map(any)

  # API
  def compact(signed), do: :jose_jws.compact(signed)

  def expand(signed), do: :jose_jws.expand(signed)

  defdelegate peek(signed), to: :jose_jws
  defdelegate peek_payload(signed), to: :jose_jws
  defdelegate peek_protected(signed), to: :jose_jws

  def sign(jwk=%JOSE.JWK{}, plain_text, jws), do: sign(JOSE.JWK.to_record(jwk), plain_text, jws)
  def sign(jwk, plain_text, jws=%JOSE.JWS{}), do: sign(jwk, plain_text, to_record(jws))
  def sign(jwk, plain_text, jws), do: :jose_jws.sign(jwk, plain_text, jws)

  def sign(jwk=%JOSE.JWK{}, plain_text, header, jws), do: sign(JOSE.JWK.to_record(jwk), plain_text, header, jws)
  def sign(jwk, plain_text, header, jws=%JOSE.JWS{}), do: sign(jwk, plain_text, header, to_record(jws))
  def sign(jwk, plain_text, header, jws), do: :jose_jws.sign(jwk, plain_text, header, jws)

  def signing_input(payload, jws=%JOSE.JWS{}), do: signing_input(payload, to_record(jws))
  def signing_input(payload, jws), do: :jose_jws.signing_input(payload, jws)

  def signing_input(payload, protected, jws=%JOSE.JWS{}), do: signing_input(payload, protected, to_record(jws))
  def signing_input(payload, protected, jws), do: :jose_jws.signing_input(payload, protected, jws)

  def verify(jwk=%JOSE.JWK{}, signed), do: verify(JOSE.JWK.to_record(jwk), signed)
  def verify(key, signed) do
    case :jose_jws.verify(key, signed) do
      {verified, payload, jws} when is_tuple(jws) ->
        {verified, payload, from_record(jws)}
      error ->
        error
    end
  end

  def verify_strict(jwk=%JOSE.JWK{}, allow, signed), do: verify_strict(JOSE.JWK.to_record(jwk), allow, signed)
  def verify_strict(key, allow, signed) do
    case :jose_jws.verify_strict(key, allow, signed) do
      {verified, payload, jws} when is_tuple(jws) ->
        {verified, payload, from_record(jws)}
      error ->
        error
    end
  end

end
