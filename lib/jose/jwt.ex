require Record

defmodule JOSE.JWT do
  record = Record.extract(:jose_jwt, from_lib: "jose/include/jose_jwt.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `JOSE.JWT` struct to a `:jose_jwt` record.
  """
  def to_record(%JOSE.JWT{unquote_splicing(pairs)}) do
    {:jose_jwt, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:jose_jwt` record into a `JOSE.JWT`.
  """
  def from_record(jose_jwt)
  def from_record({:jose_jwt, unquote_splicing(vals)}) do
    %JOSE.JWT{unquote_splicing(pairs)}
  end

  # Decode API
  def from(jwt=%JOSE.JWT{}), do: from(to_record(jwt))
  def from(any), do: :jose_jwt.from(any) |> from_record
  def from_binary(binary), do: :jose_jwt.from_binary(binary) |> from_record
  def from_file(file), do: :jose_jwt.from_file(file) |> from_record
  def from_map(map), do: :jose_jwt.from_map(map) |> from_record

  # Encode API
  def to_binary(jwt=%JOSE.JWT{}), do: to_binary(to_record(jwt))
  def to_binary(any), do: :jose_jwt.to_binary(any)
  def to_file(file, jwt=%JOSE.JWT{}), do: to_file(file, to_record(jwt))
  def to_file(file, any), do: :jose_jwt.to_file(file, any)
  def to_map(jwt=%JOSE.JWT{}), do: to_map(to_record(jwt))
  def to_map(any), do: :jose_jwt.to_map(any)

  # API
  def decrypt(jwk=%JOSE.JWK{}, encrypted), do: decrypt(JOSE.JWK.to_record(jwk), encrypted)
  def decrypt(key, encrypted) do
    case :jose_jwt.decrypt(key, encrypted) do
      {jwe, jwt} when is_tuple(jwe) and is_tuple(jwt) ->
        {JOSE.JWE.from_record(jwe), from_record(jwt)}
      error ->
        error
    end
  end

  def encrypt(jwk=%JOSE.JWK{}, jwt), do: encrypt(JOSE.JWK.to_record(jwk), jwt)
  def encrypt(jwk, jwt=%JOSE.JWT{}), do: encrypt(jwk, to_record(jwt))
  def encrypt(jwk, jwt), do: :jose_jwt.encrypt(jwk, jwt)

  def encrypt(jwk=%JOSE.JWK{}, jwe, jwt), do: encrypt(JOSE.JWK.to_record(jwk), jwe, jwt)
  def encrypt(jwk, jwe=%JOSE.JWE{}, jwt), do: encrypt(jwk, JOSE.JWE.to_record(jwe), jwt)
  def encrypt(jwk, jwe, jwt=%JOSE.JWT{}), do: encrypt(jwk, jwe, to_record(jwt))
  def encrypt(jwk, jwe, jwt), do: :jose_jwt.encrypt(jwk, jwe, jwt)

  def peek(signed), do: from_record(:jose_jwt.peek(signed))
  def peek_payload(signed), do: from_record(:jose_jwt.peek_payload(signed))
  def peek_protected(signed), do: JOSE.JWS.from_record(:jose_jwt.peek_protected(signed))

  def sign(jwk=%JOSE.JWK{}, jwt), do: sign(JOSE.JWK.to_record(jwk), jwt)
  def sign(jwk, jwt=%JOSE.JWT{}), do: sign(jwk, to_record(jwt))
  def sign(jwk, jwt), do: :jose_jwt.sign(jwk, jwt)

  def sign(jwk=%JOSE.JWK{}, jws, jwt), do: sign(JOSE.JWK.to_record(jwk), jws, jwt)
  def sign(jwk, jws=%JOSE.JWS{}, jwt), do: sign(jwk, JOSE.JWS.to_record(jws), jwt)
  def sign(jwk, jws, jwt=%JOSE.JWT{}), do: sign(jwk, jws, to_record(jwt))
  def sign(jwk, jws, jwt), do: :jose_jwt.sign(jwk, jws, jwt)

  def verify(jwk=%JOSE.JWK{}, signed), do: verify(JOSE.JWK.to_record(jwk), signed)
  def verify(key, signed) do
    case :jose_jwt.verify(key, signed) do
      {verified, jwt, jws} when is_tuple(jwt) and is_tuple(jws) ->
        {verified, from_record(jwt), JOSE.JWS.from_record(jws)}
      error ->
        error
    end
  end

  def verify_strict(jwk=%JOSE.JWK{}, allow, signed), do: verify_strict(JOSE.JWK.to_record(jwk), allow, signed)
  def verify_strict(key, allow, signed) do
    case :jose_jwt.verify_strict(key, allow, signed) do
      {verified, jwt, jws} when is_tuple(jwt) and is_tuple(jws) ->
        {verified, from_record(jwt), JOSE.JWS.from_record(jws)}
      error ->
        error
    end
  end

end
