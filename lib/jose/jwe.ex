require Record

defmodule JOSE.JWE do
  record = Record.extract(:jose_jwe, from_lib: "jose/include/jose_jwe.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `JOSE.JWE` struct to a `:jose_jwe` record.
  """
  def to_record(%JOSE.JWE{unquote_splicing(pairs)}) do
    {:jose_jwe, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:jose_jwe` record into a `JOSE.JWE`.
  """
  def from_record(jose_jwe)
  def from_record({:jose_jwe, unquote_splicing(vals)}) do
    %JOSE.JWE{unquote_splicing(pairs)}
  end

  # Decode API
  def from(jwe=%JOSE.JWE{}), do: from(to_record(jwe))
  def from(any), do: :jose_jwe.from(any) |> from_record
  def from_binary(binary), do: :jose_jwe.from_binary(binary) |> from_record
  def from_file(file), do: :jose_jwe.from_file(file) |> from_record
  def from_map(map), do: :jose_jwe.from_map(map) |> from_record

  # Encode API
  def to_binary(jwe=%JOSE.JWE{}), do: to_binary(to_record(jwe))
  def to_binary(any), do: :jose_jwe.to_binary(any)
  def to_file(file, jwe=%JOSE.JWE{}), do: to_file(file, to_record(jwe))
  def to_file(file, any), do: :jose_jwe.to_file(file, any)
  def to_map(jwe=%JOSE.JWE{}), do: to_map(to_record(jwe))
  def to_map(any), do: :jose_jwe.to_map(any)

  # API
  def block_decrypt(jwk=%JOSE.JWK{}, encrypted), do: block_decrypt(to_record(jwk), encrypted)
  def block_decrypt(jwk, encrypted) do
    case :jose_jwe.block_decrypt(jwk, encrypted) do
      {jwe, plain_text} when is_tuple(jwe) ->
        {from_record(jwe), plain_text}
      error ->
        error
    end
  end

  def block_encrypt(jwk=%JOSE.JWK{}, plain_text, jwe), do: block_encrypt(JOSE.JWK.to_record(jwk), plain_text, jwe)
  def block_encrypt(jwk, plain_text, jwe=%JOSE.JWE{}), do: block_encrypt(jwk, plain_text, to_record(jwe))
  def block_encrypt(jwk, plain_text, jwe), do: :jose_jwe.block_encrypt(jwk, plain_text, jwe)

  def block_encrypt(jwk=%JOSE.JWK{}, plain_text, cek, jwe), do: block_encrypt(JOSE.JWK.to_record(jwk), plain_text, cek, jwe)
  def block_encrypt(jwk, plain_text, cek, jwe=%JOSE.JWE{}), do: block_encrypt(jwk, plain_text, cek, to_record(jwe))
  def block_encrypt(jwk, plain_text, cek, jwe), do: :jose_jwe.block_encrypt(jwk, plain_text, cek, jwe)

  def block_encrypt(jwk=%JOSE.JWK{}, plain_text, cek, iv, jwe), do: block_encrypt(JOSE.JWK.to_record(jwk), plain_text, cek, iv, jwe)
  def block_encrypt(jwk, plain_text, cek, iv, jwe=%JOSE.JWE{}), do: block_encrypt(jwk, plain_text, cek, iv, to_record(jwe))
  def block_encrypt(jwk, plain_text, cek, iv, jwe), do: :jose_jwe.block_encrypt(jwk, plain_text, cek, iv, jwe)

  def compact(encrypted), do: :jose_jwe.compact(encrypted)

  def compress(plain_text, jwe=%JOSE.JWE{}), do: compress(plain_text, to_record(jwe))
  def compress(plain_text, jwe), do: :jose_jwe.compress(plain_text, jwe)

  def expand(encrypted), do: :jose_jwe.expand(encrypted)

  def key_decrypt(jwk=%JOSE.JWK{}, encrypted_key, jwe), do: key_decrypt(JOSE.JWK.to_record(jwk), encrypted_key, jwe)
  def key_decrypt(jwk, encrypted_key, jwe=%JOSE.JWE{}), do: key_decrypt(jwk, encrypted_key, to_record(jwe))
  def key_decrypt(jwk, encrypted_key, jwe), do: :jose_jwe.key_decrypt(jwk, encrypted_key, jwe)

  def key_encrypt(jwk=%JOSE.JWK{}, decrypted_key, jwe), do: key_encrypt(JOSE.JWK.to_record(jwk), decrypted_key, jwe)
  def key_encrypt(jwk, decrypted_key, jwe=%JOSE.JWE{}), do: key_encrypt(jwk, decrypted_key, to_record(jwe))
  def key_encrypt(jwk, decrypted_key, jwe), do: :jose_jwe.key_encrypt(jwk, decrypted_key, jwe)

  def next_cek(jwk=%JOSE.JWK{}, jwe), do: next_cek(JOSE.JWK.to_record(jwk), jwe)
  def next_cek(jwk, jwe=%JOSE.JWE{}), do: next_cek(jwk, to_record(jwe))
  def next_cek(jwk, jwe), do: :jose_jwe.next_cek(jwk, jwe)

  def next_iv(jwe=%JOSE.JWE{}), do: next_iv(to_record(jwe))
  def next_iv(jwe), do: :jose_jwe.next_iv(jwe)

  def uncompress(cipher_text, jwe=%JOSE.JWE{}), do: uncompress(cipher_text, to_record(jwe))
  def uncompress(cipher_text, jwe), do: :jose_jwe.uncompress(cipher_text, jwe)

end
