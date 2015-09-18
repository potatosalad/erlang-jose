require Record

defmodule JOSE.JWK do

  @moduledoc """
  JWK stands for Json Web Key. This module parses the record definition in 
  `:jose_jwk` and eases the transition between Erlang/Elixir.

  It provides several utilities for creating/decoding key structs from files, 
  pem representation, binary and etc. It also provides mechanisms for signing 
  and verifying data.
  """

  record = Record.extract(:jose_jwk, from_lib: "jose/include/jose_jwk.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `JOSE.JWK` struct to a `:jose_jwk` record.
  """
  def to_record(%JOSE.JWK{unquote_splicing(pairs)}) do
    {:jose_jwk, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:jose_jwk` record into a `JOSE.JWK`.
  """
  def from_record(jose_jwk)
  def from_record({:jose_jwk, unquote_splicing(vals)}) do
    %JOSE.JWK{unquote_splicing(pairs)}
  end

  # Decode API
  def from(jwk=%JOSE.JWK{}), do: from(to_record(jwk))
  def from(any), do: :jose_jwk.from(any) |> from_record
  def from(password, jwk=%JOSE.JWK{}), do: from(password, to_record(jwk))
  def from(password, any), do: :jose_jwk.from(password, any) |> from_encrypted_record
  def from_binary(binary), do: :jose_jwk.from_binary(binary) |> from_record
  def from_binary(password, binary), do: :jose_jwk.from_binary(password, binary) |> from_encrypted_record
  def from_file(file), do: :jose_jwk.from_file(file) |> from_record
  def from_file(password, file), do: :jose_jwk.from_file(password, file) |> from_encrypted_record
  def from_key(key), do: :jose_jwk.from_key(key) |> from_record
  def from_map(map), do: :jose_jwk.from_map(map) |> from_record
  def from_map(password, map), do: :jose_jwk.from_map(password, map) |> from_encrypted_record
  def from_oct(oct), do: :jose_jwk.from_oct(oct) |> from_record
  def from_oct(password, pem), do: :jose_jwk.from_oct(password, pem) |> from_encrypted_record
  def from_oct_file(file), do: :jose_jwk.from_oct_file(file) |> from_record
  def from_oct_file(password, file), do: :jose_jwk.from_oct_file(password, file) |> from_encrypted_record

  @doc """
  Generates a key from a pem representation (Privacy Enhanced Email) in binary.
  """
  def from_pem(pem), do: :jose_jwk.from_pem(pem) |> from_record

  @doc """
  Same as `from_pem/1` but with a password used to unlock it. 
  """
  def from_pem(password, pem), do: :jose_jwk.from_pem(password, pem) |> from_record

  @doc """
  Generates a key from reading a pem representation from a file.
  """
  def from_pem_file(file), do: :jose_jwk.from_pem_file(file) |> from_record

  @doc """
  Same as `from_pem_file/1` but with a password to unlock it.
  """
  def from_pem_file(password, file), do: :jose_jwk.from_pem_file(password, file) |> from_record

  defp from_encrypted_record({jwe, jwk}) when is_tuple(jwe) and is_tuple(jwk) do
    {JOSE.JWE.from_record(jwe), from_record(jwk)}
  end
  defp from_encrypted_record(any), do: any

  # Encode API
  def to_binary(jwk=%JOSE.JWK{}), do: to_binary(to_record(jwk))
  def to_binary(jwk), do: :jose_jwk.to_binary(jwk)
  def to_binary(password, jwk=%JOSE.JWK{}), do: to_binary(password, to_record(jwk))
  def to_binary(password, jwk), do: :jose_jwk.to_binary(password, jwk)
  def to_binary(password, jwe=%JOSE.JWE{}, jwk), do: to_binary(password, JOSE.JWE.to_record(jwe), jwk)
  def to_binary(password, jwe, jwk=%JOSE.JWK{}), do: to_binary(password, jwe, to_record(jwk))
  def to_binary(password, jwe, jwk), do: :jose_jwk.to_binary(password, jwe, jwk)
  def to_file(file, jwk=%JOSE.JWK{}), do: to_file(file, to_record(jwk))
  def to_file(file, jwk), do: :jose_jwk.to_file(file, jwk)
  def to_file(password, file, jwk=%JOSE.JWK{}), do: to_file(password, file, to_record(jwk))
  def to_file(password, file, jwk), do: :jose_jwk.to_file(password, file, jwk)
  def to_file(password, file, jwe=%JOSE.JWE{}, jwk), do: to_file(password, file, JOSE.JWE.to_record(jwe), jwk)
  def to_file(password, file, jwe, jwk=%JOSE.JWK{}), do: to_file(password, file, jwe, to_record(jwk))
  def to_file(password, file, jwe, jwk), do: :jose_jwk.to_file(password, file, jwe, jwk)
  def to_key(jwk=%JOSE.JWK{}), do: to_key(to_record(jwk))
  def to_key(jwk), do: :jose_jwk.to_key(jwk)
  def to_map(jwk=%JOSE.JWK{}), do: to_map(to_record(jwk))
  def to_map(jwk), do: :jose_jwk.to_map(jwk)
  def to_map(password, jwk=%JOSE.JWK{}), do: to_map(password, to_record(jwk))
  def to_map(password, jwk), do: :jose_jwk.to_map(password, jwk)
  def to_map(password, jwe=%JOSE.JWE{}, jwk), do: to_map(password, JOSE.JWE.to_record(jwe), jwk)
  def to_map(password, jwe, jwk=%JOSE.JWK{}), do: to_map(password, jwe, to_record(jwk))
  def to_map(password, jwe, jwk), do: :jose_jwk.to_map(password, jwe, jwk)
  def to_oct(jwk=%JOSE.JWK{}), do: to_oct(to_record(jwk))
  def to_oct(jwk), do: :jose_jwk.to_oct(jwk)
  def to_oct(password, jwk=%JOSE.JWK{}), do: to_oct(password, to_record(jwk))
  def to_oct(password, jwk), do: :jose_jwk.to_oct(password, jwk)
  def to_oct(password, jwe=%JOSE.JWE{}, jwk), do: to_oct(password, JOSE.JWE.to_record(jwe), jwk)
  def to_oct(password, jwe, jwk=%JOSE.JWK{}), do: to_oct(password, jwe, to_record(jwk))
  def to_oct(password, jwe, jwk), do: :jose_jwk.to_oct(password, jwe, jwk)
  def to_oct_file(file, jwk=%JOSE.JWK{}), do: to_oct_file(file, to_record(jwk))
  def to_oct_file(file, jwk), do: :jose_jwk.to_oct_file(file, jwk)
  def to_oct_file(password, file, jwk=%JOSE.JWK{}), do: to_oct_file(password, file, to_record(jwk))
  def to_oct_file(password, file, jwk), do: :jose_jwk.to_oct_file(password, file, jwk)
  def to_oct_file(password, file, jwe=%JOSE.JWE{}, jwk), do: to_oct_file(password, file, JOSE.JWE.to_record(jwe), jwk)
  def to_oct_file(password, file, jwe, jwk=%JOSE.JWK{}), do: to_oct_file(password, file, jwe, to_record(jwk))
  def to_oct_file(password, file, jwe, jwk), do: :jose_jwk.to_oct_file(password, file, jwe, jwk)
  def to_pem(jwk=%JOSE.JWK{}), do: to_pem(to_record(jwk))
  def to_pem(jwk), do: :jose_jwk.to_pem(jwk)
  def to_pem(password, jwk=%JOSE.JWK{}), do: to_pem(password, to_record(jwk))
  def to_pem(password, jwk), do: :jose_jwk.to_pem(password, jwk)
  def to_pem_file(file, jwk=%JOSE.JWK{}), do: to_pem_file(file, to_record(jwk))
  def to_pem_file(file, jwk), do: :jose_jwk.to_pem_file(file, jwk)
  def to_pem_file(password, file, jwk=%JOSE.JWK{}), do: to_pem_file(password, file, to_record(jwk))
  def to_pem_file(password, file, jwk), do: :jose_jwk.to_pem_file(password, file, jwk)
  def to_public(jwk=%JOSE.JWK{}), do: to_public(to_record(jwk))
  def to_public(jwk), do: :jose_jwk.to_public(jwk) |> from_record
  def to_public_file(file, jwk=%JOSE.JWK{}), do: to_public_file(file, to_record(jwk))
  def to_public_file(file, jwk), do: :jose_jwk.to_public_file(file, jwk)
  def to_public_key(jwk=%JOSE.JWK{}), do: to_public_key(to_record(jwk))
  def to_public_key(jwk), do: :jose_jwk.to_public_key(jwk)
  def to_public_map(jwk=%JOSE.JWK{}), do: to_public_map(to_record(jwk))
  def to_public_map(jwk), do: :jose_jwk.to_public_map(jwk)
  def to_thumbprint_map(jwk=%JOSE.JWK{}), do: to_thumbprint_map(to_record(jwk))
  def to_thumbprint_map(jwk), do: :jose_jwk.to_thumbprint_map(jwk)

  # API
  def block_decrypt(encrypted, jwk=%JOSE.JWK{}), do: block_decrypt(encrypted, to_record(jwk))
  def block_decrypt(encrypted, jwk) do
    case :jose_jwk.block_decrypt(encrypted, jwk) do
      {jwe, plain_text} when is_tuple(jwe) ->
        {JOSE.JWE.from_record(jwe), plain_text}
      error ->
        error
    end
  end

  def block_encrypt(plain_text, jwk=%JOSE.JWK{}), do: block_encrypt(plain_text, to_record(jwk))
  def block_encrypt(plain_text, jwk), do: :jose_jwk.block_encrypt(plain_text, jwk)

  def block_encrypt(plain_text, jwe=%JOSE.JWE{}, jwk), do: block_encrypt(plain_text, JOSE.JWE.to_record(jwe), jwk)
  def block_encrypt(plain_text, jwe, jwk=%JOSE.JWK{}), do: block_encrypt(plain_text, jwe, to_record(jwk))
  def block_encrypt(plain_text, jwe, jwk), do: :jose_jwk.block_encrypt(plain_text, jwe, jwk)

  def box_decrypt(encrypted, jwk=%JOSE.JWK{}), do: box_decrypt(encrypted, to_record(jwk))
  def box_decrypt(encrypted, jwk) do
    case :jose_jwk.box_decrypt(encrypted, jwk) do
      {jwe, plain_text} when is_tuple(jwe) ->
        {JOSE.JWE.from_record(jwe), plain_text}
      error ->
        error
    end
  end

  def box_encrypt(plain_text, other_public_jwk=%JOSE.JWK{}), do: box_encrypt(plain_text, to_record(other_public_jwk))
  def box_encrypt(plain_text, other_public_jwk), do: :jose_jwk.box_encrypt(plain_text, other_public_jwk)

  def box_encrypt(plain_text, other_public_jwk=%JOSE.JWK{}, my_private_jwk), do: box_encrypt(plain_text, to_record(other_public_jwk), my_private_jwk)
  def box_encrypt(plain_text, other_public_jwk, my_private_jwk=%JOSE.JWK{}), do: box_encrypt(plain_text, other_public_jwk, to_record(my_private_jwk))
  def box_encrypt(plain_text, other_public_jwk, my_private_jwk), do: :jose_jwk.box_encrypt(plain_text, other_public_jwk, my_private_jwk)

  def box_encrypt(plain_text, jwe=%JOSE.JWE{}, other_public_jwk, my_private_jwk), do: box_encrypt(plain_text, JOSE.JWE.to_record(jwe), other_public_jwk, my_private_jwk)
  def box_encrypt(plain_text, jwe, other_public_jwk=%JOSE.JWK{}, my_private_jwk), do: box_encrypt(plain_text, jwe, to_record(other_public_jwk), my_private_jwk)
  def box_encrypt(plain_text, jwe, other_public_jwk, my_private_jwk=%JOSE.JWK{}), do: box_encrypt(plain_text, jwe, other_public_jwk, to_record(my_private_jwk))
  def box_encrypt(plain_text, jwe, other_public_jwk, my_private_jwk), do: :jose_jwk.box_encrypt(plain_text, jwe, other_public_jwk, my_private_jwk)

  def generate_key(jwk=%JOSE.JWK{}), do: jwk |> to_record |> generate_key
  def generate_key(parameters), do: :jose_jwk.generate_key(parameters) |> from_record

  def sign(plain_text, jwk=%JOSE.JWK{}), do: sign(plain_text, to_record(jwk))
  def sign(plain_text, jwk), do: :jose_jwk.sign(plain_text, jwk)

  def sign(plain_text, jws=%JOSE.JWS{}, jwk), do: sign(plain_text, JOSE.JWS.to_record(jws), jwk)
  def sign(plain_text, jws, jwk=%JOSE.JWK{}), do: sign(plain_text, jws, to_record(jwk))
  def sign(plain_text, jws, jwk), do: :jose_jwk.sign(plain_text, jws, jwk)

  def thumbprint(jwk=%JOSE.JWK{}), do: thumbprint(to_record(jwk))
  def thumbprint(jwk), do: :jose_jwk.thumbprint(jwk)

  def thumbprint(digest_type, jwk=%JOSE.JWK{}), do: thumbprint(digest_type, to_record(jwk))
  def thumbprint(digest_type, jwk), do: :jose_jwk.thumbprint(digest_type, jwk)

  def verify(signed, jwk=%JOSE.JWK{}), do: verify(signed, to_record(jwk))
  def verify(signed, jwk) do
    case :jose_jwk.verify(signed, jwk) do
      {verified, payload, jws} when is_tuple(jws) ->
        {verified, payload, JOSE.JWS.from_record(jws)}
      error ->
        error
    end
  end

end
