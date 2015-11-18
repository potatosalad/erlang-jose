require Record

defmodule JOSE.JWE do
  @moduledoc ~S"""
  JWE stands for JSON Web Encryption which is defined in [RFC 7516](https://tools.ietf.org/html/rfc7516).
  """

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

  ## Decode API

  @doc """
  Converts a binary or map into a `JOSE.JWE`.

      iex> JOSE.JWE.from(%{ "alg" => "dir" })
      %JOSE.JWE{alg: {:jose_jwe_alg_dir, :dir}, enc: :undefined, fields: %{},
       zip: :undefined}
      iex> JOSE.JWE.from("{\"alg\":\"dir\"}")
      %JOSE.JWE{alg: {:jose_jwe_alg_dir, :dir}, enc: :undefined, fields: %{},
       zip: :undefined}

  There are 3 keys which can have custom modules defined for them:

    * `"alg"` - must implement `:jose_jwe` and `:jose_jwe_alg` behaviours
    * `"enc"` - must implement `:jose_jwe` and `:jose_jwe_enc` behaviours
    * `"zip"` - must implement `:jose_jwe` and `:jose_jwe_zip` behaviours

  For example:

      iex> JOSE.JWE.from({%{ zip: MyCustomCompress }, %{ "alg" => "dir", "zip" => "custom" }})
      %JOSE.JWE{alg: {:jose_jwe_alg_dir, :dir}, enc: :undefined, fields: %{},
       zip: {MyCustomCompress, :state}}

  """
  def from(jwe=%JOSE.JWE{}), do: from(to_record(jwe))
  def from(any), do: :jose_jwe.from(any) |> from_record

  @doc """
  Converts a binary into a `JOSE.JWE`.
  """
  def from_binary(binary), do: :jose_jwe.from_binary(binary) |> from_record

  @doc """
  Reads file and calls `from_binary/1` to convert into a `JOSE.JWE`.
  """
  def from_file(file), do: :jose_jwe.from_file(file) |> from_record

  @doc """
  Converts a map into a `JOSE.JWE`.
  """
  def from_map(map), do: :jose_jwe.from_map(map) |> from_record

  ## Encode API

  @doc """
  Converts a `JOSE.JWE` into a binary.
  """
  def to_binary(jwe=%JOSE.JWE{}), do: to_binary(to_record(jwe))
  def to_binary(any), do: :jose_jwe.to_binary(any)

  @doc """
  Calls `to_binary/1` on a `JOSE.JWE` and then writes the binary to file.
  """
  def to_file(file, jwe=%JOSE.JWE{}), do: to_file(file, to_record(jwe))
  def to_file(file, any), do: :jose_jwe.to_file(file, any)

  @doc """
  Converts a `JOSE.JWE` into a map.
  """
  def to_map(jwe=%JOSE.JWE{}), do: to_map(to_record(jwe))
  def to_map(any), do: :jose_jwe.to_map(any)

  ## API

  @doc """
  Decrypts the `encrypted` binary or map using the `jwk`.

      iex> jwk = JOSE.JWK.from(%{"k" => "STlqtIOhWJjoVnYjUjxFLZ6oN1oB70QARGSTWQ_5XgM", "kty" => "oct"})
      %JOSE.JWK{fields: %{}, keys: :undefined,
       kty: {:jose_jwk_kty_oct,
        <<73, 57, 106, 180, 131, 161, 88, 152, 232, 86, 118, 35, 82, 60, 69, 45, 158, 168, 55, 90, 1, 239, 68, 0, 68, 100, 147, 89, 15, 249, 94, 3>>}}
      iex> JOSE.JWE.block_decrypt(jwk, "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA")
      {"{}",
       %JOSE.JWE{alg: {:jose_jwe_alg_dir, :dir},
        enc: {:jose_jwe_enc_aes,
         {:jose_jwe_enc_aes, {:aes_cbc, 128}, 256, 32, 16, 16, 16, 16, :sha256}},
        fields: %{}, zip: :undefined}}

  See `block_encrypt/2`.
  """
  def block_decrypt(jwk=%JOSE.JWK{}, encrypted), do: block_decrypt(JOSE.JWK.to_record(jwk), encrypted)
  def block_decrypt(jwk, encrypted) do
    case :jose_jwe.block_decrypt(jwk, encrypted) do
      {plain_text, jwe} when is_tuple(jwe) ->
        {plain_text, from_record(jwe)}
      error ->
        error
    end
  end

  @doc """
  Encrypts `plain_text` using the `jwk` and algorithm specified by the `jwe` by getting the `cek` for `block_encrypt/4`.
  """
  def block_encrypt(jwk=%JOSE.JWK{}, plain_text, jwe), do: block_encrypt(JOSE.JWK.to_record(jwk), plain_text, jwe)
  def block_encrypt(jwk, plain_text, jwe=%JOSE.JWE{}), do: block_encrypt(jwk, plain_text, to_record(jwe))
  def block_encrypt(jwk, plain_text, jwe), do: :jose_jwe.block_encrypt(jwk, plain_text, jwe)

  @doc """
  Encrypts `plain_text` using the `jwk`, `cek`, and algorithm specified by the `jwe` by getting the `iv` for `block_encrypt/5`.
  """
  def block_encrypt(jwk=%JOSE.JWK{}, plain_text, cek, jwe), do: block_encrypt(JOSE.JWK.to_record(jwk), plain_text, cek, jwe)
  def block_encrypt(jwk, plain_text, cek, jwe=%JOSE.JWE{}), do: block_encrypt(jwk, plain_text, cek, to_record(jwe))
  def block_encrypt(jwk, plain_text, cek, jwe), do: :jose_jwe.block_encrypt(jwk, plain_text, cek, jwe)

  @doc """
  Encrypts the `plain_text` using the `jwk`, `cek`, `iv`, and algorithm specified by the `jwe`.

      iex> jwk = JOSE.JWK.from(%{"k" => "STlqtIOhWJjoVnYjUjxFLZ6oN1oB70QARGSTWQ_5XgM", "kty" => "oct"})
      %JOSE.JWK{fields: %{}, keys: :undefined,
       kty: {:jose_jwk_kty_oct,
        <<73, 57, 106, 180, 131, 161, 88, 152, 232, 86, 118, 35, 82, 60, 69, 45, 158, 168, 55, 90, 1, 239, 68, 0, 68, 100, 147, 89, 15, 249, 94, 3>>}}
      iex> JOSE.JWE.block_encrypt(jwk, "{}", %{ "alg" => "dir", "enc" => "A128CBC-HS256" })
      {%{alg: :jose_jwe_alg_dir, enc: :jose_jwe_enc_aes},
       %{"ciphertext" => "Ei49MvTLLje7bsZ5EZCZMA", "encrypted_key" => "",
         "iv" => "jBt5tTa1Q0N3uFPEkf30MQ",
         "protected" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
         "tag" => "gMWOAmhZSq9ksHCZm6VSoA"}}

  See `block_decrypt/2`.
  """
  def block_encrypt(jwk=%JOSE.JWK{}, plain_text, cek, iv, jwe), do: block_encrypt(JOSE.JWK.to_record(jwk), plain_text, cek, iv, jwe)
  def block_encrypt(jwk, plain_text, cek, iv, jwe=%JOSE.JWE{}), do: block_encrypt(jwk, plain_text, cek, iv, to_record(jwe))
  def block_encrypt(jwk, plain_text, cek, iv, jwe), do: :jose_jwe.block_encrypt(jwk, plain_text, cek, iv, jwe)

  @doc """
  Compacts an expanded encrypted map into a binary.

      iex> JOSE.JWE.compact(%{"ciphertext" => "Ei49MvTLLje7bsZ5EZCZMA", "encrypted_key" => "",
       "iv" => "jBt5tTa1Q0N3uFPEkf30MQ",
       "protected" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
       "tag" => "gMWOAmhZSq9ksHCZm6VSoA"})
      {%{},
       "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA"}

  See `expand/1`.
  """
  defdelegate compact(encrypted), to: :jose_jwe

  @doc """
  Compresses the `plain_text` using the `"zip"` algorithm specified by the `jwe`.

      iex> JOSE.JWE.compress("{}", %{ "alg" => "dir", "zip" => "DEF" })
      <<120, 156, 171, 174, 5, 0, 1, 117, 0, 249>>

  See `uncompress/2`.
  """
  def compress(plain_text, jwe=%JOSE.JWE{}), do: compress(plain_text, to_record(jwe))
  def compress(plain_text, jwe), do: :jose_jwe.compress(plain_text, jwe)

  @doc """
  Expands a compacted encrypted binary into a map.

      iex> JOSE.JWE.expand("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA")
      {%{},
       %{"ciphertext" => "Ei49MvTLLje7bsZ5EZCZMA", "encrypted_key" => "",
         "iv" => "jBt5tTa1Q0N3uFPEkf30MQ",
         "protected" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
         "tag" => "gMWOAmhZSq9ksHCZm6VSoA"}}

  See `compact/1`.
  """
  defdelegate expand(encrypted), to: :jose_jwe

  @doc """
  Decrypts the `encrypted_key` using the `jwk` and the `"alg"` and `"enc"` specified by the `jwe`.

      # let's define our jwk and encrypted_key
      jwk = JOSE.JWK.from(%{"k" => "idN_YyeYZqEE7BkpexhA2Q", "kty" => "oct"})
      enc = <<27, 123, 126, 121, 56, 105, 105, 81, 140, 76, 30, 2, 14, 92, 231, 174, 203, 196, 110, 204, 57, 238, 248, 73>>

      iex> JOSE.JWE.key_decrypt(jwk, enc, %{ "alg" => "A128KW", "enc" => "A128CBC-HS256" })
      <<134, 82, 15, 176, 181, 115, 173, 19, 13, 44, 189, 185, 187, 125, 28, 240>>

  See `key_encrypt/3`.
  """
  def key_decrypt(jwk=%JOSE.JWK{}, encrypted_key, jwe), do: key_decrypt(JOSE.JWK.to_record(jwk), encrypted_key, jwe)
  def key_decrypt(jwk, encrypted_key, jwe=%JOSE.JWE{}), do: key_decrypt(jwk, encrypted_key, to_record(jwe))
  def key_decrypt(jwk, encrypted_key, jwe), do: :jose_jwe.key_decrypt(jwk, encrypted_key, jwe)

  @doc """
  Encrypts the `decrypted_key` using the `jwk` and the `"alg"` and `"enc"` specified by the `jwe`.

      # let's define our jwk and cek (or decrypted_key)
      jwk = JOSE.JWK.from(%{"k" => "idN_YyeYZqEE7BkpexhA2Q", "kty" => "oct"})            # JOSE.JWK.generate_key({:oct, 16})
      cek = <<134, 82, 15, 176, 181, 115, 173, 19, 13, 44, 189, 185, 187, 125, 28, 240>> # :crypto.rand_bytes(16)

      iex> JOSE.JWE.key_encrypt(jwk, cek, %{ "alg" => "A128KW", "enc" => "A128CBC-HS256" })
      {<<27, 123, 126, 121, 56, 105, 105, 81, 140, 76, 30, 2, 14, 92, 231, 174, 203, 196, 110, 204, 57, 238, 248, 73>>,
       %JOSE.JWE{alg: {:jose_jwe_alg_aes_kw,
         {:jose_jwe_alg_aes_kw, 128, false, :undefined, :undefined}},
        enc: {:jose_jwe_enc_aes,
         {:jose_jwe_enc_aes, {:aes_cbc, 128}, 256, 32, 16, 16, 16, 16, :sha256}},
        fields: %{}, zip: :undefined}}

  See `key_decrypt/3`.
  """
  def key_encrypt(jwk=%JOSE.JWK{}, decrypted_key, jwe), do: key_encrypt(JOSE.JWK.to_record(jwk), decrypted_key, jwe)
  def key_encrypt(jwk, decrypted_key, jwe=%JOSE.JWE{}), do: key_encrypt(jwk, decrypted_key, to_record(jwe))
  def key_encrypt(jwk, decrypted_key, jwe) do
    case :jose_jwe.key_encrypt(jwk, decrypted_key, jwe) do
      {encrypted_key, jwe} when is_tuple(jwe) ->
        {encrypted_key, from_record(jwe)}
      error ->
        error
    end
  end

  @doc """
  Returns the next `cek` using the `jwk` and the `"alg"` and `"enc"` specified by the `jwe`.

      # let's define our jwk
      jwk = JOSE.JWK.from(%{"k" => "idN_YyeYZqEE7BkpexhA2Q", "kty" => "oct"}) # JOSE.JWK.generate_key({:oct, 16})

      iex> JOSE.JWE.next_cek(jwk, %{ "alg" => "A128KW", "enc" => "A128CBC-HS256" })
      <<37, 83, 139, 165, 44, 23, 163, 186, 255, 155, 183, 17, 220, 211, 80, 247, 239, 149, 194, 53, 134, 41, 254, 176, 0, 247, 66, 38, 217, 252, 82, 233>>

      # when using the "dir" algorithm, the jwk itself will be used
      iex> JOSE.JWE.next_cek(jwk, %{ "alg" => "dir", "enc" => "A128GCM" })
      <<137, 211, 127, 99, 39, 152, 102, 161, 4, 236, 25, 41, 123, 24, 64, 217>>

  """
  def next_cek(jwk=%JOSE.JWK{}, jwe), do: next_cek(JOSE.JWK.to_record(jwk), jwe)
  def next_cek(jwk, jwe=%JOSE.JWE{}), do: next_cek(jwk, to_record(jwe))
  def next_cek(jwk, jwe), do: :jose_jwe.next_cek(jwk, jwe)

  @doc """
  Returns the next `iv` the `"alg"` and `"enc"` specified by the `jwe`.

      # typically just returns random bytes for the specified "enc" algorithm
      iex> bit_size(JOSE.JWE.next_iv(%{ "alg" => "dir", "enc" => "A128CBC-HS256" }))
      128
      iex> bit_size(JOSE.JWE.next_iv(%{ "alg" => "dir", "enc" => "A128GCM" }))
      96

  """
  def next_iv(jwe=%JOSE.JWE{}), do: next_iv(to_record(jwe))
  def next_iv(jwe), do: :jose_jwe.next_iv(jwe)

  @doc """
  Uncompresses the `cipher_text` using the `"zip"` algorithm specified by the `jwe`.

      iex> JOSE.JWE.uncompress(<<120, 156, 171, 174, 5, 0, 1, 117, 0, 249>>, %{ "alg" => "dir", "zip" => "DEF" })
      "{}"

  See `compress/2`.
  """
  def uncompress(cipher_text, jwe=%JOSE.JWE{}), do: uncompress(cipher_text, to_record(jwe))
  def uncompress(cipher_text, jwe), do: :jose_jwe.uncompress(cipher_text, jwe)

end
