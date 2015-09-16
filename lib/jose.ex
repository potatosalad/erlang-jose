defmodule JOSE do

  @moduledoc """
  JOSE stands for JSON Object Signing and Encryption. It is a set of standards 
  specified by the IETF. The oficial specifications are described below:

  - JWS (Json Web Signature)  : [RFC7515](https://tools.ietf.org/html/rfc7515)
  - JWE (Json Web Encryption) : [RFC7516](https://tools.ietf.org/html/rfc7516)
  - JWK (Json Web Key)        : [RFC7517](https://tools.ietf.org/html/rfc7517)
  - JWA (Json Web Algorithms) : [RFC7518](https://tools.ietf.org/html/rfc7518)
  - JWT (Json Web Token)      : [RFC7519](https://tools.ietf.org/html/rfc7519)

  This module is the main entry point for decoding/encoding a JWT.
  """
  
  # API
  @doc """
  Decodes a JWT in binary form into a map of claims.
  """
  def decode(binary), do: :jose.decode(binary)

  @doc """
  Encodes a given JOSE term into a binary representation.
  """
  def encode(term), do: :jose.encode(term)

  @doc """
  Retrieves the current set JSON module. 
  """
  def json_module(), do: :jose.json_module()

  
  @doc """
  Sets the JSON module used for JSON encoding/decoding. Currently 
  supports Poison and JSX.
  """
  def json_module(module), do: :jose.json_module(module)

end
