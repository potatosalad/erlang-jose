defmodule JOSETest do
  use ExUnit.Case

  test "JOSE.JWE decode and encode" do
    map = %{ "alg" => "dir", "enc" => "A128GCM" }
    binary = :jsx.encode(map)
    jwe = JOSE.JWE.from_map(map)
    assert map == :erlang.element(2, JOSE.JWE.to_map(jwe))
    assert binary == :erlang.element(2, JOSE.JWE.to_binary(jwe))
    assert jwe == JOSE.JWE.from_binary(binary)
    assert jwe == JOSE.JWE.from(jwe)
  end

  test "JOSE.JWK decode and encode" do
    map = %{
      "crv" => "P-256", "d" => "aJhYDBNS-5yrH97PAExzWNLlJGqJwFGZmv7iJvdG4p0",
      "kty" => "EC", "x" => "LksdLpZN3ijcn_TBfRK-_tgmvws0c5_V5k0bg14RLhU",
      "y" => "ukc-JOEAWhW664SY5Q29xHlAVEDlrQwYF3-vQ_cdi1s"
    }
    password = "password"
    binary = :jsx.encode(map)
    jwk = JOSE.JWK.from_map(map)
    assert map == :erlang.element(2, JOSE.JWK.to_map(jwk))
    assert binary == :erlang.element(2, JOSE.JWK.to_binary(jwk))
    assert jwk == JOSE.JWK.from_binary(binary)
    assert jwk == JOSE.JWK.from(jwk)
    assert jwk == JOSE.JWK.from_pem(JOSE.JWK.to_pem(jwk))
    assert jwk == :erlang.element(2, JOSE.JWK.from_binary(password, JOSE.JWK.to_binary(password, jwk)))
    assert jwk == :erlang.element(2, JOSE.JWK.from_map(password, JOSE.JWK.to_map(password, jwk)))
    assert jwk == JOSE.JWK.from_pem(password, JOSE.JWK.to_pem(password, jwk))
  end

  test "JOSE.JWS decode and encode" do
    map = %{ "alg" => "HS256" }
    binary = :jsx.encode(map)
    jws = JOSE.JWS.from_map(map)
    assert map == :erlang.element(2, JOSE.JWS.to_map(jws))
    assert binary == :erlang.element(2, JOSE.JWS.to_binary(jws))
    assert jws == JOSE.JWS.from_binary(binary)
    assert jws == JOSE.JWS.from(jws)
  end

  test "JOSE.JWT decode and encode" do
    map = %{ "test" => true }
    binary = :jsx.encode(map)
    jwt = JOSE.JWT.from_map(map)
    assert map == :erlang.element(2, JOSE.JWT.to_map(jwt))
    assert binary == :erlang.element(2, JOSE.JWT.to_binary(jwt))
    assert jwt == JOSE.JWT.from_binary(binary)
    assert jwt == JOSE.JWT.from(jwt)
  end
end
