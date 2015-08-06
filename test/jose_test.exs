defmodule JOSETest do
  use ExUnit.Case

  test "JOSE.JWA 128-bit encrypt and decrypt" do
    key = << 0 :: 128 >>
    cbc_iv = << 0 :: 128 >>
    gcm_iv = << 0 :: 96 >>
    aad = <<>>
    plain_text = "my plain text that will be encrypted and decrypted"
    padded_plain_text = :jose_jwa_pkcs7.pad(plain_text)
    cbc_cipher_text = <<199,137,180,181,237,81,30,239,12,183,48,136,189,120,32,120,2,184,140,30,193,245,216,166,134,123,91,16,96,158,102,48,174,205,240,31,66,164,135,107,142,193,158,113,111,41,201,248,18,235,208,146,39,147,167,155,213,115,66,41,32,147,133,108>>
    ecb_cipher_text = <<199,137,180,181,237,81,30,239,12,183,48,136,189,120,32,120,196,190,232,104,49,166,58,104,4,101,23,230,131,230,216,54,111,74,1,207,251,80,216,24,126,96,68,178,160,232,54,184,174,111,184,35,145,216,208,74,42,19,166,82,247,178,75,249>>
    gcm_cipher_text = <<110,241,250,190,12,215,202,252,211,92,167,193,5,146,138,16,150,225,138,220,32,39,53,3,149,152,169,154,250,232,179,153,80,118,116,69,110,18,250,190,0,237,211,207,162,234,219,148,172,41,172,23,31,128,39,115,117,112,178,178,199,205,134,252>>
    gcm_cipher_tag  = <<51,155,66,18,126,201,118,185,242,41,175,75,96,213,29,68>>
    assert cbc_cipher_text == JOSE.JWA.block_encrypt({:aes_cbc, 128}, key, cbc_iv, padded_plain_text)
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_cbc, 128}, key, cbc_iv, cbc_cipher_text))
    assert ecb_cipher_text == JOSE.JWA.block_encrypt({:aes_ecb, 128}, key, padded_plain_text)
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_ecb, 128}, key, ecb_cipher_text))
    assert {gcm_cipher_text, gcm_cipher_tag} == JOSE.JWA.block_encrypt({:aes_gcm, 128}, key, gcm_iv, {aad, padded_plain_text})
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_gcm, 128}, key, gcm_iv, {aad, gcm_cipher_text, gcm_cipher_tag}))
  end

  test "JOSE.JWA 192-bit encrypt and decrypt" do
    key = << 0 :: 192 >>
    cbc_iv = << 0 :: 128 >>
    gcm_iv = << 0 :: 96 >>
    aad = <<>>
    plain_text = "my plain text that will be encrypted and decrypted"
    padded_plain_text = :jose_jwa_pkcs7.pad(plain_text)
    cbc_cipher_text = <<49,252,5,74,231,203,35,84,241,143,161,11,238,168,150,220,5,186,188,246,39,46,14,237,8,193,241,107,82,192,36,19,53,7,75,14,27,5,84,179,141,162,74,154,7,86,106,203,149,140,92,130,21,168,122,3,174,155,120,197,130,55,103,223>>
    ecb_cipher_text = <<49,252,5,74,231,203,35,84,241,143,161,11,238,168,150,220,199,197,40,176,120,24,25,198,250,225,235,25,140,32,110,32,11,103,244,196,171,249,227,108,87,189,94,52,92,58,79,128,169,219,180,118,180,153,232,208,144,0,5,212,7,192,23,103>>
    gcm_cipher_text = <<245,158,4,12,107,145,151,47,60,82,27,59,240,144,130,104,75,64,179,145,11,89,130,71,188,137,237,74,85,90,73,161,141,222,114,166,237,131,108,12,222,82,132,7,152,42,81,37,183,62,208,42,184,124,230,10,12,131,73,76,18,61,3,18>>
    gcm_cipher_tag  = <<35,252,154,36,245,70,214,141,72,99,106,35,226,195,77,212>>
    assert cbc_cipher_text == JOSE.JWA.block_encrypt({:aes_cbc, 192}, key, cbc_iv, padded_plain_text)
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_cbc, 192}, key, cbc_iv, cbc_cipher_text))
    assert ecb_cipher_text == JOSE.JWA.block_encrypt({:aes_ecb, 192}, key, padded_plain_text)
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_ecb, 192}, key, ecb_cipher_text))
    assert {gcm_cipher_text, gcm_cipher_tag} == JOSE.JWA.block_encrypt({:aes_gcm, 192}, key, gcm_iv, {aad, padded_plain_text})
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_gcm, 192}, key, gcm_iv, {aad, gcm_cipher_text, gcm_cipher_tag}))
  end

  test "JOSE.JWA 256-bit encrypt and decrypt" do
    key = << 0 :: 256 >>
    cbc_iv = << 0 :: 128 >>
    gcm_iv = << 0 :: 96 >>
    aad = <<>>
    plain_text = "my plain text that will be encrypted and decrypted"
    padded_plain_text = :jose_jwa_pkcs7.pad(plain_text)
    cbc_cipher_text = <<203,134,178,199,240,85,211,255,152,87,193,89,160,129,80,189,223,27,211,79,247,100,28,81,198,122,151,141,179,241,149,10,252,151,150,73,95,129,227,179,158,239,118,253,99,84,37,102,255,147,113,55,174,214,3,204,67,163,185,56,180,124,27,211>>
    ecb_cipher_text = <<203,134,178,199,240,85,211,255,152,87,193,89,160,129,80,189,59,31,176,85,123,202,110,75,65,52,218,70,130,255,90,56,44,137,185,81,14,5,40,131,196,105,44,121,10,106,53,147,77,203,1,167,110,119,19,238,140,17,112,102,230,171,149,48>>
    gcm_cipher_text = <<163,222,96,77,33,1,2,0,39,58,160,171,206,211,233,112,19,20,35,189,94,202,70,84,179,199,213,235,27,101,71,247,173,62,212,76,109,43,143,31,97,140,60,71,53,117,70,131,34,37,197,239,143,181,113,62,111,114,19,237,165,2,52,17>>
    gcm_cipher_tag  = <<62,158,38,76,169,81,223,217,172,83,155,21,226,51,65,230>>
    assert cbc_cipher_text == JOSE.JWA.block_encrypt({:aes_cbc, 256}, key, cbc_iv, padded_plain_text)
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_cbc, 256}, key, cbc_iv, cbc_cipher_text))
    assert ecb_cipher_text == JOSE.JWA.block_encrypt({:aes_ecb, 256}, key, padded_plain_text)
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_ecb, 256}, key, ecb_cipher_text))
    assert {gcm_cipher_text, gcm_cipher_tag} == JOSE.JWA.block_encrypt({:aes_gcm, 256}, key, gcm_iv, {aad, padded_plain_text})
    assert plain_text == :jose_jwa_pkcs7.unpad(JOSE.JWA.block_decrypt({:aes_gcm, 256}, key, gcm_iv, {aad, gcm_cipher_text, gcm_cipher_tag}))
  end

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
