defmodule JOSE.JWA do

  # API
  def block_cipher(), do: :jose_jwa.block_cipher()
  def block_decrypt(cipher, key, cipher_text), do: :jose_jwa.block_decrypt(cipher, key, cipher_text)
  def block_decrypt(cipher, key, iv, cipher_text), do: :jose_jwa.block_decrypt(cipher, key, iv, cipher_text)
  def block_encrypt(cipher, key, plain_text), do: :jose_jwa.block_encrypt(cipher, key, plain_text)
  def block_encrypt(cipher, key, iv, plain_text), do: :jose_jwa.block_encrypt(cipher, key, iv, plain_text)
  def ciphers(), do: :jose_jwa.ciphers()
  def constant_time_compare(a, b), do: :jose_jwa.constant_time_compare(a, b)
  def ec_key_mode(), do: :jose_jwa.ec_key_mode()
  def supports(), do: :jose_jwa.supports()

end
