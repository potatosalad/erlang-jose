defmodule JOSE.JWA do

  # API
  def block_cipher(cipher), do: :jose_jwa.block_cipher(cipher)
  def block_decrypt(cipher, key, cipher_text), do: :jose_jwa.block_decrypt(cipher, key, cipher_text)
  def block_decrypt(cipher, key, iv, cipher_text), do: :jose_jwa.block_decrypt(cipher, key, iv, cipher_text)
  def block_encrypt(cipher, key, plain_text), do: :jose_jwa.block_encrypt(cipher, key, plain_text)
  def block_encrypt(cipher, key, iv, plain_text), do: :jose_jwa.block_encrypt(cipher, key, iv, plain_text)
  def crypto_ciphers(), do: :jose_jwa.crypto_ciphers()
  def crypto_fallback(), do: :jose_jwa.crypto_fallback()
  def crypto_fallback(boolean), do: :jose_jwa.crypto_fallback(boolean)
  def crypto_supports(), do: :jose_jwa.crypto_supports()
  def constant_time_compare(a, b), do: :jose_jwa.constant_time_compare(a, b)
  def ec_key_mode(), do: :jose_jwa.ec_key_mode()
  def is_native_cipher(cipher), do: :jose_jwa.is_native_cipher(cipher)
  def is_rsa_padding_supported(rsa_padding), do: :jose_jwa.is_rsa_padding_supported(rsa_padding)
  def is_signer_supported(signer), do: :jose_jwa.is_signer_supported(signer)
  def supports(), do: :jose_jwa.supports()

end
