defmodule JOSE.JWA do

  # Crypto API
  def block_decrypt(cipher, key, cipher_text), do: :jose_jwa.block_decrypt(cipher, key, cipher_text)
  def block_decrypt(cipher, key, iv, cipher_text), do: :jose_jwa.block_decrypt(cipher, key, iv, cipher_text)
  def block_encrypt(cipher, key, plain_text), do: :jose_jwa.block_encrypt(cipher, key, plain_text)
  def block_encrypt(cipher, key, iv, plain_text), do: :jose_jwa.block_encrypt(cipher, key, iv, plain_text)
  # Public Key API
  def decrypt_private(cipher_text, private_key, options), do: :jose_jwa.decrypt_private(cipher_text, private_key, options)
  def encrypt_public(plain_text, public_key, options), do: :jose_jwa.encrypt_public(plain_text, public_key, options)
  def sign(message, digest_type, private_key, options), do: :jose_jwa.sign(message, digest_type, private_key, options)
  def verify(message, digest_type, signature, public_key, options), do: :jose_jwa.verify(message, digest_type, signature, public_key, options)
  # API
  def block_cipher(cipher), do: :jose_jwa.block_cipher(cipher)
  def crypto_ciphers(), do: :jose_jwa.crypto_ciphers()
  def crypto_fallback(), do: :jose_jwa.crypto_fallback()
  def crypto_fallback(boolean), do: :jose_jwa.crypto_fallback(boolean)
  def crypto_supports(), do: :jose_jwa.crypto_supports()
  def constant_time_compare(a, b), do: :jose_jwa.constant_time_compare(a, b)
  def ec_key_mode(), do: :jose_jwa.ec_key_mode()
  def is_block_cipher_supported(cipher), do: :jose_jwa.is_block_cipher_supported(cipher)
  def is_rsa_crypt_supported(padding), do: :jose_jwa.is_rsa_crypt_supported(padding)
  def is_rsa_sign_supported(padding), do: :jose_jwa.is_rsa_sign_supported(padding)
  def supports(), do: :jose_jwa.supports()

end
