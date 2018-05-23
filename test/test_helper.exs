ExUnit.start()

defmodule JOSETestHelper do

  def gen_ec(curve_id) do
    :public_key.generate_key({:namedCurve, :pubkey_cert_records.namedCurves(curve_id)})
  end

  def gen_hmac do
    :crypto.strong_rand_bytes(:rand.uniform(64, 256))
  end

  def gen_private_key(:ecdsa) do
    private_key = gen_ec(:secp256r1)
    {private_key, bin_private_key(private_key)}
  end

  def bin_private_key(private_key), do: :http_signature_private_key.encode(private_key)

end
