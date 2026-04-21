# Public API
defmodule ExCcrypto.Asymkey.AsymkeyContextBuilder do
  alias ExCcrypto.Asymkey.RSA.RSAKeypair
  alias ExCcrypto.Asymkey.Ecc.EccKeypair

  def generator_context(algo \\ :ecc)

  def generator_context(:ecc) do
    %EccKeypair{}
  end

  def generator_context(:rsa), do: %RSAKeypair{}

  # def generator_context(:kaz_sign), do: %KazSignKeypair{}

  # def generator_context(:ml_dsa), do: %MlDsaKeypair{}

  # def generator_context(:slh_dsa), do: %SlhDsaKeypair{}

  # def generator_context(:ml_kem), do: %MlKemKeypair{}

  # def generator_context(:kaz_kem), do: %KazKemKeypair{}

  def generator_context(algo), do: {:error, {:unsupported_asymkey_generator_algo, algo}}
end
