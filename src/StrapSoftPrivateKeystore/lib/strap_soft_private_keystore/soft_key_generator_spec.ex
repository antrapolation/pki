defmodule StrapSoftPrivateKeystore.SoftKeyGeneratorSpec do
  alias StrapSoftPrivateKeystore.SoftKeyGeneratorSpec
  use TypedStruct

  typedstruct do
    field(:algo, any())
    field(:params, any())
  end

  def new(algo, params) do
    %SoftKeyGeneratorSpec{algo: algo, params: params}
  end
end

defimpl StrapPrivateKeystore.KeyGenerator, for: StrapSoftPrivateKeystore.SoftKeyGeneratorSpec do
  alias StrapSoftPrivateKeystore.SoftKeypair
  alias ExCcrypto.Asymkey
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.Asymkey.AsymkeyContextBuilder
  alias StrapSoftPrivateKeystore.SoftKeyGeneratorSpec

  def generate_keypair(%SoftKeyGeneratorSpec{algo: :ecc, params: curve}, _opts) do
    with {:ok, kp} <-
           AsymkeyContextBuilder.generator_context(:ecc)
           |> ContextConfig.set(:curve, curve)
           |> Asymkey.generate() do
      {:ok, SoftKeypair.new(kp)}
    end
  end

  def generate_keypair(%SoftKeyGeneratorSpec{algo: :kaz_sign, params: variant}, _opts) do
    with {:ok, kp} <-
           AsymkeyContextBuilder.generator_context(:kaz_sign)
           |> ContextConfig.set(:variant, variant)
           |> Asymkey.generate() do
      {:ok, SoftKeypair.new(kp)}
    end
  end

  def generate_keypair(%SoftKeyGeneratorSpec{algo: :ml_dsa, params: variant}, _opts) do
    with {:ok, kp} <-
           AsymkeyContextBuilder.generator_context(:ml_dsa)
           |> ContextConfig.set(:variant, variant)
           |> Asymkey.generate() do
      {:ok, SoftKeypair.new(kp)}
    end
  end

  def generate_keypair(%SoftKeyGeneratorSpec{algo: :slh_dsa, params: variant}, _opts) do
    with {:ok, kp} <-
           AsymkeyContextBuilder.generator_context(:slh_dsa)
           |> ContextConfig.set(:variant, variant)
           |> Asymkey.generate() do
      {:ok, SoftKeypair.new(kp)}
    end
  end

  def generate_keypair(%SoftKeyGeneratorSpec{algo: :ml_kem, params: variant}, _opts) do
    with {:ok, kp} <-
           AsymkeyContextBuilder.generator_context(:ml_kem)
           |> ContextConfig.set(:variant, variant)
           |> Asymkey.generate() do
      {:ok, SoftKeypair.new(kp)}
    end
  end

  def generate_keypair(%SoftKeyGeneratorSpec{algo: :kaz_kem, params: variant}, _opts) do
    with {:ok, kp} <-
           AsymkeyContextBuilder.generator_context(:kaz_kem)
           |> ContextConfig.set(:variant, variant)
           |> Asymkey.generate() do
      {:ok, SoftKeypair.new(kp)}
    end
  end
end
