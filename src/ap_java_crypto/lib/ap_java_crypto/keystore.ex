defmodule ApJavaCrypto.Keystore do
  alias ApJavaCrypto.SlhDsa.SlhDsaPrivateKey
  alias ApJavaCrypto.MlDsa.MlDsaPrivateKey
  alias ApJavaCrypto.KazSign.KazSignPrivateKey

  require Logger

  def to_pkcs12_keystore(keypair, cert, chain, auth_token, opts \\ %{})

  def to_pkcs12_keystore(keypair, cert, chain, auth_token, opts) when not is_list(chain),
    do: to_pkcs12_keystore(keypair, cert, [chain], auth_token, opts)

  def to_pkcs12_keystore(
        key,
        {:der, {:ap_java_crypto, cert}},
        chain,
        auth_token,
        opts
      ) do
    Logger.debug("P12 to ApJavaCrypto")
    name = Map.get(opts, :name, "P12 Keystore")

    cchain =
      Enum.map(chain, fn c ->
        {:der, {:ap_java_crypto, cb}} = c
        {:der, cb}
      end)

    ApJavaCrypto.generate_p12(
      name,
      {key.variant, :private_key, key.value},
      {:der, cert},
      cchain,
      %{
        store_pass: auth_token
      }
    )
  end

  def load_pkcs12_keystore({:ap_java_crypto, keystore}, auth_token, _opts \\ %{}) do
    with {:ok, cont} <- ApJavaCrypto.load_p12(keystore, %{store_pass: auth_token}) do
      {:ok,
       Enum.map(cont, fn r ->
         %{
           r
           | key: to_private_key(r.key),
             cert: {:der, {:ap_java_crypto, r.cert}},
             chain: Enum.map(r.chain, fn c -> {:der, {:ap_java_crypto, c}} end)
         }
       end)}
    end
  end

  defp to_private_key(%{algo: algo, value: value}) do
    talgo = String.downcase(to_string(algo))

    cond do
      String.starts_with?(talgo, "kaz-sign") ->
        KazSignPrivateKey.new(String.to_atom(talgo), value)

      String.starts_with?(talgo, "ml-dsa") ->
        MlDsaPrivateKey.new(String.to_atom(talgo), value)

      String.starts_with?(talgo, "slh-dsa") ->
        SlhDsaPrivateKey.new(String.to_atom(talgo), value)

      true ->
        raise "Unsupported private key algo : #{talgo}"
    end
  end
end
