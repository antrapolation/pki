defmodule PkiCaEngine.SystemKeypairs do
  @moduledoc """
  Creates system keypairs during tenant bootstrap.
  All keypair passwords are encrypted with the CA Admin's KEM public key.
  """

  alias PkiCaEngine.KeyVault

  @system_keypairs [
    %{name: ":root", algorithm: "ECC-P256", description: "System root signing key"},
    %{name: ":sub_root", algorithm: "ECC-P256", description: "Operational root signing key"},
    %{name: ":strap_ca_remote_service_host_signing_key", algorithm: "ECC-P256", description: "Service-to-service signing"},
    %{name: ":strap_ca_remote_service_host_cipher_key", algorithm: "ECDH-P256", description: "Service-to-service encryption"}
  ]

  def create_all(ca_instance_id, acl_kem_public_key, opts \\ []) do
    results = Enum.map(@system_keypairs, fn keypair_spec ->
      algo = Keyword.get(opts, :signing_algorithm, keypair_spec.algorithm)
      KeyVault.register_keypair(ca_instance_id, keypair_spec.name, algo, acl_kem_public_key)
    end)

    errors = Enum.filter(results, &match?({:error, _}, &1))

    if errors == [] do
      keypairs = Enum.map(results, fn {:ok, kp} -> kp end)
      {:ok, keypairs}
    else
      {:error, {:system_keypairs_failed, errors}}
    end
  end

  def list_names, do: Enum.map(@system_keypairs, & &1.name)
end
