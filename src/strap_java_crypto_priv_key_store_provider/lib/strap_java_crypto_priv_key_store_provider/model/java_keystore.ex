defmodule StrapJavaCryptoPrivKeyStoreProvider.Model.JavaKeystore do
  use TypedStruct

  typedstruct do
    field(:store_type, any())
    field(:enc_keypair, any())
    field(:algo, any())
    field(:params, any())
    field(:opts, any())
    field(:purpose, any())
    field(:process_group_name, any())
    field(:landing_node, any())
  end

  alias __MODULE__
end

alias StrapJavaCryptoPrivKeyStoreProvider.Model.JavaKeystore
alias StrapPrivKeyStoreProvider.Protocol.KeystoreManagerProtocol

defimpl KeystoreManagerProtocol, for: JavaKeystore do
  alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.Keypair
  alias ExCcrypto.Asymkey.AsymkeystoreLoader

  def update_auth_token(%JavaKeystore{} = ks, existing, new, opts) do
    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, existing, opts),
         {:ok, keystore} <- KeypairEngine.to_keystore(keypair, new, opts) do
      {:ok, keystore}
    end
  end

  def to_keypair(%JavaKeystore{} = ks, auth_token, opts) do
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout, :issuer_cert]) |> Map.put(:store_pass, auth_token)

    case ApJavaCrypto.load_p12(ks.enc_keypair, Map.put(safe_opts, :group_name, group_name)) do
      {:ok, [entry | _]} ->
        # entry is expected to be %{name: "1", key: %{value: priv, algo: ...}, cert: cert, chain: ...}
        # We need to extract public key from cert because entry.key only has private key usually

        cert = entry.cert
        privKey = entry.key.value

        # Extract PubKey from Cert
        {:ok, cert_info} =
          ApJavaCrypto.parse_cert(cert, Map.put(safe_opts, :group_name, group_name))

        pubKey = cert_info.public_key

        # Reconstruct Tuples
        algo = ks.algo
        privKeyTuple = {algo, :private_key, privKey}
        # PubKeyTuple needs to match what ApJavaCrypto expects.
        # ApJavaCrypto.parse_cert returns binary public key.
        # We wrap it in {algo, :public_key, binary}
        pubKeyTuple = {algo, :public_key, pubKey}

        content = %{
          private_key: privKeyTuple,
          public_key: pubKeyTuple
        }

        # Store cert and chain in opts for future use (e.g. to_keystore)
        kp_opts = %{
          cert: cert,
          chain: entry.chain,
          alias: entry.name
        }

        {:ok,
         %Keypair{
           algo: ks.algo,
           value: content,
           params: ks.params,
           purpose: ks.purpose,
           process_group_name: ks.process_group_name,
           landing_node: ks.landing_node,
           opts: kp_opts
         }}

      err ->
        err
    end
  end
end

alias StrapPrivKeyStoreProvider.Protocol.CertManagerProtocol
alias StrapJavaCryptoPrivKeyStoreProvider.Model.JavaKeystore

defimpl CertManagerProtocol, for: JavaKeystore do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CertOwner

  # self-sign
  def generate_cert(%JavaKeystore{} = ks, %CertOwner{} = owner, %CertProfile{} = issuer, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)

    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token, opts) do
      privKey = Map.get(keypair.value, :private_key)
      pubKey = Map.get(keypair.value, :public_key)

      cowner =
        case issuer.self_sign do
          true -> CertOwner.set_public_key(owner, pubKey)
          false -> owner
        end

      # Prepare Issuer Key Tuple for ApJavaCrypto
      # privKey is ALREADY a tuple {algo, :private_key, bin}
      issuer_key_tuple = privKey

      # Use Tuple for issuer_key in profile
      profile = CertProfile.set_issuer_key(issuer, issuer_key_tuple)

      safe_opts = Map.drop(opts, [:timeout, :issuer_cert])

      sanitized_owner =
        Map.from_struct(cowner) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      sanitized_profile =
        Map.from_struct(profile) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      ApJavaCrypto.issue_certificate(
        sanitized_owner,
        sanitized_profile,
        Map.put(safe_opts, :group_name, group_name)
      )
    end
  end

  def issuer_cert(_, _, _, %{issuer_cert: ic}) when is_nil(ic),
    do: {:error, :issuer_cert_is_required}

  def issue_cert(%JavaKeystore{} = ks, %CertOwner{} = owner, %CertProfile{} = issuer, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)
    issuer_cert = Map.get(opts, :issuer_cert)
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token, opts) do
      privKey = Map.get(keypair.value, :private_key)
      # privKey is Tuple

      profile =
        CertProfile.set_issuer_key(issuer, privKey)
        |> CertProfile.set_issuer_cert(issuer_cert)

      safe_opts = Map.drop(opts, [:timeout, :issuer_cert])

      sanitized_owner =
        Map.from_struct(owner) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      sanitized_profile =
        Map.from_struct(profile) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      ApJavaCrypto.issue_certificate(
        sanitized_owner,
        sanitized_profile,
        Map.put(safe_opts, :group_name, group_name)
      )
    end
  end

  def issue_cert(%JavaKeystore{} = ks, csr, %CertProfile{} = issuer, opts) when is_binary(csr) do
    auth_token = Map.get(opts, :keystore_auth_token)
    issuer_cert = Map.get(opts, :issuer_cert)
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token, opts) do
      privKey = Map.get(keypair.value, :private_key)
      # privKey is Tuple

      profile =
        CertProfile.set_issuer_key(issuer, privKey)
        |> CertProfile.set_issuer_cert(issuer_cert)

      safe_opts = Map.drop(opts, [:timeout, :issuer_cert])

      sanitized_profile =
        Map.from_struct(profile) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      ApJavaCrypto.issue_certificate(
        {:der, csr},
        sanitized_profile,
        Map.put(safe_opts, :group_name, group_name)
      )
    end
  end

  def issue_cert(%JavaKeystore{} = ks, {:native, csr}, %CertProfile{} = issuer, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)
    issuer_cert = Map.get(opts, :issuer_cert)
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token, opts) do
      privKey = Map.get(keypair.value, :private_key)
      # privKey is Tuple

      profile =
        CertProfile.set_issuer_key(issuer, privKey)
        |> CertProfile.set_issuer_cert(issuer_cert)

      safe_opts = Map.drop(opts, [:timeout, :issuer_cert])
      # ApJavaCrypto accepts {:der, csr}

      sanitized_profile =
        Map.from_struct(profile) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      ApJavaCrypto.issue_certificate(
        {:der, csr},
        sanitized_profile,
        Map.put(safe_opts, :group_name, group_name)
      )
    end
  end

  def issue_cert(_, csr, _, _), do: {:error, {:native_csr_expected, csr}}
end

alias StrapPrivKeyStoreProvider.Protocol.CSRGeneratorProtocol

defimpl CSRGeneratorProtocol, for: JavaKeystore do
  alias ExCcrypto.ContextConfig
  alias ExCcrypto.X509.CertOwner

  def generate(%JavaKeystore{} = ks, %CertOwner{} = owner, opts) do
    auth_token = Map.get(opts, :keystore_auth_token)
    output = Map.get(opts, :output_format, :bin)
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)

    with {:ok, keypair} <- KeystoreManagerProtocol.to_keypair(ks, auth_token, opts) do
      privKey = Map.get(keypair.value, :private_key)
      # privKey is Tuple

      safe_opts = Map.drop(opts, [:timeout, :issuer_cert])

      sanitized_owner =
        Map.from_struct(owner) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

      case ApJavaCrypto.generate_csr(
             sanitized_owner,
             privKey,
             Map.put(safe_opts, :group_name, group_name)
           ) do
        {:ok, {:der, csr}} ->
          {:ok, format_csr(csr, output)}

        {:ok, {:der, csr}, _addr} ->
          {:ok, format_csr(csr, output)}

        err ->
          err
      end
    end
  end

  defp format_csr(csr, :bin), do: csr

  defp format_csr(csr, :pem) do
    "-----BEGIN CERTIFICATE REQUEST-----\n#{Base.encode64(csr)}\n-----END CERTIFICATE REQUEST-----\n"
  end
end
