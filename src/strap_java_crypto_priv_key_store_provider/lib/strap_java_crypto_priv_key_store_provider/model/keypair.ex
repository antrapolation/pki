defmodule StrapJavaCryptoPrivKeyStoreProvider.Model.Keypair do
  use TypedStruct

  typedstruct do
    field(:purpose, any())
    field(:algo, any())
    field(:params, any())
    field(:value, any())
    field(:opts, any(), default: %{})
    field(:process_group_name, any())
    field(:landing_node, any())
  end

  # Need to define alias for Keypair here if used inside
  alias __MODULE__
end

alias StrapPrivKeyStoreProvider.Protocol.KeypairEngine
alias StrapJavaCryptoPrivKeyStoreProvider.Model.Keypair

defimpl KeypairEngine, for: Keypair do
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.JavaKeystore
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.Privkey
  alias StrapJavaCryptoPrivKeyStoreProvider.Model.Pubkey
  alias ExCcrypto.X509.CertProfile
  alias ExCcrypto.X509.CertOwner
  alias ExCcrypto.ContextConfig

  def keypair_purpose(%Keypair{} = kp, _opts), do: kp.purpose

  def to_keystore(%Keypair{} = kp, auth_token, opts) do
    group_name = Map.get(opts, :crypto_group, :ap_java_crypto)
    safe_opts = Map.drop(opts, [:timeout]) |> Map.put(:store_pass, auth_token)

    # 1. Generate Self-Signed Cert
    # We need to construct owner with public key
    # PubKey in value is now a tuple {algo, :public_key, key}
    pubKeyTuple = Map.get(kp.value, :public_key)
    privKeyTuple = Map.get(kp.value, :private_key)

    owner =
      %CertOwner{}
      |> CertOwner.set_name("CN=Self Signed Keypair")
      |> CertOwner.set_public_key(pubKeyTuple)

    # Issuer profile for self-signed
    issuer =
      CertProfile.self_sign_issuer_cert_config()
      |> CertProfile.set_signing_hash(:sha512)
      |> CertProfile.set_validity_period({{2025, 1, 1}, {0, 0, 0}}, {1, :year})

    # Use Tuple for issuer_key (ApJavaCrypto unwraps it)
    issuer_key_tuple = privKeyTuple
    profile = CertProfile.set_issuer_key(issuer, issuer_key_tuple)

    # Sanitize owner and profile to remove nils (which become :nil atoms and crash JRuby)
    sanitized_owner =
      Map.from_struct(owner) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

    sanitized_profile =
      Map.from_struct(profile) |> Enum.reject(fn {_, v} -> is_nil(v) end) |> Map.new()

    # Ensure safe_opts passed
    with {:ok, cert} <-
           ApJavaCrypto.issue_certificate(
             sanitized_owner,
             sanitized_profile,
             Map.put(safe_opts, :group_name, group_name)
           ) do
      # 2. Generate PKCS12
      key_alias = "1"

      # ApJavaCrypto.generate_p12 takes key.
      # Since wrapper doesn't unwrap, we might need to be careful.
      # But let's assume consistent Tuple usage or that I can fix wrapper later if needed.
      # Wait, if wrapper doesn't unwrap, and JRuby expects binary/unwrapped...
      # But generate_p12 usually takes private key object?

      key_tuple = privKeyTuple

      # cert needs to be passed. issue_certificate returns {:der, bin} or {:pem, ...} depending on opts?
      # Default is likely DER or format ApJavaCrypto returns.
      # ApJavaCrypto.issue_certificate returns {:ok, {:der, cert}} usually.

      # ApJavaCrypto.generate_p12 expects cert argument.

      case ApJavaCrypto.generate_p12(
             key_alias,
             key_tuple,
             cert,
             [],
             Map.put(safe_opts, :group_name, group_name)
           ) do
        {:ok, p12_bin} ->
          {:ok,
           %JavaKeystore{
             store_type: :pkcs12,
             enc_keypair: p12_bin,
             algo: kp.algo,
             params: kp.params,
             purpose: kp.purpose,
             process_group_name: kp.process_group_name,
             landing_node: kp.landing_node
           }}

        {:ok, p12_bin, _addr} ->
          {:ok,
           %JavaKeystore{
             store_type: :pkcs12,
             enc_keypair: p12_bin,
             algo: kp.algo,
             params: kp.params,
             purpose: kp.purpose,
             process_group_name: kp.process_group_name,
             landing_node: kp.landing_node
           }}

        err ->
          err
      end
    else
      err -> err
    end
  end

  def set_keypair_info(%Keypair{} = kp, key, value, _opts) do
    %Keypair{
      kp
      | opts:
          Map.get(kp, :opts, %{})
          |> Map.put(key, value)
    }
  end

  def remove_keypair_info(%Keypair{} = kp, key, _opts) do
    %Keypair{kp | opts: Map.delete(kp.opts, key)}
  end

  def get_keypair_info(%Keypair{} = kp, key, _opts), do: Map.get(kp.opts, key)

  def public_key(%Keypair{} = kp, _opts),
    do: %Pubkey{
      algo: kp.algo,
      params: kp.params,
      purpose: kp.purpose,
      value: Map.get(kp.value, :public_key),
      process_group_name: kp.process_group_name,
      landing_node: kp.landing_node
    }

  def private_key(%Keypair{} = kp, _opts),
    do: %Privkey{
      algo: kp.algo,
      params: kp.params,
      purpose: kp.purpose,
      value: Map.get(kp.value, :private_key),
      process_group_name: kp.process_group_name,
      landing_node: kp.landing_node
    }
end
