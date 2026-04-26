defmodule PkiCaEngine.HsmAgentSetup do
  @moduledoc """
  Context module for the CA admin HSM agent setup wizard.

  Manages draft state in Mnesia, cert and token generation, and wizard
  completion (which wipes the server private key from the record).
  """

  require Logger

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.HsmAgentSetup
  alias PkiCrypto.{Algorithm, Registry, X509Builder}

  # ---------------------------------------------------------------------------
  # Draft lifecycle
  # ---------------------------------------------------------------------------

  @doc "Create a new wizard draft for the given CA instance."
  @spec create_draft(binary(), binary() | nil) :: {:ok, HsmAgentSetup.t()} | {:error, term()}
  def create_draft(ca_instance_id, tenant_id) do
    setup = HsmAgentSetup.new(%{ca_instance_id: ca_instance_id, tenant_id: tenant_id})
    Repo.insert(setup)
  end

  @doc "Load a draft by ID."
  @spec get_draft(binary()) :: {:ok, HsmAgentSetup.t()} | {:error, :not_found}
  def get_draft(setup_id) do
    case Repo.get(HsmAgentSetup, setup_id) do
      nil -> {:error, :not_found}
      setup -> {:ok, setup}
    end
  end

  @doc "Return the most recent pending draft for a CA instance, if any."
  @spec pending_for_ca(binary()) :: {:ok, HsmAgentSetup.t()} | {:error, :not_found}
  def pending_for_ca(ca_instance_id) do
    all = Repo.get_all_by_index(HsmAgentSetup, :ca_instance_id, ca_instance_id)

    result =
      all
      |> Enum.filter(&(&1.status in ["pending_agent", "agent_connected"]))
      |> Enum.sort_by(& &1.inserted_at, {:desc, DateTime})
      |> List.first()

    case result do
      nil -> {:error, :not_found}
      setup -> {:ok, setup}
    end
  end

  # ---------------------------------------------------------------------------
  # Step saves
  # ---------------------------------------------------------------------------

  @doc "Persist gateway port + cert material from the :gateway step."
  @spec save_gateway(binary(), integer(), String.t(), binary() | nil, binary() | nil, binary() | nil) ::
          {:ok, HsmAgentSetup.t()} | {:error, term()}
  def save_gateway(setup_id, port, cert_mode, server_cert_pem, server_key_pem, ca_cert_pem) do
    with {:ok, setup} <- get_draft(setup_id) do
      updated = %{
        setup
        | gateway_port: port,
          cert_mode: cert_mode,
          server_cert_pem: server_cert_pem,
          server_key_pem: server_key_pem,
          ca_cert_pem: ca_cert_pem,
          updated_at: now()
      }

      Repo.insert(updated)
    end
  end

  @doc "Persist agent ID and token hash from the :token step."
  @spec save_token(binary(), binary(), binary()) :: {:ok, HsmAgentSetup.t()} | {:error, term()}
  def save_token(setup_id, agent_id, token_plaintext) do
    with {:ok, setup} <- get_draft(setup_id) do
      token_hash = :crypto.hash(:sha256, token_plaintext) |> Base.encode16(case: :lower)

      updated = %{
        setup
        | agent_id: agent_id,
          auth_token_hash: token_hash,
          expected_agent_id: agent_id,
          updated_at: now()
      }

      Repo.insert(updated)
    end
  end

  @doc "Record that an agent has connected and its advertised key labels."
  @spec mark_agent_connected(binary(), [String.t()]) :: {:ok, HsmAgentSetup.t()} | {:error, term()}
  def mark_agent_connected(setup_id, key_labels) do
    with {:ok, setup} <- get_draft(setup_id) do
      updated = %{setup | key_labels: key_labels, status: "agent_connected", updated_at: now()}
      Repo.insert(updated)
    end
  end

  @doc """
  Complete the wizard: persist the chosen key label, wipe `server_key_pem`,
  and mark status `"complete"`.
  """
  @spec complete(binary(), binary()) :: {:ok, HsmAgentSetup.t()} | {:error, term()}
  def complete(setup_id, selected_key_label) do
    with {:ok, setup} <- get_draft(setup_id) do
      updated = %{
        setup
        | selected_key_label: selected_key_label,
          server_key_pem: nil,
          status: "complete",
          updated_at: now()
      }

      Repo.insert(updated)
    end
  end

  # ---------------------------------------------------------------------------
  # Cert generation
  # ---------------------------------------------------------------------------

  @doc """
  Generate a self-signed mTLS CA cert + server cert/key pair for the agent
  gateway. Returns `{:ok, %{server_cert_pem, server_key_pem, ca_cert_pem}}`.

  The CA cert is given to the agent operator so the agent can verify the
  server. The server cert/key is loaded by the Cowboy mTLS listener.
  """
  @spec generate_certs(binary()) ::
          {:ok, %{server_cert_pem: binary(), server_key_pem: binary(), ca_cert_pem: binary()}}
          | {:error, term()}
  def generate_certs(ca_instance_id) do
    algo = Registry.get("ECC-P256")

    with {:ok, %{public_key: ca_pub, private_key: ca_priv}} <- Algorithm.generate_keypair(algo),
         {:ok, ca_cert_der} <-
           X509Builder.self_sign(
             "ECC-P256",
             %{public_key: ca_pub, private_key: ca_priv},
             "CN=HSM Agent CA,O=PKI System,OU=#{ca_instance_id}",
             730
           ),
         {:ok, %{public_key: srv_pub, private_key: srv_priv}} <- Algorithm.generate_keypair(algo),
         {:ok, srv_cert_der} <-
           X509Builder.self_sign(
             "ECC-P256",
             %{public_key: srv_pub, private_key: srv_priv},
             "CN=HSM Gateway,O=PKI System,OU=#{ca_instance_id}",
             730
           ) do
      {:ok,
       %{
         ca_cert_pem: der_to_pem(ca_cert_der, "CERTIFICATE"),
         server_cert_pem: der_to_pem(srv_cert_der, "CERTIFICATE"),
         server_key_pem: priv_to_pem(srv_priv, algo)
       }}
    end
  end

  # ---------------------------------------------------------------------------
  # Token generation
  # ---------------------------------------------------------------------------

  @doc "Generate a secure random token (32 bytes, URL-safe base64)."
  @spec generate_token() :: binary()
  def generate_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  # ---------------------------------------------------------------------------
  # Agent config YAML
  # ---------------------------------------------------------------------------

  @doc """
  Build a ready-to-use agent-config.yaml snippet embedding the CA cert PEM
  and the configured agent_id / auth_token (plaintext — shown once).
  """
  @spec build_agent_config_yaml(HsmAgentSetup.t(), binary()) :: binary()
  def build_agent_config_yaml(%HsmAgentSetup{} = setup, token_plaintext) do
    ca_cert_inline =
      case setup.ca_cert_pem do
        nil -> ""
        pem -> indent(pem, "    ")
      end

    """
    agent_id: "#{setup.agent_id || "my-hsm-agent"}"
    auth_token: "#{token_plaintext}"

    backend:
      host: "localhost"
      port: #{setup.gateway_port || 8443}
      tls:
        ca_cert_pem: |
    #{ca_cert_inline}
    """
  end

  # ---------------------------------------------------------------------------
  # Token authentication path (called from AgentHandler)
  # ---------------------------------------------------------------------------

  @doc """
  Authenticate an agent using wizard-registered token. Returns `:ok` if
  `SHA-256(presented_token) == setup.auth_token_hash`, or `{:error, reason}`.
  """
  @spec authenticate_wizard_agent(binary(), binary(), binary()) :: :ok | {:error, atom()}
  def authenticate_wizard_agent(agent_id, tenant_id, presented_token) do
    all_for_tenant =
      Repo.where(HsmAgentSetup, fn s ->
        s.tenant_id == tenant_id and s.agent_id == agent_id and
          s.status in ["pending_agent", "agent_connected"]
      end)

    case all_for_tenant do
      [] ->
        {:error, :unknown_wizard_agent}

      [setup | _] ->
        presented_hash =
          :crypto.hash(:sha256, presented_token) |> Base.encode16(case: :lower)

        if constant_time_equal?(presented_hash, setup.auth_token_hash || "") do
          :ok
        else
          {:error, :invalid_token}
        end
    end
  end

  @doc """
  Find the wizard setup ID for a given agent_id + tenant_id combination.
  Used by AgentHandler to call `mark_agent_connected/2` after registration.
  """
  @spec find_setup_id(binary(), binary()) :: {:ok, binary()} | {:error, :not_found}
  def find_setup_id(agent_id, tenant_id) do
    result =
      Repo.where(HsmAgentSetup, fn s ->
        s.agent_id == agent_id and s.tenant_id == tenant_id and
          s.status == "pending_agent"
      end)
      |> List.first()

    case result do
      nil -> {:error, :not_found}
      setup -> {:ok, setup.id}
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp der_to_pem(der, type) do
    pem_entry = {String.to_atom(type), der, :not_encrypted}
    :public_key.pem_encode([pem_entry])
  end

  defp priv_to_pem(priv_key, algo) when is_map(algo) do
    # ECC private key — encode as ECPrivateKey
    try do
      der = :public_key.der_encode(:ECPrivateKey, priv_key)
      der_to_pem(der, "EC PRIVATE KEY")
    rescue
      _ ->
        # Fallback for binary key material (PQC)
        Base.encode64(priv_key)
    end
  end

  defp indent(text, prefix) do
    text
    |> String.split("\n")
    |> Enum.map_join("\n", fn line -> if line == "", do: line, else: prefix <> line end)
  end

  defp constant_time_equal?(a, b) when is_binary(a) and is_binary(b) do
    byte_size(a) == byte_size(b) and :crypto.hash_equals(a, b)
  end

  defp constant_time_equal?(_, _), do: false
end
