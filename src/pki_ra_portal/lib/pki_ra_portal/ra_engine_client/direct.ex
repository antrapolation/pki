defmodule PkiRaPortal.RaEngineClient.Direct do
  @moduledoc """
  Direct (in-process) implementation of the RA engine client.

  Calls RA engine modules directly via Elixir function calls instead of HTTP.
  Converts Ecto structs returned by engine modules into plain maps with atom keys
  to match the contract expected by the portal.
  """

  @behaviour PkiRaPortal.RaEngineClient

  require Logger

  # --- Auth endpoints ---

  @impl true
  def authenticate(username, password) do
    case PkiRaEngine.UserManagement.authenticate(nil, username, password) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def authenticate_with_session(username, password) do
    case PkiRaEngine.UserManagement.authenticate_with_credentials(nil, username, password) do
      {:ok, user, session_info} -> {:ok, to_map(user), to_map(session_info)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def register_user(attrs) do
    case PkiRaEngine.UserManagement.register_user(nil, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def needs_setup? do
    PkiRaEngine.UserManagement.needs_setup?(nil)
  end

  @impl true
  def needs_setup?(tenant_id) do
    PkiRaEngine.UserManagement.needs_setup?(tenant_id)
  end

  @impl true
  def get_user_by_username(username, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.get_user_by_username(tenant_id, username) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def reset_password(user_id, new_password, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.update_user_password(tenant_id, user_id, %{password: new_password}) do
      :ok -> :ok
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  # --- User management ---

  @impl true
  def list_users(opts \\ []) do
    tenant_id = opts[:tenant_id]
    filters = Keyword.drop(opts, [:tenant_id])

    case PkiRaEngine.UserManagement.list_users(tenant_id, filters) do
      {:ok, users} -> {:ok, Enum.map(users, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def create_user(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.create_user(tenant_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def create_user(attrs, admin_context, opts) do
    tenant_id = opts[:tenant_id]

    merged_attrs =
      attrs
      |> Map.put(:admin_user_id, admin_context[:user_id] || admin_context["user_id"])
      |> Map.put(:admin_password, admin_context[:password] || admin_context["password"])

    case PkiRaEngine.UserManagement.create_user(tenant_id, merged_attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_user(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.delete_user(tenant_id, id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  # --- CSR management ---

  @impl true
  def list_csrs(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CsrValidation.list_csrs(tenant_id, filters) do
      {:ok, csrs} -> {:ok, Enum.map(csrs, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def get_csr(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CsrValidation.get_csr(tenant_id, id) do
      {:ok, csr} -> {:ok, to_map(csr)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def approve_csr(id, meta, opts \\ []) do
    tenant_id = opts[:tenant_id]
    reviewer_user_id = meta[:reviewer_user_id] || meta["reviewer_user_id"]

    case PkiRaEngine.CsrValidation.approve_csr(tenant_id, id, reviewer_user_id) do
      {:ok, csr} -> {:ok, to_map(csr)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def reject_csr(id, reason, meta, opts \\ []) do
    tenant_id = opts[:tenant_id]
    reviewer_user_id = meta[:reviewer_user_id] || meta["reviewer_user_id"]

    case PkiRaEngine.CsrValidation.reject_csr(tenant_id, id, reviewer_user_id, reason) do
      {:ok, csr} -> {:ok, to_map(csr)}
      {:error, _} = err -> err
    end
  end

  # --- Cert profiles ---

  @impl true
  def list_cert_profiles(opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.list_profiles(tenant_id) do
      {:ok, profiles} -> {:ok, Enum.map(profiles, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def create_cert_profile(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.create_profile(tenant_id, attrs) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def update_cert_profile(id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.update_profile(tenant_id, id, attrs) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_cert_profile(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.delete_profile(tenant_id, id) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  # --- Service configs ---

  @impl true
  def list_service_configs(opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ServiceConfig.list_service_configs(tenant_id) do
      {:ok, configs} -> {:ok, Enum.map(configs, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def configure_service(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ServiceConfig.configure_service(tenant_id, attrs) do
      {:ok, config} -> {:ok, to_map(config)}
      {:error, _} = err -> err
    end
  end

  # --- RA instances ---

  @impl true
  def list_ra_instances(opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id) do
      {:ok, instances} -> {:ok, Enum.map(instances, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def create_ra_instance(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.RaInstanceManagement.create_ra_instance(tenant_id, attrs) do
      {:ok, instance} -> {:ok, to_map(instance)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def available_issuer_keys(opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiCaEngine.CaInstanceManagement.active_leaf_issuer_keys(tenant_id) do
      {:ok, keys} -> {:ok, Enum.map(keys, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  # --- API keys ---

  @impl true
  def list_api_keys(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    ra_user_id = filters[:ra_user_id] || filters["ra_user_id"]

    case PkiRaEngine.ApiKeyManagement.list_keys(tenant_id, ra_user_id) do
      {:ok, keys} -> {:ok, Enum.map(keys, &to_map/1)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def create_api_key(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ApiKeyManagement.create_api_key(tenant_id, attrs) do
      {:ok, key} -> {:ok, to_map(key)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def revoke_api_key(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ApiKeyManagement.revoke_key(tenant_id, id) do
      {:ok, key} -> {:ok, to_map(key)}
      {:error, _} = err -> err
    end
  end

  # --- Struct to map conversion helpers ---

  defp to_map(%{__struct__: _} = struct) do
    struct
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> Map.new(fn {k, v} -> {k, to_map_value(v)} end)
  end

  defp to_map(other), do: other

  defp to_map_value(%{__struct__: Ecto.Association.NotLoaded}), do: nil
  defp to_map_value(%{__struct__: _} = s), do: to_map(s)
  defp to_map_value(list) when is_list(list), do: Enum.map(list, &to_map_value/1)
  defp to_map_value(other), do: other
end
