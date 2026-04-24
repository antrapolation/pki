defmodule PkiTenantWeb.Ca.IssuerKeysLive do
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.{CaInstanceManagement, IssuerKeyManagement, CertificateSigning, KeyActivation, CeremonyOrchestrator}
  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{ThresholdShare, KeyCeremony}
  import PkiTenantWeb.ErrorHelpers, only: [sanitize_error: 2]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Issuer Keys",
       ca_instances: [],
       issuer_keys: [],
       effective_ca_id: nil,
       selected_ca_id: "",
       loading: true,
       # Modal state
       modal: nil,
       modal_key: nil,
       modal_shares: [],
       modal_passwords: [],
       modal_custodians: [],
       modal_private_key: nil,
       modal_csr_pem: "",
       modal_cert_pem: "",
       modal_cert_profile: %{validity_days: 3650, is_ca: true},
       modal_result: nil,
       modal_error: nil,
       modal_busy: false
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    if connected?(socket), do: send(self(), {:load_data, params["ca"]})
    {:noreply, socket}
  end

  @impl true
  def handle_info({:load_data, url_ca_id}, socket) do
    try do
      user_ca_id = socket.assigns.current_user[:ca_instance_id]

      ca_instances =
        case CaInstanceManagement.list_ca_instances() do
          {:ok, instances} -> instances
          _ -> []
        end

      effective_ca_id =
        cond do
          url_ca_id && url_ca_id != "" -> url_ca_id
          user_ca_id -> user_ca_id
          true ->
            case ca_instances do
              [first | _] -> first.id
              [] -> nil
            end
        end

      issuer_keys = load_keys(effective_ca_id)

      {:noreply,
       assign(socket,
         ca_instances: ca_instances,
         issuer_keys: issuer_keys,
         effective_ca_id: effective_ca_id,
         selected_ca_id: effective_ca_id || "",
         loading: false
       )}
    rescue
      e ->
        Logger.warning("[IssuerKeysLive] Failed to load data: #{Exception.message(e)}")
        {:noreply, assign(socket, loading: false)}
    end
  end

  # ---------------------------------------------------------------------------
  # Events
  # ---------------------------------------------------------------------------

  @impl true
  def handle_event("select_ca_instance", %{"ca_instance_id" => id}, socket) do
    path = if id == "", do: "/issuer-keys", else: "/issuer-keys?ca=#{id}"
    {:noreply, push_patch(socket, to: path)}
  end

  # --- Open modals ---

  def handle_event("view_csr", %{"id" => key_id}, socket) do
    # Find CSR from the ceremony associated with this issuer key
    csr_pem = case Repo.get_all_by_index(KeyCeremony, :issuer_key_id, key_id) do
      {:ok, [ceremony | _]} ->
        get_in(ceremony.domain_info || %{}, ["csr_pem"])
      _ -> nil
    end

    if csr_pem do
      {:noreply, assign(socket, modal: :view_csr, modal_csr_pem: csr_pem, modal_error: nil)}
    else
      {:noreply, put_flash(socket, :error, "No CSR found for this key.")}
    end
  end

  def handle_event("open_sign_csr", %{"id" => key_id}, socket) do
    with {:ok, key} when not is_nil(key) <- IssuerKeyManagement.get_issuer_key(key_id),
         {:ok, shares} <- Repo.get_all_by_index(ThresholdShare, :issuer_key_id, key_id) do
      tc = key.threshold_config || %{}
      k = tc["k"] || tc[:k] || 2
      custodian_names = shares |> Enum.map(& &1.custodian_name) |> Enum.uniq()

      {:noreply,
       assign(socket,
         modal: :sign_csr,
         modal_key: key,
         modal_shares: shares,
         modal_custodians: custodian_names,
         modal_passwords: List.duplicate("", k),
         modal_private_key: nil,
         modal_csr_pem: "",
         modal_cert_pem: "",
         modal_cert_profile: %{validity_days: 3650, is_ca: true},
         modal_result: nil,
         modal_error: nil,
         modal_busy: false
       )}
    else
      {:error, reason} ->
        Logger.error("[issuer_keys] Failed to load key for sign_csr: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to load key", reason))}
      _ ->
        {:noreply, put_flash(socket, :error, "Key not found.")}
    end
  end

  def handle_event("open_unlock", %{"id" => key_id}, socket) do
    with {:ok, key} when not is_nil(key) <- IssuerKeyManagement.get_issuer_key(key_id),
         {:ok, shares} <- Repo.get_all_by_index(ThresholdShare, :issuer_key_id, key_id) do
      tc = key.threshold_config || %{}
      k = tc["k"] || tc[:k] || 2
      custodian_names = shares |> Enum.map(& &1.custodian_name) |> Enum.uniq()

      {:noreply,
       assign(socket,
         modal: :unlock,
         modal_key: key,
         modal_shares: shares,
         modal_custodians: custodian_names,
         modal_passwords: List.duplicate("", k),
         modal_result: nil,
         modal_error: nil,
         modal_busy: false
       )}
    else
      {:error, reason} ->
        Logger.error("[issuer_keys] Failed to load key for unlock: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to load key", reason))}
      _ ->
        {:noreply, put_flash(socket, :error, "Key not found.")}
    end
  end

  def handle_event("unlock_key", _params, %{assigns: %{modal_busy: true}} = socket),
    do: {:noreply, socket}

  def handle_event("unlock_key", params, socket) do
    unless socket.assigns.current_user[:role] in ["ca_admin", "key_manager"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      key = socket.assigns.modal_key
      k = threshold_k(key)
      custodian_names = socket.assigns.modal_custodians |> Enum.take(k)

      passwords =
        Enum.with_index(custodian_names)
        |> Enum.map(fn {_name, idx} -> params["password_#{idx}"] || "" end)

      cond do
        Enum.any?(passwords, &(String.trim(&1) == "")) ->
          {:noreply, assign(socket, modal_error: "All custodian passwords are required.")}

        true ->
          socket = assign(socket, modal_busy: true, modal_error: nil)

          # Submit shares one by one for key activation
          results = Enum.zip(custodian_names, passwords)
          |> Enum.map(fn {name, password} ->
            KeyActivation.submit_share(key.id, name, password)
          end)

          errors = Enum.filter(results, fn
            {:error, _} -> true
            _ -> false
          end)

          if Enum.empty?(errors) do
            PkiTenant.AuditBridge.log("issuer_key_unlocked", %{
              issuer_key_id: key.id,
              key_alias: key.key_alias
            })

            {:noreply,
             socket
             |> reset_modal()
             |> put_flash(:info, "Key unlocked. Available for signing for the next hour.")}
          else
            {:noreply,
             assign(socket,
               modal_busy: false,
               modal_error: "Unlock failed: #{format_error(elem(hd(errors), 1))}"
             )}
          end
      end
    end
  end

  def handle_event("open_activate", %{"id" => key_id}, socket) do
    case IssuerKeyManagement.get_issuer_key(key_id) do
      {:ok, key} when not is_nil(key) ->
        {:noreply,
         assign(socket,
           modal: :activate,
           modal_key: key,
           modal_cert_pem: "",
           modal_result: nil,
           modal_error: nil,
           modal_busy: false
         )}

      {:error, reason} ->
        Logger.error("[issuer_keys] Failed to load key for activate: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to load key", reason))}

      _ ->
        {:noreply, put_flash(socket, :error, "Key not found.")}
    end
  end

  def handle_event("close_modal", _params, socket) do
    {:noreply, reset_modal(socket)}
  end

  defp reset_modal(socket) do
    assign(socket,
      modal: nil,
      modal_key: nil,
      modal_shares: [],
      modal_passwords: [],
      modal_custodians: [],
      modal_private_key: nil,
      modal_csr_pem: "",
      modal_cert_pem: "",
      modal_cert_profile: %{validity_days: 3650, is_ca: true},
      modal_result: nil,
      modal_error: nil,
      modal_busy: false
    )
  end

  # --- Sign CSR flow ---

  def handle_event("reconstruct_and_sign", _params, %{assigns: %{modal_busy: true}} = socket),
    do: {:noreply, socket}

  def handle_event("reconstruct_and_sign", params, socket) do
    unless socket.assigns.current_user[:role] in ["ca_admin", "key_manager"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      handle_reconstruct_and_sign(params, socket)
    end
  end

  defp handle_reconstruct_and_sign(params, socket) do
    key = socket.assigns.modal_key
    shares = socket.assigns.modal_shares

    k = threshold_k(key)
    custodian_names = shares |> Enum.map(& &1.custodian_name) |> Enum.uniq() |> Enum.take(k)

    # Collect passwords from form
    passwords =
      Enum.with_index(custodian_names)
      |> Enum.map(fn {_name, idx} -> params["password_#{idx}"] || "" end)

    csr_pem = params["csr_pem"] || ""
    validity_days = parse_int(params["validity_days"]) || 3650
    is_ca = params["is_ca"] == "true"

    cond do
      String.trim(csr_pem) == "" ->
        {:noreply, assign(socket, modal_error: "Please paste the CSR PEM.")}

      Enum.any?(passwords, &(String.trim(&1) == "")) ->
        {:noreply, assign(socket, modal_error: "All custodian passwords are required.")}

      true ->
        socket = assign(socket, modal_busy: true, modal_error: nil)

        # First submit shares to activate the key
        _submit_results = Enum.zip(custodian_names, passwords)
        |> Enum.map(fn {name, password} ->
          KeyActivation.submit_share(key.id, name, password)
        end)

        # Sign the CSR
        issuer_name = extract_subject_from_cert_pem(key.certificate_pem) || "/CN=Root-CA"

        cert_profile = %{
          validity_days: validity_days,
          is_ca: is_ca,
          issuer_name: issuer_name
        }

        case CertificateSigning.sign_certificate(key.id, csr_pem, cert_profile) do
          {:ok, result} ->
            PkiTenant.AuditBridge.log("csr_signed", %{
              issuer_key_id: key.id,
              key_alias: key.key_alias,
              algorithm: key.algorithm,
              serial: result.serial_number
            })
            {:noreply,
             assign(socket,
               modal_result: result,
               modal_private_key: nil,
               modal_busy: false,
               modal_error: nil
             )}

          {:error, reason} ->
            {:noreply,
             assign(socket,
               modal_private_key: nil,
               modal_busy: false,
               modal_error: "Signing failed: #{format_error(reason)}"
             )}
        end
    end
  end

  # --- Activate key ---

  def handle_event("activate_key", _params, %{assigns: %{modal_busy: true}} = socket),
    do: {:noreply, socket}

  def handle_event("activate_key", params, socket) do
    key = socket.assigns.modal_key
    cert_pem = params["cert_pem"] || ""

    if String.trim(cert_pem) == "" do
      {:noreply, assign(socket, modal_error: "Please paste the certificate PEM.")}
    else
      socket = assign(socket, modal_busy: true, modal_error: nil)

      # Verify single certificate (not a chain)
      begin_count = cert_pem |> String.split("-----BEGIN ") |> length() |> Kernel.-(1)

      cond do
        begin_count > 1 ->
          {:noreply, assign(socket, modal_busy: false, modal_error: "Please paste a single certificate, not a chain.")}

        begin_count == 0 ->
          {:noreply, assign(socket, modal_busy: false, modal_error: "No PEM certificate found.")}

        true ->
          # Delegate to CeremonyOrchestrator for validated external-cert activation.
          # This verifies: cert not expired, public key matches the pending key,
          # and the cert's algorithm family is consistent with key.algorithm.
          case CeremonyOrchestrator.activate_with_external_cert(key.id, cert_pem) do
            {:ok, _updated} ->
              PkiTenant.AuditBridge.log("key_activated_with_external_cert", %{
                issuer_key_id: key.id,
                key_alias: key.key_alias
              })
              keys = load_keys(socket.assigns.effective_ca_id)
              {:noreply,
               socket
               |> reset_modal()
               |> assign(issuer_keys: keys)
               |> put_flash(:info, "Issuer key activated successfully.")}

            {:error, reason} ->
              {:noreply, assign(socket, modal_busy: false, modal_error: "Activation failed: #{format_error(reason)}")}
          end
      end
    end
  end

  # --- Lifecycle transitions ---

  def handle_event("suspend_key", %{"id" => id}, socket) do
    case IssuerKeyManagement.transition_status(id, "suspended") do
      {:ok, _key} ->
        PkiTenant.AuditBridge.log("issuer_key_suspended", %{issuer_key_id: id})
        keys = load_keys(socket.assigns.effective_ca_id)

        {:noreply,
         socket
         |> put_flash(:info, "Key suspended successfully.")
         |> assign(issuer_keys: keys)}

      {:error, reason} ->
        Logger.error("[issuer_keys] Failed to suspend key #{id}: #{inspect(reason)}")

        {:noreply,
         put_flash(socket, :error, sanitize_error("Failed to suspend key", reason))}
    end
  end

  def handle_event("reactivate_key", %{"id" => id}, socket) do
    case IssuerKeyManagement.transition_status(id, "active") do
      {:ok, _key} ->
        PkiTenant.AuditBridge.log("issuer_key_reactivated", %{issuer_key_id: id})
        keys = load_keys(socket.assigns.effective_ca_id)

        {:noreply,
         socket
         |> put_flash(:info, "Key reactivated successfully.")
         |> assign(issuer_keys: keys)}

      {:error, reason} ->
        Logger.error("[issuer_keys] Failed to reactivate key #{id}: #{inspect(reason)}")

        {:noreply,
         put_flash(socket, :error, sanitize_error("Failed to reactivate key", reason))}
    end
  end

  def handle_event("retire_key", %{"id" => id}, socket) do
    unless socket.assigns.current_user[:role] in ["ca_admin", "key_manager"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      case IssuerKeyManagement.transition_status(id, "retired") do
        {:ok, _key} ->
          PkiTenant.AuditBridge.log("issuer_key_retired", %{issuer_key_id: id})
          keys = load_keys(socket.assigns.effective_ca_id)

          {:noreply,
           socket
           |> put_flash(:info, "Key retired. It can no longer sign certificates but existing certificates remain valid.")
           |> assign(issuer_keys: keys)}

        {:error, reason} ->
          Logger.error("[issuer_keys] Failed to retire key #{id}: #{inspect(reason)}")

          {:noreply,
           put_flash(socket, :error, sanitize_error("Failed to retire key", reason))}
      end
    end
  end

  def handle_event("archive_key", %{"id" => id}, socket) do
    unless socket.assigns.current_user[:role] in ["ca_admin"] do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      case IssuerKeyManagement.transition_status(id, "archived") do
        {:ok, _key} ->
          PkiTenant.AuditBridge.log("issuer_key_archived", %{issuer_key_id: id})
          keys = load_keys(socket.assigns.effective_ca_id)

          {:noreply,
           socket
           |> put_flash(:info, "Key archived successfully.")
           |> assign(issuer_keys: keys)}

        {:error, reason} ->
          Logger.error("[issuer_keys] Failed to archive key #{id}: #{inspect(reason)}")

          {:noreply,
           put_flash(socket, :error, sanitize_error("Failed to archive key", reason))}
      end
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp load_keys(nil), do: []
  defp load_keys(ca_id) do
    case IssuerKeyManagement.list_issuer_keys(ca_id) do
      {:ok, keys} -> keys
      _ -> []
    end
  rescue
    _ -> []
  end

  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp format_error({:validation_error, errors}) when is_map(errors) do
    errors |> Enum.map(fn {k, v} -> "#{k}: #{inspect(v)}" end) |> Enum.join(", ")
  end
  defp format_error({:decryption_failed, user_id}), do: "Wrong password for custodian #{String.slice(to_string(user_id), 0..7)}"
  defp format_error({:share_not_found, user_id}), do: "Share not found for custodian #{String.slice(to_string(user_id), 0..7)}"
  defp format_error(:invalid_csr), do: "Invalid CSR — signature verification failed"
  defp format_error(:invalid_csr_pem), do: "Invalid CSR PEM format"
  defp format_error({:invalid_status, status}), do: "Key status is '#{status}' — must be 'pending' to activate"
  defp format_error(:key_not_pending), do: "Key is not in pending status — cannot activate"
  defp format_error(:malformed_cert), do: "Certificate could not be parsed — ensure it is a valid PEM or DER certificate"
  defp format_error(:cert_expired), do: "Certificate has expired — upload a valid, unexpired certificate"
  defp format_error(:public_key_mismatch), do: "Certificate public key does not match this issuer key"
  defp format_error(:algo_mismatch), do: "Certificate algorithm does not match the issuer key algorithm"
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(reason) do
    Logger.error("[issuer_keys] Unhandled error reason: #{inspect(reason)}")
    "an unexpected error occurred"
  end

  defp extract_subject_from_cert_pem(nil), do: nil
  defp extract_subject_from_cert_pem(pem) when is_binary(pem) do
    case X509.Certificate.from_pem(pem) do
      {:ok, cert} -> X509.RDNSequence.to_string(X509.Certificate.subject(cert))
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp threshold_k(key) do
    tc = key.threshold_config || %{}
    tc["k"] || tc[:k] || 2
  end

  defp can_sign_csr?(key) do
    key.status == "active" && key.certificate_pem && kaz_or_classical?(key.algorithm)
  end

  defp kaz_or_classical?(nil), do: false
  defp kaz_or_classical?(algo) do
    a = String.downcase(algo)
    a in ["ecc-p256", "ecc-p384", "rsa-2048", "rsa-4096"] or String.starts_with?(a, "kaz-sign")
  end

  defp status_class("active"), do: "badge-success"
  defp status_class("pending"), do: "badge-warning"
  defp status_class("suspended"), do: "badge-error"
  defp status_class("retired"), do: "badge-ghost"
  defp status_class("archived"), do: "badge-ghost"
  defp status_class(_), do: "badge-ghost"

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <%!-- CA Instance selector --%>
      <div class="flex items-center gap-3">
        <label class="text-xs font-medium text-base-content/60">CA Instance</label>
        <form phx-change="select_ca_instance">
          <select name="ca_instance_id" class="select select-bordered select-sm">
            <option value="">Select CA Instance</option>
            <option :for={inst <- @ca_instances} value={inst.id} selected={@selected_ca_id == inst.id}>
              {inst.name}
            </option>
          </select>
        </form>
      </div>

      <%!-- Keys table --%>
      <div :if={@effective_ca_id} class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Issuer Keys</h2>
          </div>
          <div :if={Enum.empty?(@issuer_keys)} class="p-8 text-center text-base-content/50 text-sm">
            No issuer keys for this CA instance. Run a key ceremony to create one.
          </div>
          <div :if={not Enum.empty?(@issuer_keys)}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[22%]">Alias</th>
                  <th class="w-[15%]">Algorithm</th>
                  <th class="w-[8%]">Root?</th>
                  <th class="w-[10%]">Status</th>
                  <th class="w-[12%]">Certificate</th>
                  <th class="w-[33%]">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={k <- @issuer_keys} class="hover">
                  <td class="font-mono text-sm overflow-hidden text-ellipsis whitespace-nowrap">{k.key_alias}</td>
                  <td class="font-mono text-sm overflow-hidden text-ellipsis whitespace-nowrap">{k.algorithm}</td>
                  <td class="text-sm">{if k.is_root, do: "Yes", else: "No"}</td>
                  <td><span class={"badge badge-sm #{status_class(k.status)}"}>{k.status}</span></td>
                  <td class="text-xs text-base-content/60">
                    {if k.certificate_pem, do: "Installed", else: "—"}
                  </td>
                  <td class="flex items-center gap-1">
                    <%!-- Sign CSR: only for active keys with a certificate and supported algorithm --%>
                    <button
                      :if={can_sign_csr?(k)}
                      phx-click="open_sign_csr"
                      phx-value-id={k.id}
                      title="Sign CSR"
                      class="btn btn-ghost btn-xs text-blue-400"
                    >
                      <.icon name="hero-pencil-square" class="size-4" />
                    </button>
                    <%!-- Unlock: active keys, makes key available to RA-driven signing for 1h --%>
                    <button
                      :if={k.status == "active" and k.certificate_pem}
                      phx-click="open_unlock"
                      phx-value-id={k.id}
                      title="Unlock for RA Signing (1h)"
                      class="btn btn-ghost btn-xs text-cyan-400"
                    >
                      <.icon name="hero-lock-open" class="size-4" />
                    </button>
                    <%!-- View CSR: for pending sub-CA keys --%>
                    <button
                      :if={k.status == "pending" and not k.is_root}
                      phx-click="view_csr"
                      phx-value-id={k.id}
                      title="View CSR"
                      class="btn btn-ghost btn-xs text-violet-400"
                    >
                      <.icon name="hero-document-text" class="size-4" />
                    </button>
                    <%!-- Activate: only for pending keys --%>
                    <button
                      :if={k.status == "pending"}
                      phx-click="open_activate"
                      phx-value-id={k.id}
                      title="Upload Certificate"
                      class="btn btn-ghost btn-xs text-emerald-400"
                    >
                      <.icon name="hero-arrow-up-tray" class="size-4" />
                    </button>
                    <%!-- Suspend: only for active keys --%>
                    <button
                      :if={k.status == "active"}
                      phx-click="suspend_key"
                      phx-value-id={k.id}
                      data-confirm="Are you sure you want to suspend this key? It will not be usable until reactivated."
                      title="Suspend"
                      class="btn btn-ghost btn-xs text-amber-400"
                    >
                      <.icon name="hero-pause" class="size-4" />
                    </button>
                    <%!-- Reactivate: only for suspended keys --%>
                    <button
                      :if={k.status == "suspended"}
                      phx-click="reactivate_key"
                      phx-value-id={k.id}
                      data-confirm="Reactivate this key?"
                      title="Reactivate"
                      class="btn btn-ghost btn-xs text-emerald-400"
                    >
                      <.icon name="hero-play" class="size-4" />
                    </button>
                    <%!-- Retire: for active or suspended keys (can verify, cannot sign) --%>
                    <button
                      :if={k.status in ["active", "suspended"]}
                      phx-click="retire_key"
                      phx-value-id={k.id}
                      data-confirm="Retire this key? It will no longer sign certificates but existing certificates remain valid."
                      title="Retire"
                      class="btn btn-ghost btn-xs text-orange-400"
                    >
                      <.icon name="hero-archive-box-arrow-down" class="size-4" />
                    </button>
                    <%!-- Archive: for non-archived keys (terminal action) --%>
                    <button
                      :if={k.status in ["pending", "active", "suspended", "retired"]}
                      phx-click="archive_key"
                      phx-value-id={k.id}
                      data-confirm="Are you sure you want to archive this key? This action cannot be undone."
                      title="Archive"
                      class="btn btn-ghost btn-xs text-rose-400"
                    >
                      <.icon name="hero-archive-box" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <%!-- View CSR Modal --%>
      <%= if @modal == :view_csr do %>
        <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div class="bg-base-100 rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
            <div class="p-6">
              <div class="flex items-center justify-between mb-4">
                <h3 class="text-sm font-semibold text-base-content">Certificate Signing Request (CSR)</h3>
                <button phx-click="close_modal" class="btn btn-ghost btn-sm btn-circle">
                  <.icon name="hero-x-mark" class="size-4" />
                </button>
              </div>
              <p class="text-xs text-base-content/60 mb-3">
                Copy this CSR and paste it into the Root CA's "Sign CSR" dialog to issue a certificate for this Sub-CA.
              </p>
              <div class="relative">
                <pre id="csr-pem-content" class="bg-base-200 rounded-lg p-4 text-xs font-mono whitespace-pre-wrap break-all select-all overflow-x-auto">{@modal_csr_pem}</pre>
                <button
                  type="button"
                  onclick="navigator.clipboard.writeText(document.getElementById('csr-pem-content').textContent).then(() => this.textContent = 'Copied!')"
                  class="btn btn-sm btn-primary absolute top-2 right-2"
                >
                  <.icon name="hero-clipboard-document" class="size-4" /> Copy
                </button>
              </div>
              <div class="mt-4 flex justify-end">
                <button phx-click="close_modal" class="btn btn-ghost btn-sm">Close</button>
              </div>
            </div>
          </div>
        </div>
      <% end %>

      <%!-- Sign CSR Modal --%>
      <%= if @modal == :sign_csr do %>
        {render_sign_csr_modal(assigns)}
      <% end %>

      <%!-- Activate Modal --%>
      <%= if @modal == :activate do %>
        {render_activate_modal(assigns)}
      <% end %>

      <%!-- Unlock Modal --%>
      <%= if @modal == :unlock do %>
        {render_unlock_modal(assigns)}
      <% end %>
    </div>
    """
  end

  defp render_unlock_modal(assigns) do
    assigns = assign(assigns, :k, threshold_k(assigns.modal_key))

    ~H"""
    <div class="modal modal-open">
      <div class="modal-box max-w-2xl">
        <h3 class="font-bold text-lg mb-2">Unlock Key for RA Signing</h3>
        <p class="text-sm text-base-content/60 mb-4">
          Reconstruct <span class="font-mono">{@modal_key.key_alias}</span> from {@k} of {length(@modal_shares)} threshold shares.
          The key stays in memory for 1 hour, allowing the RA engine to issue certificates.
        </p>

        <div :if={@modal_error} class="alert alert-error text-sm mb-3">{@modal_error}</div>

        <form phx-submit="unlock_key" class="space-y-3">
          <div :for={{name, idx} <- Enum.with_index(Enum.take(@modal_custodians, @k))}>
            <label class="label text-xs font-medium">
              Custodian #{idx + 1} — <span class="font-mono">{name}</span>
            </label>
            <input
              type="password"
              name={"password_#{idx}"}
              required
              autocomplete="off"
              class="input input-bordered w-full"
              placeholder="Custodian password"
            />
          </div>

          <div class="modal-action">
            <button type="button" phx-click="close_modal" class="btn btn-ghost btn-sm">Cancel</button>
            <button type="submit" disabled={@modal_busy} class="btn btn-primary btn-sm">
              {if @modal_busy, do: "Unlocking…", else: "Unlock"}
            </button>
          </div>
        </form>
      </div>
    </div>
    """
  end

  defp custodian_label(shares, name) do
    case Enum.find(shares, fn s -> s.custodian_name == name end) do
      nil -> name
      _s -> name
    end
  end

  defp render_sign_csr_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div class="card bg-base-100 shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div class="card-body">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-sm font-semibold">
              <.icon name="hero-pencil-square" class="size-4 inline" /> Sign CSR with {@modal_key.key_alias}
            </h2>
            <button phx-click="close_modal" class="btn btn-ghost btn-sm btn-square">
              <.icon name="hero-x-mark" class="size-4" />
            </button>
          </div>

          <%!-- Error --%>
          <div :if={@modal_error} class="alert alert-error mb-4 text-sm">
            <.icon name="hero-exclamation-circle" class="size-4" />
            <span>{@modal_error}</span>
          </div>

          <%!-- Result: show signed certificate --%>
          <%= if @modal_result do %>
            <div class="bg-success/5 border border-success/20 rounded-lg p-4 mb-4">
              <div class="flex items-center gap-2 mb-2">
                <.icon name="hero-check-circle" class="size-5 text-success" />
                <span class="text-sm font-medium">Certificate Signed Successfully</span>
              </div>
              <div class="text-xs text-base-content/60 mb-2">
                Serial: <span class="font-mono">{@modal_result.serial_number}</span>
              </div>
            </div>
            <div class="mb-4">
              <label class="block text-xs font-medium text-base-content/60 mb-1">Signed Certificate (PEM)</label>
              <textarea class="textarea textarea-bordered w-full font-mono text-xs h-48" readonly>{@modal_result.cert_pem}</textarea>
              <p class="text-xs text-base-content/40 mt-1">Copy this certificate and upload it to the Sub-CA issuer key to activate it.</p>
            </div>
            <button phx-click="close_modal" class="btn btn-primary btn-sm">Done</button>
          <% else %>
            <%!-- Sign CSR form --%>
            <form phx-submit="reconstruct_and_sign" class="space-y-4">
              <%!-- Key info --%>
              <div class="bg-base-200/50 rounded-lg p-3 text-sm space-y-1">
                <div class="flex gap-2">
                  <span class="text-base-content/50 w-24">Key:</span>
                  <span class="font-mono">{@modal_key.key_alias}</span>
                </div>
                <div class="flex gap-2">
                  <span class="text-base-content/50 w-24">Algorithm:</span>
                  <span class="font-mono">{@modal_key.algorithm}</span>
                </div>
              </div>

              <%!-- CSR PEM input --%>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">CSR (PEM)</label>
                <textarea name="csr_pem" class="textarea textarea-bordered w-full font-mono text-xs h-32" placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"></textarea>
              </div>

              <%!-- Certificate profile --%>
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label class="block text-xs font-medium text-base-content/60 mb-1">Validity (days)</label>
                  <input type="number" name="validity_days" value="3650" class="input input-bordered input-sm w-full" />
                </div>
                <div>
                  <label class="block text-xs font-medium text-base-content/60 mb-1">Certificate Type</label>
                  <select name="is_ca" class="select select-bordered select-sm w-full">
                    <option value="true">CA Certificate</option>
                    <option value="false">End-Entity</option>
                  </select>
                </div>
              </div>

              <%!-- Custodian passwords for key reconstruction --%>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-2">
                  Key Custodian Passwords
                  <span class="text-base-content/40">(need {threshold_k(@modal_key)} of {length(@modal_shares)} shares)</span>
                </label>
                <% k = threshold_k(@modal_key) %>
                <% custodian_names = @modal_shares |> Enum.map(& &1.custodian_name) |> Enum.uniq() |> Enum.take(k) %>
                <div :for={{name, idx} <- Enum.with_index(custodian_names)} class="flex items-center gap-3 mb-2">
                  <span class="text-xs text-base-content/50 w-24 font-mono shrink-0">{name}</span>
                  <input
                    type="password"
                    name={"password_#{idx}"}
                    placeholder="Custodian's secret password"
                    maxlength="100"
                    class="input input-bordered input-sm flex-1"
                    autocomplete="off"
                  />
                </div>
              </div>

              <div class="flex justify-end gap-2 pt-2">
                <button phx-click="close_modal" type="button" class="btn btn-ghost btn-sm">Cancel</button>
                <button type="submit" class="btn btn-primary btn-sm" disabled={@modal_busy}>
                  <%= if @modal_busy do %>
                    <span class="loading loading-spinner loading-xs"></span> Signing...
                  <% else %>
                    <.icon name="hero-pencil-square" class="size-4" /> Reconstruct Key & Sign
                  <% end %>
                </button>
              </div>
            </form>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp render_activate_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div class="card bg-base-100 shadow-xl w-full max-w-lg">
        <div class="card-body">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-sm font-semibold">
              <.icon name="hero-arrow-up-tray" class="size-4 inline" /> Upload Certificate for {@modal_key.key_alias}
            </h2>
            <button phx-click="close_modal" class="btn btn-ghost btn-sm btn-square">
              <.icon name="hero-x-mark" class="size-4" />
            </button>
          </div>

          <%!-- Error --%>
          <div :if={@modal_error} class="alert alert-error mb-4 text-sm">
            <.icon name="hero-exclamation-circle" class="size-4" />
            <span>{@modal_error}</span>
          </div>

          <div class="bg-base-200/50 rounded-lg p-3 text-sm space-y-1 mb-4">
            <div class="flex gap-2">
              <span class="text-base-content/50 w-24">Key:</span>
              <span class="font-mono">{@modal_key.key_alias}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-24">Algorithm:</span>
              <span class="font-mono">{@modal_key.algorithm}</span>
            </div>
            <div class="flex gap-2">
              <span class="text-base-content/50 w-24">Status:</span>
              <span class="badge badge-sm badge-warning">{@modal_key.status}</span>
            </div>
          </div>

          <form phx-submit="activate_key" class="space-y-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Signed Certificate (PEM)</label>
              <textarea name="cert_pem" class="textarea textarea-bordered w-full font-mono text-xs h-40" placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"></textarea>
              <p class="text-xs text-base-content/40 mt-1">Paste the certificate signed by the parent CA.</p>
            </div>

            <div class="flex justify-end gap-2">
              <button phx-click="close_modal" type="button" class="btn btn-ghost btn-sm">Cancel</button>
              <button type="submit" class="btn btn-success btn-sm" disabled={@modal_busy}>
                <%= if @modal_busy do %>
                  <span class="loading loading-spinner loading-xs"></span> Activating...
                <% else %>
                  <.icon name="hero-arrow-up-tray" class="size-4" /> Upload & Activate
                <% end %>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
