defmodule PkiTenantWeb.Ca.CertificatesLive do
  use PkiTenantWeb, :live_view

  alias PkiCaEngine.{CaInstanceManagement, IssuerKeyManagement, CertificateSigning}

  require Logger

  @revocation_reasons [
    {"unspecified", "Unspecified"},
    {"key_compromise", "Key Compromise"},
    {"ca_compromise", "CA Compromise"},
    {"affiliation_changed", "Affiliation Changed"},
    {"superseded", "Superseded"},
    {"cessation_of_operation", "Cessation of Operation"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Certificates",
       certificates: [],
       issuer_keys: [],
       ca_instances: [],
       selected_ca_id: "",
       selected_issuer_key_id: "",
       selected_key_label: "",
       key_search: "",
       key_search_results: [],
       status_filter: "all",
       selected_cert: nil,
       revocation_reasons: @revocation_reasons,
       revoke_reason: "unspecified",
       loading: true,
       page: 1,
       per_page: 20
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    if connected?(socket), do: send(self(), {:load_data, params})
    {:noreply, socket}
  end

  @impl true
  def handle_info({:load_data, params}, socket) do
    try do
      user_ca_id = socket.assigns.current_user[:ca_instance_id]

      ca_instances = case CaInstanceManagement.list_ca_instances() do
        {:ok, instances} -> instances
        _ -> []
      end

      effective_ca_id =
        cond do
          params["ca"] && params["ca"] != "" -> params["ca"]
          user_ca_id -> user_ca_id
          true ->
            case ca_instances do
              [first | _] -> first.id
              _ -> nil
            end
        end

      issuer_keys = if effective_ca_id do
        case IssuerKeyManagement.list_issuer_keys(effective_ca_id) do
          {:ok, keys} -> keys
          _ -> []
        end
      else
        []
      end

      url_key_id = params["key"] || ""
      url_status = params["status"] || "all"

      key_label = if url_key_id != "" do
        case Enum.find(issuer_keys, fn k -> k.id == url_key_id end) do
          nil -> ""
          key -> "#{key.key_alias} (#{key.algorithm})"
        end
      else
        ""
      end

      {:noreply,
       socket
       |> assign(
         ca_instances: ca_instances,
         selected_ca_id: effective_ca_id || "",
         issuer_keys: issuer_keys,
         selected_issuer_key_id: url_key_id,
         selected_key_label: key_label,
         status_filter: url_status,
         selected_cert: nil,
         loading: false,
         page: 1
       )
       |> load_certificates()}
    rescue
      e ->
        Logger.warning("[CertificatesLive] Failed to load data: #{Exception.message(e)}")
        {:noreply, assign(socket, loading: false)}
    end
  end

  @impl true
  def handle_event("search", params, socket) do
    ca_id = params["ca_id"] || socket.assigns.selected_ca_id
    status = params["status"] || "all"
    key_id = socket.assigns.selected_issuer_key_id

    query = URI.encode_query(
      Enum.reject([ca: ca_id, key: key_id, status: status], fn {_, v} -> v == "" or v == "all" end)
    )

    path = if query == "", do: "/certificates", else: "/certificates?#{query}"
    {:noreply, push_patch(socket, to: path)}
  end

  @impl true
  def handle_event("search_issuer_key", %{"value" => query}, socket) do
    results = if String.length(query) >= 1 do
      q = String.downcase(query)
      socket.assigns.issuer_keys
      |> Enum.filter(fn key ->
        String.contains?(String.downcase(key.key_alias || ""), q) or
        String.contains?(String.downcase(key.algorithm || ""), q)
      end)
    else
      []
    end

    {:noreply, assign(socket, key_search: query, key_search_results: results)}
  end

  @impl true
  def handle_event("select_issuer_key", %{"issuer_key_id" => id, "label" => label}, socket) do
    {:noreply, assign(socket, selected_issuer_key_id: id, selected_key_label: label, key_search: "", key_search_results: [])}
  end

  @impl true
  def handle_event("select_issuer_key", %{"issuer_key_id" => id}, socket) do
    label = case Enum.find(socket.assigns.issuer_keys, fn k -> k.id == id end) do
      nil -> ""
      key -> "#{key.key_alias} (#{key.algorithm})"
    end
    {:noreply, assign(socket, selected_issuer_key_id: id, selected_key_label: label, key_search: "", key_search_results: [])}
  end

  @impl true
  def handle_event("clear_issuer_key", _, socket) do
    {:noreply, assign(socket, selected_issuer_key_id: "", selected_key_label: "", key_search: "", key_search_results: [])}
  end

  @impl true
  def handle_event("view_cert", %{"serial" => serial}, socket) do
    case CertificateSigning.get_certificate(serial) do
      {:ok, cert} when not is_nil(cert) ->
        parsed = parse_x509(cert.cert_der || cert.cert_pem)

        enriched = %{
          serial_number: cert.serial_number,
          subject_dn: cert.subject_dn,
          issuer_key_id: cert.issuer_key_id,
          cert_pem: cert.cert_pem,
          cert_der: cert.cert_der,
          not_before: cert.not_before,
          not_after: cert.not_after,
          status: cert.status,
          revoked_at: cert.revoked_at,
          revocation_reason: cert.revocation_reason,
          fingerprint: parsed[:fingerprint] || "-",
          issuer_dn: parsed[:issuer_dn],
          signature_algorithm: parsed[:signature_algorithm],
          public_key_algorithm: parsed[:public_key_algorithm],
          serial_hex: parsed[:serial_hex],
          key_usage: parsed[:key_usage],
          basic_constraints: parsed[:basic_constraints],
          extensions: parsed[:extensions]
        }

        {:noreply, assign(socket, selected_cert: enriched)}

      _ ->
        {:noreply, put_flash(socket, :error, "Certificate not found.")}
    end
  end

  @impl true
  def handle_event("close_detail", _, socket) do
    {:noreply, assign(socket, selected_cert: nil)}
  end

  @impl true
  def handle_event("revoke_cert", %{"serial" => serial, "reason" => reason}, socket) do
    if socket.assigns.current_user[:role] != "ca_admin" do
      {:noreply, put_flash(socket, :error, "Only CA administrators can revoke certificates.")}
    else
      case CertificateSigning.revoke_certificate(serial, reason) do
        {:ok, _} ->
          PkiTenant.AuditBridge.log("certificate_revoked", %{serial: serial, reason: reason})

          {:noreply,
           socket
           |> put_flash(:info, "Certificate #{String.slice(serial, 0, 12)}... revoked.")
           |> assign(selected_cert: nil)
           |> load_certificates()}

        {:error, reason} ->
          Logger.error("[certificates] Failed to revoke #{serial}: #{inspect(reason)}")

          {:noreply,
           put_flash(socket, :error, PkiTenantWeb.ErrorHelpers.sanitize_error("Failed to revoke certificate", reason))}
      end
    end
  end

  def handle_event("revoke_cert", _params, socket) do
    role = socket.assigns.current_user[:role]
    if role != "ca_admin" do
      {:noreply, put_flash(socket, :error, "Only CA administrators can revoke certificates.")}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: parse_int(page) || 1)}
  end

  defp parse_int(val) when is_integer(val), do: val
  defp parse_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp load_certificates(socket) do
    issuer_key_id = socket.assigns.selected_issuer_key_id
    status = socket.assigns.status_filter

    filters = if status != "all", do: [status: status], else: []

    certs = if issuer_key_id != "" do
      case CertificateSigning.list_certificates(issuer_key_id, filters) do
        {:ok, certs} -> certs
        _ -> []
      end
    else
      # Load all certs across all issuer keys in this CA
      ca_id = socket.assigns.selected_ca_id
      if ca_id != "" do
        issuer_keys = socket.assigns.issuer_keys
        issuer_keys
        |> Enum.flat_map(fn key ->
          case CertificateSigning.list_certificates(key.id, filters) do
            {:ok, certs} -> certs
            _ -> []
          end
        end)
      else
        []
      end
    end

    assign(socket, certificates: certs)
  rescue
    _ -> assign(socket, certificates: [])
  end

  defp parse_x509(nil), do: %{}
  defp parse_x509(cert_data) do
    try do
      otp_cert = cond do
        is_binary(cert_data) and String.starts_with?(to_string(cert_data), "-----BEGIN") ->
          X509.Certificate.from_pem!(cert_data)
        is_binary(cert_data) ->
          X509.Certificate.from_der!(cert_data)
        true ->
          nil
      end

      if otp_cert do
        fingerprint = X509.Certificate.to_der(otp_cert)
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)
        |> format_fingerprint()

        subject = X509.Certificate.subject(otp_cert)
        |> X509.RDNSequence.to_string()

        issuer = X509.Certificate.issuer(otp_cert)
        |> X509.RDNSequence.to_string()

        {_algo_oid, _params} = sig_info = X509.Certificate.signature_algorithm(otp_cert)
        sig_algo = format_signature_algorithm(sig_info)

        pub_key_algo = format_public_key_algorithm(X509.Certificate.public_key(otp_cert))

        serial = X509.Certificate.serial(otp_cert)
        serial_hex = if is_integer(serial), do: Integer.to_string(serial, 16), else: to_string(serial)

        extensions = X509.Certificate.extensions(otp_cert)
        key_usage = extract_key_usage(extensions)
        basic_constraints = extract_basic_constraints(extensions)
        ext_list = format_extensions(extensions)

        %{
          fingerprint: fingerprint,
          subject_dn: subject,
          issuer_dn: issuer,
          signature_algorithm: sig_algo,
          public_key_algorithm: pub_key_algo,
          serial_hex: serial_hex,
          key_usage: key_usage,
          basic_constraints: basic_constraints,
          extensions: ext_list
        }
      else
        %{}
      end
    rescue
      _ ->
        # Fallback: raw ASN.1 parsing for PQC certificates (KAZ-SIGN, ML-DSA, etc.)
        parse_x509_raw(cert_data)
    end
  end

  defp parse_x509_raw(cert_data) do
    try do
      der = cond do
        is_binary(cert_data) and String.starts_with?(to_string(cert_data), "-----BEGIN") ->
          case :public_key.pem_decode(cert_data) do
            [{_type, der, _}] -> der
            _ -> nil
          end
        is_binary(cert_data) -> cert_data
        true -> nil
      end

      if der do
        {:Certificate, tbs_cert, sig_algo, _signature} = :public_key.der_decode(:Certificate, der)
        {:TBSCertificate, _version, serial, _sig_algo_inner, issuer_rdn, _validity, subject_rdn, _subject_pki, _issuer_uid, _subject_uid, extensions} = tbs_cert

        fingerprint = :crypto.hash(:sha256, der)
        |> Base.encode16(case: :lower)
        |> format_fingerprint()

        subject = format_rdn_sequence(subject_rdn)
        issuer = format_rdn_sequence(issuer_rdn)

        serial_hex = if is_integer(serial), do: Integer.to_string(serial, 16), else: to_string(serial)

        {:AlgorithmIdentifier, sig_oid, _params} = sig_algo
        sig_algo_str = format_oid(sig_oid)

        ext_list = case extensions do
          :asn1_NOVALUE -> []
          exts when is_list(exts) ->
            Enum.map(exts, fn
              {:Extension, oid, critical, _value} ->
                %{oid: format_oid_string(oid), name: extension_name(oid), critical: critical}
              _ ->
                %{oid: "?", name: "Unknown", critical: false}
            end)
          _ -> []
        end

        %{
          fingerprint: fingerprint,
          subject_dn: subject,
          issuer_dn: issuer,
          signature_algorithm: sig_algo_str,
          public_key_algorithm: "PQC (Post-Quantum)",
          serial_hex: serial_hex,
          key_usage: [],
          basic_constraints: nil,
          extensions: ext_list
        }
      else
        %{}
      end
    rescue
      _ -> %{}
    end
  end

  defp format_rdn_sequence({:rdnSequence, rdn_sets}) do
    rdn_sets
    |> List.flatten()
    |> Enum.map(fn
      {:AttributeTypeAndValue, oid, value} ->
        name = rdn_attr_name(oid)
        val = extract_rdn_value(value)
        "#{name}=#{val}"
      _ -> ""
    end)
    |> Enum.reject(&(&1 == ""))
    |> Enum.reverse()
    |> Enum.join(", ")
  end
  defp format_rdn_sequence(_), do: "-"

  defp rdn_attr_name({2, 5, 4, 3}), do: "CN"
  defp rdn_attr_name({2, 5, 4, 6}), do: "C"
  defp rdn_attr_name({2, 5, 4, 7}), do: "L"
  defp rdn_attr_name({2, 5, 4, 8}), do: "ST"
  defp rdn_attr_name({2, 5, 4, 10}), do: "O"
  defp rdn_attr_name({2, 5, 4, 11}), do: "OU"
  defp rdn_attr_name({1, 2, 840, 113549, 1, 9, 1}), do: "emailAddress"
  defp rdn_attr_name(oid) when is_tuple(oid), do: Enum.join(Tuple.to_list(oid), ".")
  defp rdn_attr_name(_), do: "?"

  defp extract_rdn_value(value) when is_binary(value) do
    case :public_key.der_decode(:X520CommonName, value) do
      {:utf8String, str} -> to_string(str)
      {:printableString, str} -> to_string(str)
      {:ia5String, str} -> to_string(str)
      {:teletexString, str} -> to_string(str)
      str when is_binary(str) -> str
      str when is_list(str) -> to_string(str)
      _ -> inspect(value)
    end
  rescue
    _ ->
      value
      |> :binary.bin_to_list()
      |> Enum.filter(&(&1 >= 32 and &1 <= 126))
      |> to_string()
  end
  defp extract_rdn_value(value), do: to_string(value)

  defp format_oid(oid) when is_tuple(oid) do
    oid_str = Enum.join(Tuple.to_list(oid), ".")
    case oid do
      {1, 2, 840, 113549, 1, 1, 11} -> "SHA-256 with RSA"
      {1, 2, 840, 10045, 4, 3, 2} -> "ECDSA with SHA-256"
      _ -> "OID: #{oid_str}"
    end
  end
  defp format_oid(_), do: "Unknown"

  defp format_oid_string(oid) when is_tuple(oid), do: Enum.join(Tuple.to_list(oid), ".")
  defp format_oid_string(oid), do: to_string(oid)

  defp format_signature_algorithm({oid, _params}) do
    case oid do
      {1, 2, 840, 113549, 1, 1, 11} -> "SHA-256 with RSA"
      {1, 2, 840, 113549, 1, 1, 12} -> "SHA-384 with RSA"
      {1, 2, 840, 113549, 1, 1, 13} -> "SHA-512 with RSA"
      {1, 2, 840, 10045, 4, 3, 2} -> "ECDSA with SHA-256"
      {1, 2, 840, 10045, 4, 3, 3} -> "ECDSA with SHA-384"
      {1, 2, 840, 10045, 4, 3, 4} -> "ECDSA with SHA-512"
      oid when is_tuple(oid) -> "OID: #{Enum.join(Tuple.to_list(oid), ".")}"
      _ -> "Unknown"
    end
  end
  defp format_signature_algorithm(_), do: "Unknown"

  defp format_public_key_algorithm({:RSAPublicKey, _modulus, _exp}), do: "RSA"
  defp format_public_key_algorithm({{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}), do: "ECC P-256"
  defp format_public_key_algorithm({{:ECPoint, _}, {:namedCurve, {1, 3, 132, 0, 34}}}), do: "ECC P-384"
  defp format_public_key_algorithm(_), do: "Unknown"

  defp extract_key_usage(extensions) do
    case Enum.find(extensions, fn ext -> elem(ext, 1) == {2, 5, 29, 15} end) do
      nil -> []
      ext ->
        case elem(ext, 3) do
          usage when is_list(usage) -> Enum.map(usage, &Atom.to_string/1)
          _ -> []
        end
    end
  rescue
    _ -> []
  end

  defp extract_basic_constraints(extensions) do
    case Enum.find(extensions, fn ext -> elem(ext, 1) == {2, 5, 29, 19} end) do
      nil -> nil
      ext ->
        case elem(ext, 3) do
          {:BasicConstraints, is_ca, path_len} ->
            %{ca: is_ca, path_length: if(path_len == :asn1_NOVALUE, do: nil, else: path_len)}
          _ -> nil
        end
    end
  rescue
    _ -> nil
  end

  defp format_extensions(extensions) do
    Enum.map(extensions, fn ext ->
      oid = elem(ext, 1)
      critical = elem(ext, 2)
      oid_str = if is_tuple(oid), do: Enum.join(Tuple.to_list(oid), "."), else: to_string(oid)
      name = extension_name(oid)
      %{oid: oid_str, name: name, critical: critical}
    end)
  rescue
    _ -> []
  end

  defp extension_name({2, 5, 29, 15}), do: "Key Usage"
  defp extension_name({2, 5, 29, 19}), do: "Basic Constraints"
  defp extension_name({2, 5, 29, 14}), do: "Subject Key Identifier"
  defp extension_name({2, 5, 29, 35}), do: "Authority Key Identifier"
  defp extension_name({2, 5, 29, 17}), do: "Subject Alternative Name"
  defp extension_name({2, 5, 29, 31}), do: "CRL Distribution Points"
  defp extension_name({1, 3, 6, 1, 5, 5, 7, 1, 1}), do: "Authority Information Access"
  defp extension_name({2, 5, 29, 37}), do: "Extended Key Usage"
  defp extension_name({2, 5, 29, 32}), do: "Certificate Policies"
  defp extension_name(oid) when is_tuple(oid), do: "OID: #{Enum.join(Tuple.to_list(oid), ".")}"
  defp extension_name(_), do: "Unknown"

  defp format_fingerprint(hex) do
    hex
    |> String.graphemes()
    |> Enum.chunk_every(2)
    |> Enum.map(&Enum.join/1)
    |> Enum.join(":")
  end

  defp format_datetime(nil), do: "-"
  defp format_datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  defp format_datetime(_), do: "-"

  defp days_remaining(nil), do: "-"
  defp days_remaining(%DateTime{} = not_after) do
    days = DateTime.diff(not_after, DateTime.utc_now(), :day)
    cond do
      days < 0 -> "Expired"
      days == 0 -> "Expires today"
      days < 30 -> "#{days}d (expiring soon)"
      true -> "#{days}d"
    end
  end
  defp days_remaining(_), do: "-"

  defp validity_class(nil), do: ""
  defp validity_class(%DateTime{} = not_after) do
    days = DateTime.diff(not_after, DateTime.utc_now(), :day)
    cond do
      days < 0 -> "text-rose-400"
      days < 30 -> "text-amber-400"
      true -> "text-emerald-400"
    end
  end
  defp validity_class(_), do: ""

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-4">
      <%!-- Description --%>
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-document-text" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">Issued Certificates</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            View and manage certificates issued by this CA. Select an issuer key to filter certificates.
            Certificates can be revoked by a CA Admin — revoked certificates are published in the CRL and reflected in OCSP responses.
          </p>
        </div>
      </div>

      <%!-- Filters --%>
      <form phx-submit="search" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-4">
          <div class="flex flex-wrap items-end gap-4">
            <div>
              <label class="text-xs font-medium text-base-content/60 mb-1 block">CA Instance</label>
              <select name="ca_id" class="select select-sm select-bordered">
                <option :for={ca <- @ca_instances} value={ca.id} selected={ca.id == @selected_ca_id}>
                  {ca.name}
                </option>
              </select>
            </div>
            <div class="relative">
              <label class="text-xs font-medium text-base-content/60 mb-1 block">Issuer Key</label>
              <input type="text"
                     value={@key_search}
                     phx-keyup="search_issuer_key"
                     phx-debounce="300"
                     placeholder="Search key alias or algorithm..."
                     autocomplete="off"
                     class="input input-sm input-bordered w-64" />
              <div :if={@key_search != "" and @key_search_results != []} class="absolute z-30 mt-1 w-64 bg-base-100 border border-base-300 rounded-lg shadow-lg max-h-48 overflow-y-auto">
                <button :for={key <- @key_search_results}
                        type="button"
                        phx-click="select_issuer_key"
                        phx-value-issuer_key_id={key.id}
                        phx-value-label={"#{key.key_alias} (#{key.algorithm})"}
                        class="block w-full text-left px-3 py-2 text-sm hover:bg-base-200">
                  <span class="font-medium">{key.key_alias}</span>
                  <span class="text-xs text-base-content/50 ml-1">({key.algorithm})</span>
                </button>
              </div>
              <div :if={@selected_issuer_key_id != ""} class="mt-1">
                <span class="badge badge-sm badge-primary gap-1">
                  {@selected_key_label}
                  <button type="button" phx-click="clear_issuer_key" class="ml-1">&times;</button>
                </span>
              </div>
            </div>
            <div>
              <label class="text-xs font-medium text-base-content/60 mb-1 block">Status</label>
              <select name="status" class="select select-sm select-bordered">
                <option value="all" selected={@status_filter == "all"}>All</option>
                <option value="active" selected={@status_filter == "active"}>Active</option>
                <option value="revoked" selected={@status_filter == "revoked"}>Revoked</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary btn-sm gap-1">
              <.icon name="hero-magnifying-glass" class="size-4" />
              Search
            </button>
            <div class="text-sm text-base-content/50">
              {length(@certificates)} certificate(s)
            </div>
          </div>
        </div>
      </form>

      <%!-- Certificates table --%>
      <% paginated = @certificates |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <table class="table table-sm table-fixed w-full">
            <thead>
              <tr class="text-xs uppercase text-base-content/50">
                <th class="w-[15%]">Serial</th>
                <th class="w-[30%]">Subject DN</th>
                <th class="w-[15%]">Issuer Key</th>
                <th class="w-[12%]">Valid Until</th>
                <th class="w-[8%]">Status</th>
                <th class="w-[10%]">Remaining</th>
                <th class="w-[10%] text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={cert <- paginated} class="hover cursor-pointer" phx-click="view_cert" phx-value-serial={cert.serial_number}>
                <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{cert.serial_number}</td>
                <td class="overflow-hidden text-ellipsis whitespace-nowrap text-sm">{cert.subject_dn}</td>
                <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                  {find_key_alias(cert.issuer_key_id, @issuer_keys)}
                </td>
                <td class="text-xs"><.local_time dt={cert.not_after} /></td>
                <td>
                  <span class={["badge badge-sm", if(cert.status == "active", do: "badge-success", else: "badge-error")]}>
                    {cert.status}
                  </span>
                </td>
                <td class={"text-xs #{validity_class(cert.not_after)}"}>{days_remaining(cert.not_after)}</td>
                <td class="text-right">
                  <button :if={cert.status == "active"} phx-click="view_cert" phx-value-serial={cert.serial_number} title="View & Revoke" class="btn btn-ghost btn-xs text-sky-400">
                    <.icon name="hero-eye" class="size-4" />
                  </button>
                </td>
              </tr>
              <tr :if={paginated == []}>
                <td colspan="7" class="text-center text-base-content/50 py-8">
                  {if @loading, do: "Loading...", else: "No certificates found."}
                </td>
              </tr>
            </tbody>
          </table>

          <%!-- Pagination --%>
          <div :if={length(@certificates) > @per_page} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {min((@page - 1) * @per_page + 1, length(@certificates))}-{min(@page * @per_page, length(@certificates))} of {length(@certificates)}
            </span>
            <div class="join">
              <button :for={p <- 1..max(ceil(length(@certificates) / @per_page), 1)}
                      phx-click="change_page" phx-value-page={p}
                      class={["join-item btn btn-xs", if(p == @page, do: "btn-active", else: "")]}>
                {p}
              </button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Certificate Detail Panel --%>
      <%= if @selected_cert do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-sm font-semibold">
                <.icon name="hero-document-text" class="size-4 inline" /> Certificate Details
              </h2>
              <button phx-click="close_detail" class="btn btn-ghost btn-sm btn-square">
                <.icon name="hero-x-mark" class="size-4" />
              </button>
            </div>

            <div class="grid grid-cols-2 gap-4 text-sm">
              <div>
                <label class="text-xs text-base-content/50">Serial Number</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:serial_number]}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Status</label>
                <p>
                  <span class={["badge badge-sm", if(@selected_cert[:status] == "active", do: "badge-success", else: "badge-error")]}>
                    {@selected_cert[:status]}
                  </span>
                  <%= if @selected_cert[:revoked_at] do %>
                    <span class="text-xs text-base-content/50 ml-2">
                      Revoked: <.local_time dt={@selected_cert[:revoked_at]} /> ({@selected_cert[:revocation_reason]})
                    </span>
                  <% end %>
                </p>
              </div>
              <div class="col-span-2">
                <label class="text-xs text-base-content/50">Subject DN</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:subject_dn]}</p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Not Before</label>
                <p><.local_time dt={@selected_cert[:not_before]} /></p>
              </div>
              <div>
                <label class="text-xs text-base-content/50">Not After</label>
                <p class={validity_class(@selected_cert[:not_after])}>
                  <.local_time dt={@selected_cert[:not_after]} /> ({days_remaining(@selected_cert[:not_after])})
                </p>
              </div>
              <div class="col-span-2">
                <label class="text-xs text-base-content/50">SHA-256 Fingerprint</label>
                <p class="font-mono text-xs break-all">{@selected_cert[:fingerprint] || "-"}</p>
              </div>
            </div>

            <%!-- Parsed X.509 Details --%>
            <div :if={@selected_cert[:issuer_dn] || @selected_cert[:signature_algorithm]} class="mt-4 border-t border-base-300 pt-4">
              <h3 class="text-sm font-semibold mb-3">
                <.icon name="hero-magnifying-glass" class="size-4 inline" /> X.509 Certificate Details
              </h3>
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div class="col-span-2">
                  <label class="text-xs text-base-content/50">Issuer DN</label>
                  <p class="font-mono text-xs break-all">{@selected_cert[:issuer_dn] || "-"}</p>
                </div>
                <div>
                  <label class="text-xs text-base-content/50">Signature Algorithm</label>
                  <p>{@selected_cert[:signature_algorithm] || "-"}</p>
                </div>
                <div>
                  <label class="text-xs text-base-content/50">Public Key Algorithm</label>
                  <p>{@selected_cert[:public_key_algorithm] || "-"}</p>
                </div>
                <div>
                  <label class="text-xs text-base-content/50">Serial (Hex)</label>
                  <p class="font-mono text-xs break-all">{@selected_cert[:serial_hex] || "-"}</p>
                </div>
                <div>
                  <label class="text-xs text-base-content/50">Basic Constraints</label>
                  <p>
                    <%= if bc = @selected_cert[:basic_constraints] do %>
                      CA: {if bc.ca, do: "Yes", else: "No"}{if bc.path_length, do: ", Path Length: #{bc.path_length}", else: ""}
                    <% else %>
                      -
                    <% end %>
                  </p>
                </div>
                <div :if={@selected_cert[:key_usage] != []} class="col-span-2">
                  <label class="text-xs text-base-content/50">Key Usage</label>
                  <div class="flex flex-wrap gap-1 mt-1">
                    <span :for={usage <- @selected_cert[:key_usage] || []} class="badge badge-sm badge-ghost">{usage}</span>
                  </div>
                </div>
                <div :if={@selected_cert[:extensions] != []} class="col-span-2">
                  <label class="text-xs text-base-content/50">Extensions</label>
                  <div class="mt-1 space-y-1">
                    <div :for={ext <- @selected_cert[:extensions] || []} class="flex items-center gap-2 text-xs">
                      <span class="font-mono text-base-content/40">{ext.oid}</span>
                      <span>{ext.name}</span>
                      <span :if={ext.critical} class="badge badge-xs badge-warning">critical</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <%!-- PEM Download --%>
            <div :if={@selected_cert[:cert_pem]} class="mt-4">
              <label class="text-xs text-base-content/50">Certificate PEM</label>
              <textarea readonly class="textarea textarea-bordered w-full font-mono text-xs h-24 mt-1">{@selected_cert[:cert_pem]}</textarea>
            </div>

            <%!-- Revoke Action --%>
            <div :if={@selected_cert[:status] == "active" and @current_user[:role] == "ca_admin"} class="mt-4 border-t border-base-300 pt-4">
              <h3 class="text-sm font-semibold text-rose-400 mb-2">
                <.icon name="hero-exclamation-triangle" class="size-4 inline" /> Revoke Certificate
              </h3>
              <form phx-submit="revoke_cert" class="flex items-end gap-3">
                <input type="hidden" name="serial" value={@selected_cert[:serial_number]} />
                <div class="flex-1">
                  <label class="text-xs text-base-content/50 mb-1 block">Reason</label>
                  <select name="reason" class="select select-sm select-bordered w-full">
                    <option :for={{val, label} <- @revocation_reasons} value={val}>{label}</option>
                  </select>
                </div>
                <button type="submit"
                        data-confirm="Are you sure you want to revoke this certificate? This action cannot be undone."
                        class="btn btn-error btn-sm">
                  <.icon name="hero-no-symbol" class="size-4" /> Revoke
                </button>
              </form>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp find_key_alias(nil, _), do: "-"
  defp find_key_alias(id, keys) do
    case Enum.find(keys, &(&1.id == id)) do
      nil -> String.slice(to_string(id), 0, 8)
      key -> key.key_alias
    end
  end
end
