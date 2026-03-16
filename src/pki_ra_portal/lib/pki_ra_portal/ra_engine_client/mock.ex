defmodule PkiRaPortal.RaEngineClient.Mock do
  @moduledoc """
  Mock implementation of the RA engine client.

  Returns realistic static data for development and testing,
  allowing the portal to be built independently of the actual RA engine.
  """

  @behaviour PkiRaPortal.RaEngineClient

  @impl true
  def list_users do
    {:ok,
     [
       %{
         id: 1,
         did: "did:ssdid:raadmin1",
         display_name: "RA Admin One",
         role: "ra_admin",
         status: "active"
       },
       %{
         id: 2,
         did: "did:ssdid:raofficer1",
         display_name: "RA Officer One",
         role: "ra_officer",
         status: "active"
       },
       %{
         id: 3,
         did: "did:ssdid:auditor1",
         display_name: "Auditor One",
         role: "auditor",
         status: "active"
       }
     ]}
  end

  @impl true
  def create_user(attrs) do
    {:ok, Map.merge(%{id: System.unique_integer([:positive]), status: "active"}, attrs)}
  end

  @impl true
  def delete_user(id), do: {:ok, %{id: id, status: "suspended"}}

  @impl true
  def list_csrs(filters) do
    csrs = [
      %{
        id: 1,
        subject: "CN=example.com,O=Example Corp",
        status: "pending",
        profile_name: "TLS Server",
        submitted_at: ~U[2026-03-15 10:00:00Z],
        requestor_did: "did:ssdid:requester1"
      },
      %{
        id: 2,
        subject: "CN=api.example.com,O=Example Corp",
        status: "approved",
        profile_name: "TLS Server",
        submitted_at: ~U[2026-03-14 08:30:00Z],
        requestor_did: "did:ssdid:requester2"
      },
      %{
        id: 3,
        subject: "CN=John Doe,O=Example Corp",
        status: "rejected",
        profile_name: "Client Auth",
        submitted_at: ~U[2026-03-13 14:20:00Z],
        requestor_did: "did:ssdid:requester3"
      }
    ]

    filtered =
      case Keyword.get(filters, :status) do
        nil -> csrs
        status -> Enum.filter(csrs, &(&1.status == status))
      end

    {:ok, filtered}
  end

  @impl true
  def get_csr(id) do
    {:ok,
     %{
       id: id,
       subject: "CN=example.com,O=Example Corp",
       status: "pending",
       profile_name: "TLS Server",
       submitted_at: ~U[2026-03-15 10:00:00Z],
       requestor_did: "did:ssdid:requester1",
       public_key_algorithm: "RSA-2048",
       extensions: %{san: ["example.com", "www.example.com"]}
     }}
  end

  @impl true
  def approve_csr(id, _meta) do
    {:ok, %{id: id, status: "approved", approved_at: DateTime.utc_now()}}
  end

  @impl true
  def reject_csr(id, reason, _meta) do
    {:ok, %{id: id, status: "rejected", rejection_reason: reason, rejected_at: DateTime.utc_now()}}
  end

  @impl true
  def list_cert_profiles do
    {:ok,
     [
       %{
         id: 1,
         name: "TLS Server",
         key_usage: "digitalSignature,keyEncipherment",
         ext_key_usage: "serverAuth",
         digest_algo: "SHA-256",
         validity_days: 365
       },
       %{
         id: 2,
         name: "Client Auth",
         key_usage: "digitalSignature",
         ext_key_usage: "clientAuth",
         digest_algo: "SHA-256",
         validity_days: 730
       }
     ]}
  end

  @impl true
  def create_cert_profile(attrs) do
    {:ok, Map.merge(%{id: System.unique_integer([:positive])}, attrs)}
  end

  @impl true
  def update_cert_profile(id, attrs) do
    {:ok, Map.merge(%{id: id}, attrs)}
  end

  @impl true
  def delete_cert_profile(id) do
    {:ok, %{id: id, deleted: true}}
  end

  @impl true
  def list_service_configs do
    {:ok,
     [
       %{
         id: 1,
         service_type: "OCSP Responder",
         port: 8080,
         url: "http://ocsp.example.com",
         rate_limit: 1000,
         ip_whitelist: "10.0.0.0/8",
         ip_blacklist: "",
         status: "active"
       },
       %{
         id: 2,
         service_type: "CRL Distribution",
         port: 8081,
         url: "http://crl.example.com",
         rate_limit: 500,
         ip_whitelist: "",
         ip_blacklist: "",
         status: "active"
       }
     ]}
  end

  @impl true
  def configure_service(attrs) do
    {:ok, Map.merge(%{id: System.unique_integer([:positive]), status: "active"}, attrs)}
  end

  @impl true
  def list_api_keys(_filters) do
    {:ok,
     [
       %{
         id: 1,
         name: "Production API Key",
         prefix: "ra_prod_",
         created_at: ~U[2026-01-15 10:00:00Z],
         status: "active",
         last_used_at: ~U[2026-03-15 09:00:00Z]
       },
       %{
         id: 2,
         name: "Staging API Key",
         prefix: "ra_stg_",
         created_at: ~U[2026-02-01 08:00:00Z],
         status: "revoked",
         last_used_at: ~U[2026-02-28 12:00:00Z]
       }
     ]}
  end

  @impl true
  def create_api_key(attrs) do
    raw_key = "ra_" <> Base.encode64(:crypto.strong_rand_bytes(32), padding: false)

    {:ok,
     Map.merge(
       %{
         id: System.unique_integer([:positive]),
         raw_key: raw_key,
         prefix: String.slice(raw_key, 0, 8),
         created_at: DateTime.utc_now(),
         status: "active"
       },
       attrs
     )}
  end

  @impl true
  def revoke_api_key(id) do
    {:ok, %{id: id, status: "revoked", revoked_at: DateTime.utc_now()}}
  end
end
