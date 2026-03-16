defmodule PkiRaEngine.SchemaTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Schema.RaUser
  alias PkiRaEngine.Schema.CertProfile
  alias PkiRaEngine.Schema.CsrRequest
  alias PkiRaEngine.Schema.ServiceConfig
  alias PkiRaEngine.Schema.RaApiKey

  # ── RaUser ──────────────────────────────────────────────────────────

  describe "RaUser.changeset/2" do
    @valid_ra_user %{
      did: "did:example:123",
      display_name: "Alice",
      role: "ra_admin",
      status: "active"
    }

    test "valid changeset" do
      changeset = RaUser.changeset(%RaUser{}, @valid_ra_user)
      assert changeset.valid?
    end

    test "missing required fields" do
      changeset = RaUser.changeset(%RaUser{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:did]
      assert errors[:role]
    end

    test "invalid role" do
      changeset = RaUser.changeset(%RaUser{}, %{@valid_ra_user | role: "superadmin"})
      refute changeset.valid?
      assert errors_on(changeset)[:role]
    end

    test "invalid status" do
      changeset = RaUser.changeset(%RaUser{}, %{@valid_ra_user | status: "deleted"})
      refute changeset.valid?
      assert errors_on(changeset)[:status]
    end
  end

  # ── CertProfile ────────────────────────────────────────────────────

  describe "CertProfile.changeset/2" do
    @valid_cert_profile %{
      name: "standard_tls",
      key_usage: "digitalSignature",
      digest_algo: "sha256"
    }

    test "valid changeset" do
      changeset = CertProfile.changeset(%CertProfile{}, @valid_cert_profile)
      assert changeset.valid?
    end

    test "missing required fields" do
      changeset = CertProfile.changeset(%CertProfile{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:name]
    end
  end

  # ── CsrRequest ─────────────────────────────────────────────────────

  describe "CsrRequest.changeset/2" do
    @valid_csr_request %{
      subject_dn: "CN=test.example.com",
      cert_profile_id: 1,
      status: "pending",
      submitted_at: ~U[2026-01-01 00:00:00.000000Z]
    }

    test "valid changeset" do
      changeset = CsrRequest.changeset(%CsrRequest{}, @valid_csr_request)
      assert changeset.valid?
    end

    test "missing required fields" do
      changeset = CsrRequest.changeset(%CsrRequest{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:subject_dn]
      assert errors[:cert_profile_id]
      assert errors[:submitted_at]
    end

    test "invalid status" do
      changeset = CsrRequest.changeset(%CsrRequest{}, %{@valid_csr_request | status: "unknown"})
      refute changeset.valid?
      assert errors_on(changeset)[:status]
    end
  end

  # ── ServiceConfig ──────────────────────────────────────────────────

  describe "ServiceConfig.changeset/2" do
    @valid_service_config %{
      service_type: "csr_web",
      port: 8080,
      url: "https://ra.example.com"
    }

    test "valid changeset" do
      changeset = ServiceConfig.changeset(%ServiceConfig{}, @valid_service_config)
      assert changeset.valid?
    end

    test "missing required fields" do
      changeset = ServiceConfig.changeset(%ServiceConfig{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:service_type]
    end

    test "invalid service_type" do
      changeset =
        ServiceConfig.changeset(%ServiceConfig{}, %{@valid_service_config | service_type: "ftp"})

      refute changeset.valid?
      assert errors_on(changeset)[:service_type]
    end
  end

  # ── RaApiKey ───────────────────────────────────────────────────────

  describe "RaApiKey.changeset/2" do
    @valid_api_key %{
      hashed_key: "abc123hash",
      ra_user_id: 1,
      label: "My Key",
      status: "active"
    }

    test "valid changeset" do
      changeset = RaApiKey.changeset(%RaApiKey{}, @valid_api_key)
      assert changeset.valid?
    end

    test "missing required fields" do
      changeset = RaApiKey.changeset(%RaApiKey{}, %{})
      refute changeset.valid?
      errors = errors_on(changeset)
      assert errors[:hashed_key]
      assert errors[:ra_user_id]
    end

    test "invalid status" do
      changeset = RaApiKey.changeset(%RaApiKey{}, %{@valid_api_key | status: "expired"})
      refute changeset.valid?
      assert errors_on(changeset)[:status]
    end
  end
end
