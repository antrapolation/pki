defmodule PkiMnesia.Structs.StructsTest do
  use ExUnit.Case, async: true

  alias PkiMnesia.Structs.{
    ActivationSession,
    ApiKey,
    AuditLogEntry,
    BackupRecord,
    CertificateStatus,
    CeremonyParticipant,
    CeremonyTranscript,
    CertProfile,
    CsrRequest,
    DcvChallenge,
    HsmAgentSetup,
    IssuedCertificate,
    KeyCeremony,
    Keystore,
    PortalUser,
    PreSignedCrl,
    RaCaConnection,
    RaInstance,
    ServiceConfig
  }

  # ---------------------------------------------------------------------------
  # ActivationSession
  # ---------------------------------------------------------------------------

  describe "ActivationSession" do
    test "new/0 sets defaults" do
      s = ActivationSession.new()
      assert s.id != nil
      assert s.status == "awaiting_custodians"
      assert s.authenticated_custodians == []
      assert s.auth_tokens == []
      assert %DateTime{} = s.inserted_at
    end

    test "new/1 accepts custom attrs" do
      s = ActivationSession.new(%{
        issuer_key_id: "key-1",
        ceremony_id: "cer-1",
        threshold_k: 2,
        threshold_n: 3,
        status: "in_progress"
      })
      assert s.issuer_key_id == "key-1"
      assert s.threshold_k == 2
      assert s.threshold_n == 3
      assert s.status == "in_progress"
    end

    test "new/1 generates unique ids" do
      assert ActivationSession.new().id != ActivationSession.new().id
    end
  end

  # ---------------------------------------------------------------------------
  # AuditLogEntry
  # ---------------------------------------------------------------------------

  describe "AuditLogEntry" do
    test "new/0 sets defaults" do
      e = AuditLogEntry.new()
      assert e.id != nil
      assert e.actor == "system"
      assert e.category == "general"
      assert e.metadata == %{}
      assert %DateTime{} = e.timestamp
    end

    test "new/1 accepts atom action and category" do
      e = AuditLogEntry.new(%{action: :cert_revoked, category: :audit, actor: "admin"})
      assert e.action == "cert_revoked"
      assert e.category == "audit"
      assert e.actor == "admin"
    end

    test "new/1 accepts string keys" do
      e = AuditLogEntry.new(%{"action" => "login", "actor" => "user1"})
      assert e.action == "login"
      assert e.actor == "user1"
    end
  end

  # ---------------------------------------------------------------------------
  # BackupRecord
  # ---------------------------------------------------------------------------

  describe "BackupRecord" do
    test "new/0 sets defaults" do
      b = BackupRecord.new()
      assert b.id != nil
      assert b.type == "local"
      assert b.size_bytes == 0
      assert b.location == ""
      assert b.status == "completed"
      assert b.error == nil
    end

    test "new/1 accepts custom attrs" do
      b = BackupRecord.new(%{type: "s3", size_bytes: 1024, location: "s3://bucket/backup", status: "in_progress"})
      assert b.type == "s3"
      assert b.size_bytes == 1024
      assert b.location == "s3://bucket/backup"
      assert b.status == "in_progress"
    end
  end

  # ---------------------------------------------------------------------------
  # CertificateStatus
  # ---------------------------------------------------------------------------

  describe "CertificateStatus" do
    test "new/1 creates with required fields" do
      cs = CertificateStatus.new(%{serial_number: "AABB", issuer_key_id: "key-1"})
      assert cs.serial_number == "AABB"
      assert cs.issuer_key_id == "key-1"
      assert cs.status == "active"
      assert cs.id != nil
    end

    test "new/1 accepts revocation attrs" do
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      cs = CertificateStatus.new(%{
        serial_number: "CC",
        issuer_key_id: "k",
        status: "revoked",
        revoked_at: now,
        revocation_reason: "keyCompromise"
      })
      assert cs.status == "revoked"
      assert cs.revoked_at == now
      assert cs.revocation_reason == "keyCompromise"
    end
  end

  # ---------------------------------------------------------------------------
  # CeremonyParticipant
  # ---------------------------------------------------------------------------

  describe "CeremonyParticipant" do
    test "new/1 creates with required fields" do
      p = CeremonyParticipant.new(%{ceremony_id: "cer-1", name: "Alice", role: "custodian"})
      assert p.ceremony_id == "cer-1"
      assert p.name == "Alice"
      assert p.role == "custodian"
      assert p.id != nil
      assert %DateTime{} = p.inserted_at
    end

    test "new/1 generates unique ids" do
      p1 = CeremonyParticipant.new(%{ceremony_id: "c"})
      p2 = CeremonyParticipant.new(%{ceremony_id: "c"})
      assert p1.id != p2.id
    end
  end

  # ---------------------------------------------------------------------------
  # CeremonyTranscript
  # ---------------------------------------------------------------------------

  describe "CeremonyTranscript" do
    test "new/1 creates with empty entries" do
      t = CeremonyTranscript.new(%{ceremony_id: "cer-1"})
      assert t.ceremony_id == "cer-1"
      assert t.entries == []
      assert t.id != nil
    end

    test "append/2 adds entry and updates hash chain" do
      t = CeremonyTranscript.new(%{ceremony_id: "cer-1"})
      entry = %{"timestamp" => "2026-01-01T00:00:00Z", "actor" => "admin", "action" => "start", "details" => "{}"}
      t2 = CeremonyTranscript.append(t, entry)
      assert length(t2.entries) == 1
      [e] = t2.entries
      assert Map.has_key?(e, "event_hash")
      assert Map.has_key?(e, "prev_hash")
    end

    test "append/2 chains hashes across entries" do
      t = CeremonyTranscript.new(%{ceremony_id: "c"})
      e1 = %{"timestamp" => "T1", "actor" => "a", "action" => "init", "details" => "{}"}
      e2 = %{"timestamp" => "T2", "actor" => "a", "action" => "done", "details" => "{}"}
      t2 = CeremonyTranscript.append(t, e1)
      t3 = CeremonyTranscript.append(t2, e2)
      [first, second] = t3.entries
      assert second["prev_hash"] == first["event_hash"]
    end
  end

  # ---------------------------------------------------------------------------
  # CertProfile
  # ---------------------------------------------------------------------------

  describe "CertProfile" do
    test "new/1 creates with required fields" do
      cp = CertProfile.new(%{ra_instance_id: "ra-1", name: "TLS Client"})
      assert cp.ra_instance_id == "ra-1"
      assert cp.name == "TLS Client"
      assert cp.id != nil
    end
  end

  # ---------------------------------------------------------------------------
  # CsrRequest
  # ---------------------------------------------------------------------------

  describe "CsrRequest" do
    test "new/1 sets defaults" do
      csr = CsrRequest.new(%{csr_pem: "-----BEGIN...", cert_profile_id: "prof-1", subject_dn: "CN=test"})
      assert csr.id != nil
      assert csr.status == "pending"
      assert csr.reviewed_by == nil
      assert %DateTime{} = csr.submitted_at
    end

    test "new/1 accepts custom status" do
      csr = CsrRequest.new(%{csr_pem: "x", cert_profile_id: "p", subject_dn: "CN=x", status: "approved"})
      assert csr.status == "approved"
    end
  end

  # ---------------------------------------------------------------------------
  # DcvChallenge
  # ---------------------------------------------------------------------------

  describe "DcvChallenge" do
    test "new/1 sets defaults" do
      d = DcvChallenge.new(%{csr_request_id: "csr-1", domain: "example.com",
                             expires_at: DateTime.utc_now()})
      assert d.challenge_type == "dns"
      assert d.status == "pending"
      assert d.challenge_token != nil
      assert d.id != nil
    end

    test "new/1 accepts custom token" do
      d = DcvChallenge.new(%{csr_request_id: "csr-1", domain: "x.com",
                             challenge_token: "abc123",
                             expires_at: DateTime.utc_now()})
      assert d.challenge_token == "abc123"
    end
  end

  # ---------------------------------------------------------------------------
  # HsmAgentSetup
  # ---------------------------------------------------------------------------

  describe "HsmAgentSetup" do
    test "new/1 sets defaults" do
      h = HsmAgentSetup.new(%{ca_instance_id: "ca-1", tenant_id: "t-1"})
      assert h.status == "pending_agent"
      assert h.cert_mode == "generated"
      assert h.key_labels == []
      assert h.id != nil
    end

    test "new/1 accepts custom attrs" do
      h = HsmAgentSetup.new(%{
        ca_instance_id: "ca-1",
        tenant_id: "t-1",
        agent_id: "agent-99",
        status: "confirmed"
      })
      assert h.agent_id == "agent-99"
      assert h.status == "confirmed"
    end
  end

  # ---------------------------------------------------------------------------
  # IssuedCertificate
  # ---------------------------------------------------------------------------

  describe "IssuedCertificate" do
    test "new/1 creates with required fields" do
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      ic = IssuedCertificate.new(%{
        serial_number: "SN123",
        issuer_key_id: "key-1",
        subject_dn: "CN=Test",
        cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        not_before: now,
        not_after: DateTime.add(now, 365 * 86400, :second)
      })
      assert ic.serial_number == "SN123"
      assert ic.status == "active"
      assert ic.id != nil
    end
  end

  # ---------------------------------------------------------------------------
  # KeyCeremony
  # ---------------------------------------------------------------------------

  describe "KeyCeremony" do
    test "new/1 sets defaults" do
      kc = KeyCeremony.new(%{ca_instance_id: "ca-1", issuer_key_id: "key-1"})
      assert kc.status == "preparing"
      assert kc.ceremony_type == "sync"
      assert kc.keystore_mode == "softhsm"
      assert kc.domain_info == %{}
      assert kc.id != nil
    end

    test "new/1 accepts custom attrs" do
      kc = KeyCeremony.new(%{
        ca_instance_id: "ca-1",
        issuer_key_id: "key-1",
        algorithm: "ECC-P256",
        threshold_k: 2,
        threshold_n: 3,
        status: "in_progress"
      })
      assert kc.algorithm == "ECC-P256"
      assert kc.threshold_k == 2
      assert kc.status == "in_progress"
    end
  end

  # ---------------------------------------------------------------------------
  # Keystore
  # ---------------------------------------------------------------------------

  describe "Keystore" do
    test "new/1 sets defaults" do
      ks = Keystore.new(%{ca_instance_id: "ca-1", type: "software"})
      assert ks.type == "software"
      assert ks.status == "active"
      assert ks.config == %{}
      assert ks.id != nil
    end

    test "new/1 accepts hsm config" do
      cfg = %{pkcs11_lib_path: "/usr/lib/softhsm/libsofthsm2.so", slot_id: 0}
      ks = Keystore.new(%{ca_instance_id: "ca-1", type: "hsm", config: cfg})
      assert ks.type == "hsm"
      assert ks.config == cfg
    end
  end

  # ---------------------------------------------------------------------------
  # PortalUser
  # ---------------------------------------------------------------------------

  describe "PortalUser" do
    test "new/1 creates with defaults" do
      u = PortalUser.new(%{username: "alice", password_hash: "$2b$hash", role: :ca_admin, display_name: "Alice", email: "alice@test.local"})
      assert u.username == "alice"
      assert u.status == "active"
      assert u.id != nil
    end
  end

  # ---------------------------------------------------------------------------
  # PreSignedCrl
  # ---------------------------------------------------------------------------

  describe "PreSignedCrl" do
    test "new/1 creates with required fields" do
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      p = PreSignedCrl.new(%{
        issuer_key_id: "key-1",
        valid_from: now,
        valid_until: DateTime.add(now, 86400, :second),
        crl_der: <<0x01, 0x02>>
      })
      assert p.issuer_key_id == "key-1"
      assert p.crl_der == <<0x01, 0x02>>
      assert p.id != nil
    end
  end

  # ---------------------------------------------------------------------------
  # RaCaConnection
  # ---------------------------------------------------------------------------

  describe "RaCaConnection" do
    test "new/1 sets defaults" do
      c = RaCaConnection.new(%{ra_instance_id: "ra-1", ca_instance_id: "ca-1", issuer_key_id: "key-1"})
      assert c.status == "active"
      assert c.id != nil
      assert %DateTime{} = c.inserted_at
    end
  end

  # ---------------------------------------------------------------------------
  # RaInstance
  # ---------------------------------------------------------------------------

  describe "RaInstance" do
    test "new/1 sets defaults" do
      r = RaInstance.new(%{name: "My RA"})
      assert r.name == "My RA"
      assert r.status == "active"
      assert r.metadata == %{}
      assert r.id != nil
    end
  end

  # ---------------------------------------------------------------------------
  # ServiceConfig
  # ---------------------------------------------------------------------------

  describe "ServiceConfig" do
    test "new/1 sets defaults" do
      sc = ServiceConfig.new(%{service_type: "ocsp", url: "http://ocsp.example.com", port: 8080})
      assert sc.service_type == "ocsp"
      assert sc.status == "active"
      assert sc.id != nil
    end
  end

  # ---------------------------------------------------------------------------
  # ApiKey
  # ---------------------------------------------------------------------------

  describe "ApiKey" do
    test "new/1 creates with required fields" do
      ak = ApiKey.new(%{
        ra_instance_id: "ra-1",
        name: "ci-key",
        key_hash: "abc123",
        key_prefix: "sk_"
      })
      assert ak.ra_instance_id == "ra-1"
      assert ak.name == "ci-key"
      assert ak.status == "active"
      assert ak.permissions == ["csr:submit"]
      assert ak.id != nil
    end

    test "new/1 accepts permissions" do
      ak = ApiKey.new(%{ra_instance_id: "ra-1", name: "k", key_hash: "h", key_prefix: "p", permissions: ["csr:submit"]})
      assert ak.permissions == ["csr:submit"]
    end
  end
end
