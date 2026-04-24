defmodule PkiCaEngine.SubCaAutoSpawnTest do
  @moduledoc """
  Tests for E1.5: auto-spawn sub-CA after self-signed root ceremony completes.

  Two tests:
  1. Full root ceremony → both root IssuerKey and sub-CA IssuerKey are active.
  2. Sub-CA cert chain validates against root cert (issuer signature is valid).
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, KeyCeremony}
  alias PkiCaEngine.CeremonyOrchestrator

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    :ok
  end

  @ca_id "ca-sub-ca-auto-spawn"

  # Run a full root ceremony (initiate → accept shares → execute_keygen).
  # Returns {:ok, %{root_key_id, sub_ca_key_id, root_cert_der}}.
  defp run_full_root_ceremony(ca_id \\ @ca_id) do
    params = %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "Dave",
      is_root: true,
      ceremony_mode: :full,
      initiated_by: "Admin",
      key_alias: "root-key",
      subject_dn: "/CN=Test Root CA/O=PKI Test"
    }

    {:ok, {ceremony, root_key, _shares, _participants, _transcript}} =
      CeremonyOrchestrator.initiate(ca_id, params)

    for name <- ["Alice", "Bob", "Charlie"] do
      {:ok, _} = CeremonyOrchestrator.accept_share(ceremony.id, name, "#{name}-pw")
    end

    passwords = [{"Alice", "Alice-pw"}, {"Bob", "Bob-pw"}, {"Charlie", "Charlie-pw"}]

    {:ok, result} = CeremonyOrchestrator.execute_keygen(ceremony.id, passwords)

    {:ok, %{
      root_key_id: root_key.id,
      sub_ca_key_id: result.sub_ca_key_id,
      ceremony_id: ceremony.id
    }}
  end

  describe "auto-spawn sub-CA after root ceremony" do
    test "both root IssuerKey and sub-CA IssuerKey are active after a full root ceremony" do
      {:ok, %{root_key_id: root_key_id, sub_ca_key_id: sub_ca_key_id}} =
        run_full_root_ceremony()

      # Root IssuerKey must be active with a certificate
      {:ok, root_key} = Repo.get(IssuerKey, root_key_id)
      assert root_key.status == "active",
             "root IssuerKey should be active, got: #{root_key.status}"
      assert root_key.is_root == true
      assert root_key.certificate_der != nil,
             "root IssuerKey should have a certificate_der"
      assert root_key.certificate_pem != nil,
             "root IssuerKey should have a certificate_pem"

      # Sub-CA key ID must be returned and be non-nil
      refute is_nil(sub_ca_key_id),
             "execute_keygen result should contain sub_ca_key_id"

      # Sub-CA IssuerKey must exist in Mnesia and be active
      {:ok, sub_key} = Repo.get(IssuerKey, sub_ca_key_id)
      assert sub_key != nil,
             "sub-CA IssuerKey must be persisted in Mnesia"
      assert sub_key.status == "active",
             "sub-CA IssuerKey should be active, got: #{sub_key.status}"
      assert sub_key.is_root == false,
             "sub-CA IssuerKey must have is_root == false"
      assert sub_key.ca_instance_id == @ca_id,
             "sub-CA must belong to same CA instance"
      assert sub_key.algorithm == "ECC-P256",
             "sub-CA must inherit same algorithm as root"
      assert sub_key.certificate_der != nil,
             "sub-CA IssuerKey must have a certificate_der"
      assert sub_key.certificate_pem != nil,
             "sub-CA IssuerKey must have a certificate_pem"
    end

    test "sub-CA KeyCeremony record is persisted with status completed and auto_spawned marker" do
      {:ok, %{sub_ca_key_id: sub_ca_key_id}} = run_full_root_ceremony()

      refute is_nil(sub_ca_key_id)

      # Find sub-CA ceremony by issuer_key_id
      {:ok, ceremonies} =
        Repo.get_all_by_index(KeyCeremony, :issuer_key_id, sub_ca_key_id)

      assert length(ceremonies) == 1,
             "exactly one KeyCeremony should exist for the sub-CA"

      [sub_ceremony] = ceremonies
      assert sub_ceremony.status == "completed",
             "sub-CA ceremony should be completed"
      assert Map.get(sub_ceremony.domain_info, "auto_spawned") == true,
             "sub-CA ceremony domain_info should have auto_spawned: true"
      assert Map.get(sub_ceremony.domain_info, "is_root") == false,
             "sub-CA ceremony domain_info should have is_root: false"
    end
  end

  describe "sub-CA cert chain validation" do
    test "sub-CA cert signature validates against root public key" do
      {:ok, %{root_key_id: root_key_id, sub_ca_key_id: sub_ca_key_id}} =
        run_full_root_ceremony()

      {:ok, root_key} = Repo.get(IssuerKey, root_key_id)
      {:ok, sub_key} = Repo.get(IssuerKey, sub_ca_key_id)

      root_cert_der = root_key.certificate_der
      sub_cert_der = sub_key.certificate_der

      # Parse sub-CA cert DER: it's a SEQUENCE { TBS, signatureAlg, signature }
      # We verify the signature over TBS using the root public key.
      assert verify_cert_signed_by(sub_cert_der, root_cert_der),
             "sub-CA cert signature must be valid when verified with root public key"
    end

    test "root cert is self-signed (issuer == subject)" do
      {:ok, %{root_key_id: root_key_id}} = run_full_root_ceremony()
      {:ok, root_key} = Repo.get(IssuerKey, root_key_id)

      cert_der = root_key.certificate_der

      # A self-signed cert should verify against itself.
      assert verify_cert_signed_by(cert_der, cert_der),
             "root cert should be self-signed"
    end
  end

  # Verify that `subject_cert_der` was signed by the key in `issuer_cert_der`.
  #
  # Uses the OTP-decoded issuer cert to extract the public key (with its curve
  # OID for ECDSA), then calls :public_key.pkix_verify/2.  For ECDSA the
  # public_key argument must be {ECPoint, {namedCurve, oid}} — assembling that
  # tuple from the OTP-parsed SubjectPublicKeyInfo is the key step.
  defp verify_cert_signed_by(subject_cert_der, issuer_cert_der) do
    try do
      issuer_otp = :public_key.pkix_decode_cert(issuer_cert_der, :otp)
      {:OTPCertificate,
        {:OTPTBSCertificate, _, _, _, _, _, _, issuer_spki, _, _, _},
        _, _} = issuer_otp
      {:OTPSubjectPublicKeyInfo, alg, ec_point} = issuer_spki

      # Build the public_key() argument for pkix_verify:
      # ECDSA — {ECPoint, {namedCurve, oid}} as extracted from the alg params.
      pub_key =
        case alg do
          {:PublicKeyAlgorithm, _ec_oid, {:namedCurve, curve_oid}} ->
            {ec_point, {:namedCurve, curve_oid}}
          _ ->
            # For RSA or other algorithms ec_point IS the key record already.
            ec_point
        end

      :public_key.pkix_verify(subject_cert_der, pub_key)
    rescue
      _e -> false
    end
  end
end
