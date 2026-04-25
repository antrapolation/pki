defmodule PkiCaEngine.AuditorTranscriptSigningTest do
  @moduledoc """
  E4.2 — Tests for auditor digital signature over the ceremony transcript.

  Generates a real Ed25519 key pair and exercises both the happy path and
  the wrong-signature rejection path end-to-end through Mnesia.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiCaEngine.CeremonyOrchestrator
  alias PkiMnesia.Structs.CeremonyTranscript

  # -----------------------------------------------------------------------
  # Test setup: real Mnesia instance + Ed25519 key pair
  # -----------------------------------------------------------------------

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    # Generate a real Ed25519 key pair for the test.
    # :crypto.generate_key/2 with :eddsa/:ed25519 returns {pub_bytes, priv_bytes}.
    {pub_bytes, priv_bytes} = :crypto.generate_key(:eddsa, :ed25519)

    # Wrap the raw bytes into the OTP public-key PEM form (SubjectPublicKeyInfo).
    pub_der = :public_key.der_encode(
      :SubjectPublicKeyInfo,
      {:SubjectPublicKeyInfo,
       {:AlgorithmIdentifier, {1, 3, 101, 112}, :asn1_NOVALUE},
       pub_bytes}
    )
    pub_pem = :public_key.pem_encode([{:SubjectPublicKeyInfo, pub_der, :not_encrypted}])

    %{pub_pem: pub_pem, pub_bytes: pub_bytes, priv_bytes: priv_bytes}
  end

  # -----------------------------------------------------------------------
  # Helpers
  # -----------------------------------------------------------------------

  # Build a ceremony with a transcript and a few entries, returning the ceremony_id.
  defp setup_ceremony(_ctx) do
    params = %{
      algorithm: "ECC-P256",
      threshold_k: 2,
      threshold_n: 3,
      custodian_names: ["Alice", "Bob", "Charlie"],
      auditor_name: "Dave",
      is_root: true,
      ceremony_mode: :full,
      initiated_by: "Admin",
      key_alias: "test-root-key-#{:erlang.unique_integer([:positive])}",
      subject_dn: "/CN=Test Root CA"
    }

    {:ok, {ceremony, _key, _shares, _participants, _transcript}} =
      CeremonyOrchestrator.initiate("ca-e42", params)

    ceremony.id
  end

  # Sign the transcript entries digest with an Ed25519 private key.
  # Uses :erlang.term_to_binary to match CeremonyTranscript.transcript_digest/1,
  # which avoids JSON-encoding failures on raw binary prev_hash/event_hash fields.
  defp sign_digest(entries, priv_bytes) do
    digest = :crypto.hash(:sha256, :erlang.term_to_binary(entries))
    :crypto.sign(:eddsa, :none, digest, [priv_bytes, :ed25519])
  end

  # -----------------------------------------------------------------------
  # Tests
  # -----------------------------------------------------------------------

  describe "register_auditor_key/2 + record_auditor_signature/3" do
    test "valid key + correct signature → :ok, verify_auditor_signature passes", ctx do
      ceremony_id = setup_ceremony(ctx)

      # Step 1: register the public key
      assert {:ok, _transcript} =
               CeremonyOrchestrator.register_auditor_key(ceremony_id, ctx.pub_pem)

      # Step 2: retrieve fresh transcript to get current entries
      {:ok, transcript} = CeremonyOrchestrator.get_transcript(ceremony_id)
      sig = sign_digest(transcript.entries, ctx.priv_bytes)

      # Step 3: submit the signature
      assert {:ok, updated_transcript} =
               CeremonyOrchestrator.record_auditor_signature(ceremony_id, ctx.pub_pem, sig)

      # signed_at must be populated
      assert updated_transcript.signed_at != nil

      # verify_auditor_signature/1 must pass
      assert :ok = CeremonyTranscript.verify_auditor_signature(updated_transcript)

      # The transcript should have an "auditor_signed" event
      actions = Enum.map(updated_transcript.entries, fn e -> e["action"] end)
      assert "auditor_signed" in actions
    end

    test "valid key + wrong signature → {:error, :invalid_signature}", ctx do
      ceremony_id = setup_ceremony(ctx)

      assert {:ok, _transcript} =
               CeremonyOrchestrator.register_auditor_key(ceremony_id, ctx.pub_pem)

      wrong_sig = :crypto.strong_rand_bytes(64)

      assert {:error, :invalid_signature} =
               CeremonyOrchestrator.record_auditor_signature(ceremony_id, ctx.pub_pem, wrong_sig)
    end
  end

  describe "CeremonyTranscript.verify_auditor_signature/1" do
    test "verifies a correct Ed25519 signature using raw public key bytes", ctx do
      entries = [
        %{
          "timestamp" => "2026-01-01T00:00:00Z",
          "actor" => "auditor",
          "action" => "ceremony_initiated",
          "details" => %{}
        }
      ]

      digest = :crypto.hash(:sha256, :erlang.term_to_binary(entries))
      sig = :crypto.sign(:eddsa, :none, digest, [ctx.priv_bytes, :ed25519])

      # Raw 32-byte key — CeremonyTranscript accepts this as a convenience
      transcript = %CeremonyTranscript{
        id: "t-1",
        ceremony_id: "c-1",
        entries: entries,
        auditor_public_key: ctx.pub_bytes,
        auditor_signature: sig,
        signed_at: DateTime.utc_now(),
        inserted_at: DateTime.utc_now(),
        finalized_at: nil
      }

      assert :ok = CeremonyTranscript.verify_auditor_signature(transcript)
    end

    test "rejects a mismatched signature", ctx do
      entries = [%{"timestamp" => "2026-01-01T00:00:00Z", "actor" => "a", "action" => "b", "details" => %{}}]

      transcript = %CeremonyTranscript{
        id: "t-2",
        ceremony_id: "c-2",
        entries: entries,
        auditor_public_key: ctx.pub_bytes,
        auditor_signature: :crypto.strong_rand_bytes(64),
        signed_at: DateTime.utc_now(),
        inserted_at: DateTime.utc_now(),
        finalized_at: nil
      }

      assert {:error, :invalid_signature} =
               CeremonyTranscript.verify_auditor_signature(transcript)
    end
  end

  # -----------------------------------------------------------------------
  # ECDSA P-256 round-trip (H1 regression test)
  # The H1 fix changed ECDSA verify from double-SHA-256 (broken) to
  # single-SHA-256 by passing raw_bytes + :sha256 to :public_key.verify.
  # This test confirms the ECDSA path round-trips correctly.
  # -----------------------------------------------------------------------

  describe "ECDSA P-256 auditor signature round-trip" do
    test "valid ECDSA P-256 signature verifies correctly" do
      # Generate an ECDSA P-256 key pair
      {pub_point, priv_key} = :crypto.generate_key(:ecdh, :secp256r1)

      # Build the SubjectPublicKeyInfo DER for P-256
      ec_pub_der = :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo,
         {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
         pub_point}
      )
      ec_pub_pem = :public_key.pem_encode([{:SubjectPublicKeyInfo, ec_pub_der, :not_encrypted}])

      entries = [%{
        "timestamp" => "2026-01-01T00:00:00Z",
        "actor" => "auditor",
        "action" => "ceremony_initiated",
        "details" => %{}
      }]

      # Compute the digest the same way verify_auditor_signature does:
      # raw_bytes = :erlang.term_to_binary(entries)
      # OTP will compute SHA-256(raw_bytes) internally when :sha256 is given.
      raw_bytes = :erlang.term_to_binary(entries)

      # Sign with ECDSA P-256 using SHA-256 (OTP will hash raw_bytes once)
      ec_priv_key = :public_key.der_decode(
        :ECPrivateKey,
        :public_key.der_encode(:ECPrivateKey,
          {:ECPrivateKey, 1, priv_key,
           {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
           pub_point, :asn1_NOVALUE})
      )
      signature = :public_key.sign(raw_bytes, :sha256, ec_priv_key)

      transcript = %CeremonyTranscript{
        id: "ecdsa-test",
        ceremony_id: "ecdsa-ceremony",
        entries: entries,
        auditor_public_key: ec_pub_pem,
        auditor_signature: signature,
        signed_at: DateTime.utc_now(),
        inserted_at: DateTime.utc_now(),
        finalized_at: nil
      }

      assert :ok = CeremonyTranscript.verify_auditor_signature(transcript)
    end

    test "ECDSA P-256 wrong signature returns {:error, :invalid_signature}" do
      {pub_point, _priv_key} = :crypto.generate_key(:ecdh, :secp256r1)

      ec_pub_der = :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo,
         {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
         pub_point}
      )
      ec_pub_pem = :public_key.pem_encode([{:SubjectPublicKeyInfo, ec_pub_der, :not_encrypted}])

      entries = [%{"timestamp" => "2026-01-01T00:00:00Z", "actor" => "a", "action" => "b", "details" => %{}}]

      transcript = %CeremonyTranscript{
        id: "ecdsa-bad",
        ceremony_id: "ecdsa-bad-ceremony",
        entries: entries,
        auditor_public_key: ec_pub_pem,
        auditor_signature: :crypto.strong_rand_bytes(72),
        signed_at: DateTime.utc_now(),
        inserted_at: DateTime.utc_now(),
        finalized_at: nil
      }

      assert {:error, :invalid_signature} =
               CeremonyTranscript.verify_auditor_signature(transcript)
    end
  end
end
