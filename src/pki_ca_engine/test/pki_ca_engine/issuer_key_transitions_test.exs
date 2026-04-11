defmodule PkiCaEngine.IssuerKeyTransitionsTest do
  @moduledoc """
  Exhaustive state machine transition tests for issuer key status lifecycle.

  Covers UC-CA-21 (issuer key management) and UC-CA-33 (key status transitions).

  Valid transitions:
    pending  -> active     (via update_status or activate_by_certificate)
    pending  -> archived
    active   -> suspended
    active   -> retired
    active   -> archived
    suspended -> active
    suspended -> retired
    suspended -> archived
    retired  -> archived
    archived -> archived   (noop)

  All other transitions must be rejected.
  """
  use PkiCaEngine.DataCase, async: true

  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey, Keystore}

  @statuses ["pending", "active", "suspended", "retired", "archived"]

  setup do
    {:ok, ca} =
      Repo.insert(CaInstance.changeset(%CaInstance{}, %{name: "transitions-ca", created_by: "admin"}))

    {:ok, keystore} =
      Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))

    %{ca: ca, keystore: keystore}
  end

  # Helper to create a key in a specific status by walking through valid transitions
  defp create_key_in_status(ca_id, status) do
    alias_suffix = "#{status}-#{System.unique_integer([:positive])}"
    {:ok, key} = IssuerKeyManagement.create_issuer_key(nil, ca_id, %{key_alias: alias_suffix, algorithm: "RSA-4096"})

    case status do
      "pending" ->
        key

      "active" ->
        {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
        key

      "suspended" ->
        {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
        {:ok, key} = IssuerKeyManagement.update_status(nil, key,"suspended")
        key

      "retired" ->
        {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
        {:ok, key} = IssuerKeyManagement.update_status(nil, key,"retired")
        key

      "archived" ->
        {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")
        key
    end
  end

  # ── Valid transitions ──────────────────────────────────────────────────

  describe "valid transitions via update_status/2" do
    test "pending -> active", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")
      assert {:ok, %IssuerKey{status: "active"}} = IssuerKeyManagement.update_status(nil, key,"active")
    end

    test "pending -> archived", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")
      assert {:ok, %IssuerKey{status: "archived"}} = IssuerKeyManagement.update_status(nil, key,"archived")
    end

    test "active -> suspended", %{ca: ca} do
      key = create_key_in_status(ca.id, "active")
      assert {:ok, %IssuerKey{status: "suspended"}} = IssuerKeyManagement.update_status(nil, key,"suspended")
    end

    test "active -> archived", %{ca: ca} do
      key = create_key_in_status(ca.id, "active")
      assert {:ok, %IssuerKey{status: "archived"}} = IssuerKeyManagement.update_status(nil, key,"archived")
    end

    test "suspended -> active (re-activation)", %{ca: ca} do
      key = create_key_in_status(ca.id, "suspended")
      assert {:ok, %IssuerKey{status: "active"}} = IssuerKeyManagement.update_status(nil, key,"active")
    end

    test "suspended -> archived", %{ca: ca} do
      key = create_key_in_status(ca.id, "suspended")
      assert {:ok, %IssuerKey{status: "archived"}} = IssuerKeyManagement.update_status(nil, key,"archived")
    end

    test "active -> retired", %{ca: ca} do
      key = create_key_in_status(ca.id, "active")
      assert {:ok, %IssuerKey{status: "retired"}} = IssuerKeyManagement.update_status(nil, key,"retired")
    end

    test "suspended -> retired", %{ca: ca} do
      key = create_key_in_status(ca.id, "suspended")
      assert {:ok, %IssuerKey{status: "retired"}} = IssuerKeyManagement.update_status(nil, key,"retired")
    end

    test "retired -> archived", %{ca: ca} do
      key = create_key_in_status(ca.id, "retired")
      assert {:ok, %IssuerKey{status: "archived"}} = IssuerKeyManagement.update_status(nil, key,"archived")
    end

    test "archived -> archived (noop)", %{ca: ca} do
      key = create_key_in_status(ca.id, "archived")
      assert {:ok, %IssuerKey{status: "archived"}} = IssuerKeyManagement.update_status(nil, key,"archived")
    end
  end

  describe "pending -> active via activate_by_certificate/2" do
    test "activates pending key with certificate data", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")

      cert_attrs = %{
        certificate_der: <<0x30, 0x82, 0x01, 0x22>>,
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
      }

      assert {:ok, %IssuerKey{status: "active"} = activated} =
               IssuerKeyManagement.activate_by_certificate(nil, key,cert_attrs)

      assert activated.certificate_der == <<0x30, 0x82, 0x01, 0x22>>
      assert activated.certificate_pem == "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
    end
  end

  # ── Invalid transitions ────────────────────────────────────────────────

  describe "invalid transitions via update_status/2" do
    test "archived -> active is rejected", %{ca: ca} do
      key = create_key_in_status(ca.id, "archived")

      assert {:error, {:invalid_transition, "archived", "active"}} =
               IssuerKeyManagement.update_status(nil, key,"active")
    end

    test "archived -> suspended is rejected", %{ca: ca} do
      key = create_key_in_status(ca.id, "archived")

      assert {:error, {:invalid_transition, "archived", "suspended"}} =
               IssuerKeyManagement.update_status(nil, key,"suspended")
    end

    test "archived -> pending is rejected", %{ca: ca} do
      key = create_key_in_status(ca.id, "archived")

      assert {:error, {:invalid_transition, "archived", "pending"}} =
               IssuerKeyManagement.update_status(nil, key,"pending")
    end

    test "active -> pending is rejected", %{ca: ca} do
      key = create_key_in_status(ca.id, "active")

      assert {:error, {:invalid_transition, "active", "pending"}} =
               IssuerKeyManagement.update_status(nil, key,"pending")
    end

    test "suspended -> pending is rejected", %{ca: ca} do
      key = create_key_in_status(ca.id, "suspended")

      assert {:error, {:invalid_transition, "suspended", "pending"}} =
               IssuerKeyManagement.update_status(nil, key,"pending")
    end

    test "pending -> suspended is rejected", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")

      assert {:error, {:invalid_transition, "pending", "suspended"}} =
               IssuerKeyManagement.update_status(nil, key,"suspended")
    end
  end

  describe "invalid transitions via activate_by_certificate/2" do
    test "active key cannot be activated by certificate", %{ca: ca} do
      key = create_key_in_status(ca.id, "active")

      assert {:error, {:invalid_status, "active"}} =
               IssuerKeyManagement.activate_by_certificate(nil, key,%{
                 certificate_der: <<0x30>>,
                 certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
               })
    end

    test "suspended key cannot be activated by certificate", %{ca: ca} do
      key = create_key_in_status(ca.id, "suspended")

      assert {:error, {:invalid_status, "suspended"}} =
               IssuerKeyManagement.activate_by_certificate(nil, key,%{
                 certificate_der: <<0x30>>,
                 certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
               })
    end

    test "archived key cannot be activated by certificate", %{ca: ca} do
      key = create_key_in_status(ca.id, "archived")

      assert {:error, {:invalid_status, "archived"}} =
               IssuerKeyManagement.activate_by_certificate(nil, key,%{
                 certificate_der: <<0x30>>,
                 certificate_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
               })
    end
  end

  # ── Exhaustive matrix ──────────────────────────────────────────────────

  describe "exhaustive transition matrix via update_status/2" do
    @valid_pairs [
      {"pending", "active"},
      {"pending", "archived"},
      {"active", "suspended"},
      {"active", "retired"},
      {"active", "archived"},
      {"suspended", "active"},
      {"suspended", "retired"},
      {"suspended", "archived"},
      {"retired", "archived"},
      {"archived", "archived"}
    ]

    # Generate a test for every possible (from, to) pair that is NOT in @valid_pairs
    for from <- @statuses, to <- @statuses, {from, to} not in @valid_pairs do
      @from from
      @to to

      test "#{from} -> #{to} is rejected", %{ca: ca} do
        key = create_key_in_status(ca.id, @from)

        assert {:error, {:invalid_transition, @from, @to}} =
                 IssuerKeyManagement.update_status(nil, key,@to)
      end
    end

    # Generate a test for every valid pair to confirm it succeeds
    for {from, to} <- @valid_pairs do
      @from from
      @to to

      test "#{from} -> #{to} succeeds", %{ca: ca} do
        key = create_key_in_status(ca.id, @from)

        assert {:ok, %IssuerKey{status: @to}} =
                 IssuerKeyManagement.update_status(nil, key,@to)
      end
    end
  end

  # ── Multi-step lifecycle paths ─────────────────────────────────────────

  describe "full lifecycle paths" do
    test "pending -> active -> suspended -> active -> archived", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
      assert key.status == "active"

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"suspended")
      assert key.status == "suspended"

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
      assert key.status == "active"

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")
      assert key.status == "archived"
    end

    test "pending -> active -> archived (direct archive from active)", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
      assert key.status == "active"

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")
      assert key.status == "archived"
    end

    test "pending -> archived (immediate archive)", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")
      assert key.status == "archived"
    end

    test "multiple suspend/activate cycles before archive", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")
      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")

      # Cycle suspend/active three times
      for _i <- 1..3, reduce: key do
        acc ->
          {:ok, suspended} = IssuerKeyManagement.update_status(nil, acc,"suspended")
          assert suspended.status == "suspended"
          {:ok, reactivated} = IssuerKeyManagement.update_status(nil, suspended,"active")
          assert reactivated.status == "active"
          reactivated
      end
      |> then(fn key ->
        {:ok, archived} = IssuerKeyManagement.update_status(nil, key,"archived")
        assert archived.status == "archived"
      end)
    end

    test "pending -> active -> retired -> archived (retirement lifecycle)", %{ca: ca} do
      key = create_key_in_status(ca.id, "pending")

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"active")
      assert key.status == "active"

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"retired")
      assert key.status == "retired"

      {:ok, key} = IssuerKeyManagement.update_status(nil, key,"archived")
      assert key.status == "archived"
    end

    test "retired -> active is rejected (retirement is irreversible)", %{ca: ca} do
      key = create_key_in_status(ca.id, "retired")

      assert {:error, {:invalid_transition, "retired", "active"}} =
               IssuerKeyManagement.update_status(nil, key,"active")
    end

    test "archived is terminal - no further transitions except self", %{ca: ca} do
      key = create_key_in_status(ca.id, "archived")

      # Confirm every non-archived target is rejected
      for target <- ["pending", "active", "suspended"] do
        assert {:error, {:invalid_transition, "archived", ^target}} =
                 IssuerKeyManagement.update_status(nil, key,target)
      end

      # Only archived -> archived is allowed
      assert {:ok, %IssuerKey{status: "archived"}} =
               IssuerKeyManagement.update_status(nil, key,"archived")
    end
  end
end
