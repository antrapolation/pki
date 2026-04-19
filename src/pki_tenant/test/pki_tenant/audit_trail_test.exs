defmodule PkiTenant.AuditTrailTest do
  @moduledoc "Mnesia-era tests for PkiTenant.AuditTrail."
  use ExUnit.Case, async: false

  alias PkiMnesia.TestHelper
  alias PkiTenant.AuditTrail

  setup do
    dir = TestHelper.setup_mnesia()
    on_exit(fn -> TestHelper.teardown_mnesia(dir) end)
    :ok
  end

  describe "record/2" do
    test "persists an entry with derived category" do
      assert {:ok, entry} = AuditTrail.record("ceremony_initiated", %{actor: "alice"})
      assert entry.action == "ceremony_initiated"
      assert entry.category == "ca_operations"
      assert entry.actor == "alice"
    end

    test "accepts an explicit category" do
      {:ok, entry} =
        AuditTrail.record("custom_action", %{category: "custom", actor: "bob"})

      assert entry.category == "custom"
    end

    test "defaults actor to \"system\"" do
      {:ok, entry} = AuditTrail.record("keystore_configured", %{})
      assert entry.actor == "system"
    end

    test "moves non-meta keys into metadata" do
      {:ok, entry} =
        AuditTrail.record("user_created", %{
          actor: "admin",
          actor_role: "ca_admin",
          username: "x",
          role: "auditor"
        })

      assert entry.actor == "admin"
      assert entry.actor_role == "ca_admin"
      assert entry.metadata == %{username: "x", role: "auditor"}
    end
  end

  describe "list_events/1" do
    setup do
      {:ok, a} = AuditTrail.record("ceremony_initiated", %{actor: "alice"})
      {:ok, b} = AuditTrail.record("user_created", %{actor: "admin"})
      {:ok, c} = AuditTrail.record("login_failed", %{actor: "bob"})

      # Age `a` backwards so sort has something to do.
      :ok = backdate(a.id, DateTime.add(DateTime.utc_now(), -60, :second))

      {:ok, a: a, b: b, c: c}
    end

    test "returns events newest first" do
      events = AuditTrail.list_events()
      assert length(events) == 3
      [first | _] = events
      assert first.action in ["user_created", "login_failed"]
    end

    test "filters by category" do
      events = AuditTrail.list_events(category: "ca_operations")
      actions = Enum.map(events, & &1.action) |> Enum.sort()
      assert actions == ["ceremony_initiated"]
    end

    test "filters by action (exact)" do
      events = AuditTrail.list_events(action: "login_failed")
      assert length(events) == 1
    end

    test "filters by actor substring" do
      events = AuditTrail.list_events(actor: "ali")
      assert length(events) == 1
    end

    test "date_from is inclusive" do
      today = Date.utc_today()
      events = AuditTrail.list_events(date_from: Date.to_iso8601(today))
      assert length(events) >= 1
    end
  end

  describe "infer_category/1" do
    test "maps common prefixes" do
      assert AuditTrail.infer_category("ceremony_initiated") == "ca_operations"
      assert AuditTrail.infer_category("user_created") == "user_management"
      assert AuditTrail.infer_category("csr_submitted") == "ra_operations"
      assert AuditTrail.infer_category("something_else") == "general"
    end
  end

  # --- helpers ---

  defp backdate(id, new_timestamp) do
    :mnesia.transaction(fn ->
      [record] = :mnesia.read({:audit_log_entries, id})
      # record is {:audit_log_entries, id, timestamp, action, category, actor, actor_role, metadata}
      updated = put_elem(record, 2, new_timestamp)
      :mnesia.write(updated)
    end)

    :ok
  end
end
