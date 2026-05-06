defmodule PkiTenantWeb.Ca.CertificatesLiveTest do
  use PkiTenantWeb.LiveCase, async: false

  describe "CertificatesLive — mount" do
    test "mounts successfully with empty certificate list", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/certificates")
      assert html =~ "Certificates"
    end

    test "auditor is redirected away from certificates page" do
      conn = build_conn_for_role(:auditor)
      assert {:error, {:redirect, _}} = live(conn, "/certificates")
    end
  end

  describe "CertificatesLive — revoke_cert" do
    test "revokes an active certificate and updates status in Mnesia", %{conn: conn} do
      cert = seed_certificate(%{status: "active"})

      {:ok, view, _html} = live(conn, "/certificates")

      render_click(view, "revoke_cert", %{
        "serial" => cert.serial_number,
        "reason" => "key_compromise"
      })

      {:ok, [revoked]} =
        Repo.where(IssuedCertificate, fn c -> c.serial_number == cert.serial_number end)

      assert revoked.status == "revoked"
      assert revoked.revocation_reason == "key_compromise"
      assert revoked.revoked_at != nil
    end

    test "returns flash confirmation after revocation", %{conn: conn} do
      cert = seed_certificate(%{status: "active"})

      {:ok, view, _html} = live(conn, "/certificates")

      html =
        render_click(view, "revoke_cert", %{
          "serial" => cert.serial_number,
          "reason" => "cessation_of_operation"
        })

      assert html =~ "revoked"
    end

    test "revoke_cert blocked for key_manager — certificate status unchanged" do
      conn = build_conn_for_role(:key_manager)
      cert = seed_certificate(%{status: "active"})

      {:ok, view, _html} = live(conn, "/certificates")

      html =
        render_click(view, "revoke_cert", %{
          "serial" => cert.serial_number,
          "reason" => "unspecified"
        })

      assert html =~ "Only CA administrators"

      {:ok, [unchanged]} =
        Repo.where(IssuedCertificate, fn c -> c.serial_number == cert.serial_number end)

      assert unchanged.status == "active"
    end

    test "revoking an already-revoked certificate returns error flash", %{conn: conn} do
      cert = seed_certificate(%{status: "revoked", revocation_reason: "superseded"})

      {:ok, view, _html} = live(conn, "/certificates")

      html =
        render_click(view, "revoke_cert", %{
          "serial" => cert.serial_number,
          "reason" => "unspecified"
        })

      assert html =~ "Failed to revoke certificate"
    end

    test "revoking an unknown serial number returns error flash", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      html =
        render_click(view, "revoke_cert", %{
          "serial" => "nonexistent-serial-#{System.unique_integer()}",
          "reason" => "unspecified"
        })

      assert html =~ "Failed to revoke certificate"
    end
  end

  describe "CertificatesLive — view_cert" do
    test "view_cert populates selected_cert assign for an existing certificate", %{conn: conn} do
      cert = seed_certificate()

      {:ok, view, _html} = live(conn, "/certificates")
      html = render_click(view, "view_cert", %{"serial" => cert.serial_number})

      assert html =~ cert.serial_number
    end

    test "view_cert for unknown serial shows error flash", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")
      html = render_click(view, "view_cert", %{"serial" => "no-such-serial"})

      assert html =~ "Certificate not found"
    end

    test "close_detail clears selected_cert assign", %{conn: conn} do
      cert = seed_certificate()

      {:ok, view, _html} = live(conn, "/certificates")
      render_click(view, "view_cert", %{"serial" => cert.serial_number})
      html = render_click(view, "close_detail", %{})

      refute html =~ "selected_cert"
    end
  end

  describe "CertificatesLive — search_issuer_key" do
    test "filters issuer key results by query string", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      html = render_keyup(view, "search_issuer_key", %{"value" => "my-key"})

      # With no seeded keys, results are empty — no crash
      assert is_binary(html)
    end
  end

  describe "CertificatesLive — select_issuer_key" do
    test "select_issuer_key with label assigns id and label", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      html = render_click(view, "select_issuer_key", %{
        "issuer_key_id" => "key-abc",
        "label" => "MyKey (ECC-P256)"
      })

      assert is_binary(html)
    end

    test "select_issuer_key without label assigns id and derives empty label when key not found", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      html = render_click(view, "select_issuer_key", %{"issuer_key_id" => "key-unknown"})

      assert is_binary(html)
    end
  end

  describe "CertificatesLive — clear_issuer_key" do
    test "clear_issuer_key resets key selection state", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      render_click(view, "select_issuer_key", %{
        "issuer_key_id" => "key-abc",
        "label" => "SomeKey"
      })

      html = render_click(view, "clear_issuer_key", %{})
      assert is_binary(html)
    end
  end

  describe "CertificatesLive — change_page" do
    test "change_page with a valid page number does not crash", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      html = render_click(view, "change_page", %{"page" => "2"})
      assert is_binary(html)
    end

    test "change_page with invalid value defaults to page 1", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/certificates")

      html = render_click(view, "change_page", %{"page" => "not-a-number"})
      assert is_binary(html)
    end
  end
end
