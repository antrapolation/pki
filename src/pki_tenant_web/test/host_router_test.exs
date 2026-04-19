defmodule PkiTenantWeb.HostRouterTest do
  use ExUnit.Case, async: true

  alias PkiTenantWeb.HostRouter

  describe "extract_service/1" do
    test "returns :ca for slug.ca.domain" do
      assert HostRouter.extract_service("acme.ca.example.com") == :ca
    end

    test "returns :ca for slug.ca.domain.tld" do
      assert HostRouter.extract_service("tenant1.ca.pki.local") == :ca
    end

    test "returns :ra for slug.ra.domain" do
      assert HostRouter.extract_service("acme.ra.example.com") == :ra
    end

    test "returns :ra for slug.ra.domain.tld" do
      assert HostRouter.extract_service("tenant1.ra.pki.local") == :ra
    end

    test "returns :ocsp for slug.ocsp.domain" do
      assert HostRouter.extract_service("acme.ocsp.example.com") == :ocsp
    end

    test "returns :ocsp for slug.ocsp.domain.tld" do
      assert HostRouter.extract_service("tenant1.ocsp.straptrust.com") == :ocsp
    end

    test "returns :ca for localhost (dev default)" do
      assert HostRouter.extract_service("localhost") == :ca
    end

    test "returns :unknown for unrecognized host" do
      assert HostRouter.extract_service("random.example.com") == :unknown
    end

    test "returns :unknown for bare IP" do
      assert HostRouter.extract_service("192.168.1.1") == :unknown
    end
  end

  test "init/1 passes opts through" do
    assert HostRouter.init([]) == []
    assert HostRouter.init(foo: :bar) == [foo: :bar]
  end
end
