defmodule PkiRaEngine.DcvVerifierTest do
  use ExUnit.Case, async: true

  alias PkiRaEngine.DcvVerifier

  describe "check_http_01/3 — blocked domains (no network)" do
    test "rejects localhost" do
      assert {:error, msg} = DcvVerifier.check_http_01("localhost", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 127.0.0.1" do
      assert {:error, msg} = DcvVerifier.check_http_01("127.0.0.1", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 0.0.0.0" do
      assert {:error, msg} = DcvVerifier.check_http_01("0.0.0.0", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects ::1 (IPv6 loopback)" do
      assert {:error, msg} = DcvVerifier.check_http_01("::1", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 10.0.0.1 (RFC1918 class A)" do
      assert {:error, msg} = DcvVerifier.check_http_01("10.0.0.1", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 192.168.1.1 (RFC1918 class C)" do
      assert {:error, msg} = DcvVerifier.check_http_01("192.168.1.1", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 172.16.0.1 (RFC1918 class B low)" do
      assert {:error, msg} = DcvVerifier.check_http_01("172.16.0.1", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 172.31.255.255 (RFC1918 class B high)" do
      assert {:error, msg} = DcvVerifier.check_http_01("172.31.255.255", "token", "value")
      assert msg =~ "blocked domain"
    end

    test "rejects 169.254.1.1 (link-local)" do
      assert {:error, msg} = DcvVerifier.check_http_01("169.254.1.1", "token", "value")
      assert msg =~ "blocked domain"
    end

  end

  describe "check_dns_01/2 — error paths" do
    test "returns error when no TXT records found for a domain" do
      # localhost has no _pki-validation TXT records — returns [] from :inet_res
      result = DcvVerifier.check_dns_01("localhost", "sometoken")
      assert {:error, _msg} = result
    end

    test "returns error for another domain with no _pki-validation TXT records" do
      # RFC 2606 .invalid TLD is guaranteed to produce no valid DNS records
      result = DcvVerifier.check_dns_01("test.invalid", "token-value")
      assert {:error, _msg} = result
    end

    test "returns error tuple on DNS lookup failure" do
      # A syntactically invalid domain triggers rescue in check_dns_01
      result = DcvVerifier.check_dns_01("", "token")
      assert {:error, _msg} = result
    end
  end
end
