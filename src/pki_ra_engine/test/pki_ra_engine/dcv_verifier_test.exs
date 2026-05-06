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
end
