defmodule PkiTenant.S3UploadTest do
  use ExUnit.Case, async: true

  alias PkiTenant.S3Upload

  describe "put_object/4 — missing credentials" do
    test "returns {:error, :missing_credentials} when access_key is nil" do
      result = S3Upload.put_object("test-bucket", "test-key", "data", %{
        endpoint: "https://s3.amazonaws.com",
        access_key: nil,
        secret_key: "some-secret",
        region: "us-east-1"
      })

      assert result == {:error, :missing_credentials}
    end

    test "returns {:error, :missing_credentials} when secret_key is nil" do
      result = S3Upload.put_object("test-bucket", "test-key", "data", %{
        endpoint: "https://s3.amazonaws.com",
        access_key: "some-key",
        secret_key: nil,
        region: "us-east-1"
      })

      assert result == {:error, :missing_credentials}
    end

    test "returns {:error, :missing_credentials} when both keys are nil" do
      result = S3Upload.put_object("test-bucket", "test-key", "data", %{
        endpoint: "https://s3.amazonaws.com",
        access_key: nil,
        secret_key: nil,
        region: "us-east-1"
      })

      assert result == {:error, :missing_credentials}
    end
  end

  describe "sign_request/6 — header format" do
    test "generates Authorization header starting with AWS4-HMAC-SHA256" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      )

      auth = Enum.find_value(headers, fn
        {"authorization", v} -> v
        _ -> nil
      end)

      assert auth != nil
      assert String.starts_with?(auth, "AWS4-HMAC-SHA256")
    end

    test "Authorization header contains the access key" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      )

      auth = Enum.find_value(headers, fn
        {"authorization", v} -> v
        _ -> nil
      end)

      assert String.contains?(auth, "AKIAIOSFODNN7EXAMPLE")
    end

    test "includes x-amz-content-sha256 header" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      )

      sha_header = Enum.find_value(headers, fn
        {"x-amz-content-sha256", v} -> v
        _ -> nil
      end)

      assert sha_header != nil
      # SHA-256 of empty string is a known hex value
      assert sha_header == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    end

    test "includes x-amz-date header in ISO8601 compact format" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      )

      date_header = Enum.find_value(headers, fn
        {"x-amz-date", v} -> v
        _ -> nil
      end)

      assert date_header != nil
      # Format: YYYYMMDDTHHMMSSz — 16 chars
      assert String.length(date_header) == 16
      assert String.ends_with?(date_header, "Z")
    end

    test "Authorization header contains Credential, SignedHeaders, and Signature fields" do
      headers = S3Upload.sign_request(
        "PUT",
        "https://s3.amazonaws.com/my-bucket/my-key",
        "hello world",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "ap-southeast-1"
      )

      auth = Enum.find_value(headers, fn
        {"authorization", v} -> v
        _ -> nil
      end)

      assert String.contains?(auth, "Credential=")
      assert String.contains?(auth, "SignedHeaders=")
      assert String.contains?(auth, "Signature=")
      assert String.contains?(auth, "ap-southeast-1")
    end
  end

  describe "put_object/4 — unreachable endpoint" do
    test "returns {:error, reason} when endpoint is unreachable" do
      result = S3Upload.put_object("test-bucket", "test-key", "data", %{
        endpoint: "http://localhost:19999",
        access_key: "test-key",
        secret_key: "test-secret",
        region: "us-east-1"
      })

      assert {:error, _reason} = result
    end
  end
end
