defmodule PkiTenant.S3Upload do
  @moduledoc """
  S3-compatible object upload using AWS Signature V4 via Req.
  No ex_aws dependency — minimal implementation for backup uploads.
  """

  require Logger

  @doc """
  Upload binary data to an S3-compatible bucket.

  opts is a map with keys:
    :endpoint    - S3 endpoint URL (default "https://s3.amazonaws.com")
    :access_key  - AWS access key ID
    :secret_key  - AWS secret access key
    :region      - AWS region (default "us-east-1")

  Returns :ok | {:error, reason}.
  """
  def put_object(bucket, key, body, opts) do
    endpoint = Map.get(opts, :endpoint, "https://s3.amazonaws.com")
    access_key = Map.get(opts, :access_key)
    secret_key = Map.get(opts, :secret_key)
    region = Map.get(opts, :region, "us-east-1")

    if is_nil(access_key) or is_nil(secret_key) do
      {:error, :missing_credentials}
    else
      url = "#{endpoint}/#{bucket}/#{key}"
      headers = sign_request("PUT", url, body, access_key, secret_key, region)

      case Req.put(url, body: body, headers: headers, receive_timeout: 120_000) do
        {:ok, %{status: status}} when status in 200..299 ->
          Logger.info("[s3_upload] Uploaded #{bucket}/#{key} (#{byte_size(body)} bytes)")
          :ok

        {:ok, %{status: status, body: resp_body}} ->
          Logger.error("[s3_upload] Upload failed: HTTP #{status} — #{inspect(resp_body)}")
          {:error, {:http_error, status, resp_body}}

        {:error, reason} ->
          Logger.error("[s3_upload] Upload failed: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  @doc """
  Generate AWS Signature V4 headers for an S3 request.
  Returns a list of {header_name, header_value} tuples.

  Exposed as a public function so callers can test signature generation
  without making a real HTTP request.
  """
  def sign_request(method, url, body, access_key, secret_key, region \\ "us-east-1") do
    service = "s3"
    uri = URI.parse(url)
    now = DateTime.utc_now()
    date_stamp = Calendar.strftime(now, "%Y%m%d")
    amz_date = Calendar.strftime(now, "%Y%m%dT%H%M%SZ")

    host = uri.host
    path = uri.path || "/"

    payload_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)

    headers_to_sign = [
      {"host", host},
      {"x-amz-content-sha256", payload_hash},
      {"x-amz-date", amz_date}
    ]

    signed_header_names = headers_to_sign |> Enum.map(&elem(&1, 0)) |> Enum.join(";")

    canonical_headers =
      headers_to_sign
      |> Enum.map(fn {k, v} -> "#{k}:#{v}\n" end)
      |> Enum.join()

    canonical_request =
      Enum.join(
        [
          String.upcase(method),
          path,
          # query string (empty)
          "",
          canonical_headers,
          signed_header_names,
          payload_hash
        ],
        "\n"
      )

    credential_scope = "#{date_stamp}/#{region}/#{service}/aws4_request"

    string_to_sign =
      Enum.join(
        [
          "AWS4-HMAC-SHA256",
          amz_date,
          credential_scope,
          :crypto.hash(:sha256, canonical_request) |> Base.encode16(case: :lower)
        ],
        "\n"
      )

    signing_key =
      "AWS4#{secret_key}"
      |> hmac_sha256(date_stamp)
      |> hmac_sha256(region)
      |> hmac_sha256(service)
      |> hmac_sha256("aws4_request")

    signature = hmac_sha256(signing_key, string_to_sign) |> Base.encode16(case: :lower)

    authorization =
      "AWS4-HMAC-SHA256 Credential=#{access_key}/#{credential_scope}, SignedHeaders=#{signed_header_names}, Signature=#{signature}"

    [
      {"authorization", authorization},
      {"x-amz-content-sha256", payload_hash},
      {"x-amz-date", amz_date}
    ]
  end

  defp hmac_sha256(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end
end
