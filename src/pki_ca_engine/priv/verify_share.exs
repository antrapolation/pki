#!/usr/bin/env elixir
#
# verify_share.exs — Offline custodian share-signature verifier
#
# Usage:
#   elixir verify_share.exs <share_hex> <signature_hex> <ceremony_id> [app_secret]
#
# Arguments:
#   share_hex     Hex-encoded encrypted_share bytes (as stored in the DB)
#   signature_hex Hex-encoded share_signature bytes (as stored in the DB)
#   ceremony_id   The ceremony ID string (UUID)
#   app_secret    Optional: the ceremony_signing_secret (defaults to "dev-only-secret")
#
# Exit codes:
#   0  — signature valid
#   1  — signature invalid
#   2  — usage error
#
# This script is intentionally dependency-free (pure Erlang/OTP crypto) so it
# can be run on an air-gapped machine that has only Elixir/Erlang installed.
#

defmodule VerifyShare do
  @hmac_algo :sha256

  def run(args) do
    case parse_args(args) do
      {:ok, share_bin, sig_bin, ceremony_id, app_secret} ->
        signing_key = :crypto.mac(:hmac, @hmac_algo, app_secret, ceremony_id)
        expected    = :crypto.mac(:hmac, @hmac_algo, signing_key, share_bin)

        if constant_time_equal?(expected, sig_bin) do
          IO.puts("OK — signature is valid for ceremony #{ceremony_id}")
          System.halt(0)
        else
          IO.puts(:stderr, "FAIL — signature is INVALID for ceremony #{ceremony_id}")
          System.halt(1)
        end

      {:error, msg} ->
        IO.puts(:stderr, "Error: #{msg}")
        IO.puts(:stderr, """

        Usage: elixir verify_share.exs <share_hex> <signature_hex> <ceremony_id> [app_secret]

          share_hex     Hex-encoded encrypted share bytes
          signature_hex Hex-encoded 32-byte HMAC-SHA256 signature
          ceremony_id   Ceremony UUID string
          app_secret    (optional) signing secret; defaults to "dev-only-secret"
        """)
        System.halt(2)
    end
  end

  defp parse_args([share_hex, sig_hex, ceremony_id | rest]) do
    app_secret = List.first(rest) || "dev-only-secret"

    with {:ok, share_bin} <- hex_decode(share_hex, "share_hex"),
         {:ok, sig_bin}   <- hex_decode(sig_hex,   "signature_hex") do
      {:ok, share_bin, sig_bin, ceremony_id, app_secret}
    end
  end

  defp parse_args(_), do: {:error, "expected at least 3 arguments"}

  defp hex_decode(hex, label) do
    case Base.decode16(String.upcase(hex)) do
      {:ok, bin} -> {:ok, bin}
      :error     -> {:error, "#{label} is not valid hex"}
    end
  end

  # Constant-time comparison — same length always because both are HMAC-SHA256 output.
  defp constant_time_equal?(a, b) when byte_size(a) != byte_size(b), do: false
  defp constant_time_equal?(a, b), do: :crypto.hash_equals(a, b)
end

VerifyShare.run(System.argv())
