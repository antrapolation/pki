defmodule PkiValidation.CrlPreSign do
  @moduledoc """
  Pre-signed CRL batch generator. Called at ceremony close when
  `crl_strategy == "pre_signed"`.

  Generates N future CRLs, each covering a distinct `valid_from`/`valid_until`
  window, signs the CRL data using the same Dispatcher path used by
  `CrlPublisher`, and stores each as a `PreSignedCrl` Mnesia record.
  """

  require Logger

  alias PkiMnesia.{Repo, Structs.CertificateStatus, Structs.PreSignedCrl}
  alias PkiCaEngine.KeyStore.Dispatcher

  @crl_validity_overlap_seconds 0

  @doc """
  Signs `count` future CRLs for `issuer_key_id`, each spanning
  `interval_seconds`. The first window starts at `DateTime.utc_now()`,
  the next starts immediately after the previous one ends, and so on.

  Returns `{:ok, [PreSignedCrl.t()]}` or `{:error, reason}`.
  """
  @spec generate_batch(binary(), pos_integer(), pos_integer()) ::
          {:ok, [PreSignedCrl.t()]} | {:error, term()}
  def generate_batch(issuer_key_id, count, interval_seconds)
      when is_binary(issuer_key_id) and is_integer(count) and count > 0 and
             is_integer(interval_seconds) and interval_seconds > 0 do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    with {:ok, revoked_certs} <- fetch_revoked_certs() do
      windows = build_windows(now, count, interval_seconds)

      results =
        Enum.reduce_while(windows, {:ok, []}, fn {valid_from, valid_until}, {:ok, acc} ->
          case sign_and_store(issuer_key_id, valid_from, valid_until, revoked_certs) do
            {:ok, record} -> {:cont, {:ok, [record | acc]}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)

      case results do
        {:ok, records} -> {:ok, Enum.reverse(records)}
        error -> error
      end
    end
  end

  # -- Private helpers --

  defp fetch_revoked_certs do
    case Repo.where(CertificateStatus, fn cs -> cs.status == "revoked" end) do
      {:ok, revoked} ->
        certs =
          revoked
          |> Enum.map(fn cs ->
            %{
              serial_number: cs.serial_number,
              revoked_at: cs.revoked_at,
              reason: cs.revocation_reason
            }
          end)
          |> Enum.sort_by(& &1.revoked_at)

        {:ok, certs}

      {:error, reason} ->
        {:error, {:fetch_revoked_certs_failed, reason}}
    end
  end

  defp build_windows(start_dt, count, interval_seconds) do
    Enum.map(0..(count - 1), fn i ->
      valid_from = DateTime.add(start_dt, i * interval_seconds, :second)
      valid_until = DateTime.add(valid_from, interval_seconds + @crl_validity_overlap_seconds, :second)
      {valid_from, valid_until}
    end)
  end

  defp sign_and_store(issuer_key_id, valid_from, valid_until, revoked_certs) do
    crl_payload = build_crl_payload(valid_from, valid_until, revoked_certs)
    tbs_data = :erlang.term_to_binary(crl_payload)

    case Dispatcher.sign(issuer_key_id, tbs_data) do
      {:ok, signature} ->
        crl_der = :erlang.term_to_binary(Map.put(crl_payload, :signature, signature))
        record = PreSignedCrl.new(%{
          issuer_key_id: issuer_key_id,
          valid_from: valid_from,
          valid_until: valid_until,
          crl_der: crl_der
        })

        case Repo.insert(record) do
          {:ok, stored} -> {:ok, stored}
          {:error, reason} -> {:error, {:store_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:sign_failed, reason}}
    end
  end

  defp build_crl_payload(valid_from, valid_until, revoked_certs) do
    %{
      type: "X509CRL",
      version: 2,
      this_update: DateTime.to_iso8601(valid_from),
      next_update: DateTime.to_iso8601(valid_until),
      revoked_certificates: revoked_certs,
      total_revoked: length(revoked_certs)
    }
  end
end
