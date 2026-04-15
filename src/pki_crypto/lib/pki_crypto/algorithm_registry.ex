defmodule PkiCrypto.AlgorithmRegistry do
  @moduledoc """
  OID-aware metadata registry for X.509 cert/CSR emission and parsing.

  Complements `PkiCrypto.Registry` (which maps algorithm name strings to
  protocol-implementing structs for sign/verify dispatch) by adding the
  metadata X.509 emission needs: OIDs for `signatureAlgorithm` and
  `subjectPublicKeyInfo`, algorithm family (for code branching), and the
  `PkiCrypto.Registry` id used to reach the signing primitives.

  OIDs are overridable via `Application.get_env(:pki_crypto, :oid_overrides, %{})`
  keyed by algorithm id string — this lets deployments swap private OIDs
  (e.g. KAZ-SIGN placeholder → real Antrapol PEN) without code changes.

  ## Example

      iex> PkiCrypto.AlgorithmRegistry.by_id("ECC-P256")
      {:ok, %{id: "ECC-P256", family: :ecdsa,
              sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2}, ...}}
  """

  @type algorithm_id :: String.t()
  @type oid :: :erlang.tuple()
  @type family :: :rsa | :ecdsa | :ml_dsa | :kaz_sign | :slh_dsa

  @type entry :: %{
          id: algorithm_id(),
          family: family(),
          sig_alg_oid: oid(),
          public_key_oid: oid()
        }

  # Defaults. OIDs here can be overridden per-id via config — see oid/1.
  @defaults %{
    "RSA-2048" => %{
      family: :rsa,
      sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11},
      public_key_oid: {1, 2, 840, 113549, 1, 1, 1}
    },
    "RSA-4096" => %{
      family: :rsa,
      sig_alg_oid: {1, 2, 840, 113549, 1, 1, 11},
      public_key_oid: {1, 2, 840, 113549, 1, 1, 1}
    },
    "ECC-P256" => %{
      family: :ecdsa,
      sig_alg_oid: {1, 2, 840, 10045, 4, 3, 2},
      public_key_oid: {1, 2, 840, 10045, 2, 1}
    },
    "ECC-P384" => %{
      family: :ecdsa,
      sig_alg_oid: {1, 2, 840, 10045, 4, 3, 3},
      public_key_oid: {1, 2, 840, 10045, 2, 1}
    }
  }

  @doc "Look up an algorithm entry by its id string."
  @spec by_id(algorithm_id()) :: {:ok, entry()} | :error
  def by_id(id) when is_binary(id) do
    case Map.fetch(@defaults, id) do
      {:ok, base} -> {:ok, Map.merge(%{id: id}, apply_overrides(id, base))}
      :error -> :error
    end
  end

  @doc "Look up an algorithm entry by the signatureAlgorithm OID."
  @spec by_oid(oid()) :: {:ok, entry()} | :error
  def by_oid(oid) when is_tuple(oid) do
    Enum.find_value(@defaults, :error, fn {id, _base} ->
      {:ok, entry} = by_id(id)
      if entry.sig_alg_oid == oid, do: {:ok, entry}, else: nil
    end)
  end

  # --- Private ---

  defp apply_overrides(id, base) do
    overrides = Application.get_env(:pki_crypto, :oid_overrides, %{})

    case Map.get(overrides, id) do
      nil -> base
      custom when is_map(custom) -> Map.merge(base, Map.take(custom, [:sig_alg_oid, :public_key_oid]))
    end
  end
end
