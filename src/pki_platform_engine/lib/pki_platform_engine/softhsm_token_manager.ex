defmodule PkiPlatformEngine.SofthsmTokenManager do
  @moduledoc """
  Per-tenant SoftHSM2 token initialization (task #22, first increment).

  Each tenant gets its own SoftHSM directory (`<base>/<slug>/`) with a
  dedicated `softhsm2.conf`, a single initialized slot, and
  randomly-generated USER / SO PINs. This gives per-tenant PKCS#11
  isolation: tenant A can't touch tenant B's token objects.

  ## PIN custody

  Two modes, chosen automatically:

  1. **Encrypted envelope (production).** When
     `PkiPlatformEngine.SecretManager.master_key/0` returns a key
     AND the caller passes `tenant_id:`, the generated PINs are
     wrapped via `PkiPlatformEngine.SofthsmPinCustody.wrap/3` and
     returned as `pin_envelope`. No `.pins` file is written.
     Callers persist the envelope in `tenants.metadata` and
     decrypt on demand via `SofthsmPinCustody.unwrap/2`.

  2. **Plaintext `.pins` file (dev / fallback).** If there's no
     master key configured, or no `tenant_id` supplied, PINs land
     in `<tenant_dir>/.pins` (mode 0600) and a warning is logged.
     Never safe for production.

  Callers always get plaintext `user_pin` / `so_pin` in the return
  map for this step's immediate use (writing config, login smoke
  test). Long-term storage is either the envelope or the file —
  never both.

  ## Availability

  If `softhsm2-util` isn't on `PATH`, `init_tenant_token/2` returns
  `{:ok, :skipped}` so the wizard continues — this keeps dev boxes
  without SoftHSM installed unblocked. Tests that need real tokens
  should key off `available?/0` (or use the `:softhsm` ExUnit tag
  that's already in the default-exclude list).
  """
  require Logger

  @default_base_dir_env "PKI_SOFTHSM_BASE"
  @default_base_dir "/tmp/pki-softhsm-tokens"

  @doc """
  Returns true iff the `softhsm2-util` binary is on PATH. Callers
  should branch on this before relying on token-backed features.
  """
  @spec available?() :: boolean()
  def available? do
    System.find_executable("softhsm2-util") != nil
  end

  @doc """
  Initialise a dedicated SoftHSM2 token for `slug`.

  Options:

    * `:base_dir` — override the directory root (default:
      `$PKI_SOFTHSM_BASE` or `/tmp/pki-softhsm-tokens`).
    * `:label` — token label (default: `"tenant-<slug>"`).
    * `:user_pin` / `:so_pin` — override the generated PINs
      (intended for tests).

  Returns `{:ok, info}` with keys:

    * `:conf_path` — absolute path to the per-tenant `softhsm2.conf`.
    * `:tenant_dir` — the token directory.
    * `:slot_id` — slot assigned by softhsm2-util after init.
    * `:label` — the token label used.
    * `:user_pin` / `:so_pin` — generated (or passed) PINs.
    * `:library_path` — path to `libsofthsm2.so` detected from the
      OS (so the tenant admin can wire an HSM keystore directly).

  Returns `{:ok, :skipped}` when softhsm2-util is not on PATH.
  Returns `{:error, reason}` on any other failure.
  """
  @spec init_tenant_token(String.t(), keyword()) ::
          {:ok, map()} | {:ok, :skipped} | {:error, term()}
  def init_tenant_token(slug, opts \\ []) do
    if available?() do
      do_init_tenant_token(slug, opts)
    else
      Logger.info("[softhsm] softhsm2-util not on PATH — skipping token init for #{slug}")
      {:ok, :skipped}
    end
  end

  @doc """
  Remove a tenant's token directory (and PIN file). Idempotent —
  a missing directory is not an error. Intended to run in the
  tenant-delete path.
  """
  @spec cleanup_tenant_token(String.t(), keyword()) :: :ok
  def cleanup_tenant_token(slug, opts \\ []) do
    tenant_dir = Path.join(base_dir(opts), slug)

    case File.rm_rf(tenant_dir) do
      {:ok, _} ->
        Logger.info("[softhsm] Cleaned up token dir for #{slug}")
        :ok

      {:error, reason, path} ->
        Logger.warning("[softhsm] Failed to clean up #{path} for #{slug}: #{inspect(reason)}")
        :ok
    end
  end

  # --- Private -----------------------------------------------------------

  defp do_init_tenant_token(slug, opts) do
    tenant_dir = Path.join(base_dir(opts), slug)
    conf_path = Path.join(tenant_dir, "softhsm2.conf")
    label = Keyword.get(opts, :label, "tenant-#{slug}")
    user_pin = Keyword.get(opts, :user_pin, generate_pin())
    so_pin = Keyword.get(opts, :so_pin, generate_pin(12))
    tenant_id = Keyword.get(opts, :tenant_id)

    with :ok <- File.mkdir_p(tenant_dir),
         :ok <- write_conf(conf_path, tenant_dir),
         {:ok, _} <- run_init_token(conf_path, label, user_pin, so_pin),
         {:ok, slot_id} <- detect_slot(conf_path, label),
         {:ok, pin_envelope} <- store_pins(tenant_dir, tenant_id, user_pin, so_pin, slug) do
      {:ok,
       %{
         conf_path: conf_path,
         tenant_dir: tenant_dir,
         slot_id: slot_id,
         label: label,
         user_pin: user_pin,
         so_pin: so_pin,
         pin_envelope: pin_envelope,
         library_path: detect_library_path()
       }}
    else
      {:error, _} = err ->
        # Best-effort cleanup of the partial dir so a retry starts
        # from a clean slate.
        _ = File.rm_rf(tenant_dir)
        err

      other ->
        _ = File.rm_rf(tenant_dir)
        {:error, {:unexpected, other}}
    end
  end

  # Either returns an encrypted envelope (production path) or
  # falls back to writing a plaintext `.pins` file and emitting a
  # loud warning. In both cases returns {:ok, envelope_or_nil}
  # — nil means the caller must treat `.pins` on disk as the
  # PIN source of truth.
  defp store_pins(tenant_dir, tenant_id, user_pin, so_pin, slug) do
    if is_binary(tenant_id) and tenant_id != "" do
      case PkiPlatformEngine.SofthsmPinCustody.wrap(tenant_id, user_pin, so_pin) do
        {:ok, envelope} ->
          {:ok, envelope}

        {:error, :no_master_key} ->
          Logger.warning(
            "[softhsm] #{slug}: no PKI_PLATFORM_MASTER_KEY — storing PINs in .pins on disk (dev-only)"
          )

          write_pin_file(tenant_dir, user_pin, so_pin)
          {:ok, nil}

        {:error, reason} ->
          Logger.error("[softhsm] #{slug}: PIN wrap failed (#{inspect(reason)}) — aborting")
          {:error, {:pin_wrap_failed, reason}}
      end
    else
      Logger.warning(
        "[softhsm] #{slug}: called without :tenant_id — storing PINs in .pins on disk (dev-only)"
      )

      write_pin_file(tenant_dir, user_pin, so_pin)
      {:ok, nil}
    end
  end

  defp write_conf(conf_path, tenant_dir) do
    content = """
    # Per-tenant SoftHSM2 config — generated by PkiPlatformEngine.SofthsmTokenManager
    directories.tokendir = #{tenant_dir}
    objectstore.backend = file
    log.level = INFO
    slots.removable = false
    """

    File.write(conf_path, content)
  end

  defp write_pin_file(tenant_dir, user_pin, so_pin) do
    path = Path.join(tenant_dir, ".pins")
    # WARNING: dev-only fallback. When PKI_PLATFORM_MASTER_KEY is
    # set and the caller passes :tenant_id, the encrypted envelope
    # path in store_pins/5 is taken instead.
    :ok = File.write!(path, "user=#{user_pin}\nso=#{so_pin}\n")
    _ = File.chmod(path, 0o600)
    :ok
  end

  defp run_init_token(conf_path, label, user_pin, so_pin) do
    env = [{"SOFTHSM2_CONF", conf_path}]

    args = [
      "--init-token",
      "--free",
      "--label",
      label,
      "--pin",
      user_pin,
      "--so-pin",
      so_pin
    ]

    case System.cmd("softhsm2-util", args, env: env, stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {output, status} -> {:error, {:softhsm2_util_exit, status, output}}
    end
  rescue
    e -> {:error, {:softhsm2_util_raised, Exception.message(e)}}
  end

  defp detect_slot(conf_path, label) do
    env = [{"SOFTHSM2_CONF", conf_path}]

    case System.cmd("softhsm2-util", ["--show-slots"], env: env, stderr_to_stdout: true) do
      {output, 0} ->
        case parse_slot_for_label(output, label) do
          nil -> {:error, {:slot_not_found, label}}
          slot -> {:ok, slot}
        end

      {output, status} ->
        {:error, {:show_slots_exit, status, output}}
    end
  end

  # SoftHSM2 `--show-slots` prints blocks like:
  #
  #     Slot 1234567890
  #         Slot info:
  #             Description:      SoftHSM slot ID 0x...
  #             ...
  #         Token info:
  #             Label:            tenant-acme
  #
  # We scan for the Slot <id> line, then look ahead up to ~20 lines
  # for `Label:            <label>`. First match wins.
  defp parse_slot_for_label(output, label) do
    lines = String.split(output, "\n")

    slot_and_label_pairs =
      lines
      |> Enum.with_index()
      |> Enum.filter(fn {line, _} -> String.match?(line, ~r/^Slot \d+/) end)
      |> Enum.map(fn {slot_line, idx} ->
        [_, slot] = Regex.run(~r/^Slot (\d+)/, slot_line)
        # scan the next 30 lines for the Label field
        context = Enum.slice(lines, idx..(idx + 30))
        {slot, context}
      end)

    case Enum.find(slot_and_label_pairs, fn {_slot, ctx} ->
           Enum.any?(ctx, &String.match?(&1, ~r/Label:\s+#{Regex.escape(label)}\s*$/))
         end) do
      nil -> nil
      {slot, _} -> String.to_integer(slot)
    end
  end

  defp detect_library_path do
    case :os.type() do
      {:unix, :darwin} ->
        # Homebrew arm64 first, then Intel.
        first_existing([
          "/opt/homebrew/lib/softhsm/libsofthsm2.so",
          "/usr/local/lib/softhsm/libsofthsm2.so"
        ])

      {:unix, _} ->
        first_existing([
          "/usr/lib/softhsm/libsofthsm2.so",
          "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
          "/usr/local/lib/softhsm/libsofthsm2.so"
        ])

      _ ->
        nil
    end
  end

  defp first_existing(paths), do: Enum.find(paths, &File.exists?/1)

  defp base_dir(opts) do
    Keyword.get(opts, :base_dir, System.get_env(@default_base_dir_env, @default_base_dir))
  end

  defp generate_pin(length \\ 8) do
    :crypto.strong_rand_bytes(length)
    |> Base.encode32(padding: false, case: :lower)
    |> binary_part(0, length)
  end
end
