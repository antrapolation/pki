defmodule PkiCaPortalWeb.SafeEngine do
  @moduledoc """
  Wraps CaEngineClient calls with rescue to prevent LiveView crashes
  when the tenant dynamic repo is not yet ready (race condition during
  the first few seconds after login).
  """

  require Logger

  @doc """
  Calls a function that returns `{:ok, result}` or `{:error, reason}`.
  If the function raises (e.g. Postgrex crash), returns the fallback.
  """
  def safe_call(fun, fallback) do
    try do
      case fun.() do
        {:ok, result} -> result
        :ok -> fallback
        {:error, reason} ->
          Logger.warning("[SafeEngine] engine call returned error: #{inspect(reason)}")
          fallback
      end
    catch
      :exit, reason ->
        Logger.warning("[SafeEngine] engine call exited: #{inspect(reason)}")
        fallback
    rescue
      e ->
        Logger.warning("[SafeEngine] engine call crashed: #{Exception.message(e)}")
        fallback
    end
  end

  @doc """
  Wraps an entire data-loading function with rescue and retry logic.
  `load_fn` should be a 0-arity function that returns `{:noreply, socket}`.
  On crash, retries up to 3 times with 2s delay, then assigns
  `loading: false` and returns the socket unchanged.
  """
  def safe_load(socket, load_fn, opts \\ []) do
    retry_key = Keyword.get(opts, :retry_key, :load_retries)
    retry_msg = Keyword.get(opts, :retry_msg, :load_data)
    max_retries = Keyword.get(opts, :max_retries, 3)
    retries = socket.assigns[retry_key] || 0

    try do
      load_fn.()
    catch
      :exit, reason ->
        Logger.warning("[SafeEngine] data load exited (attempt #{retries + 1}/#{max_retries}): #{inspect(reason)}")

        if retries < max_retries do
          Process.send_after(self(), retry_msg, 2_000)
          {:noreply, Phoenix.LiveView.assign(socket, [{retry_key, retries + 1}])}
        else
          {:noreply, Phoenix.LiveView.assign(socket, [{retry_key, 0}, {:loading, false}])}
        end
    rescue
      e ->
        Logger.warning("[SafeEngine] data load crashed (attempt #{retries + 1}/#{max_retries}): #{Exception.message(e)}")

        if retries < max_retries do
          Process.send_after(self(), retry_msg, 2_000)
          {:noreply, Phoenix.LiveView.assign(socket, [{retry_key, retries + 1}])}
        else
          {:noreply, Phoenix.LiveView.assign(socket, [{retry_key, 0}, {:loading, false}])}
        end
    end
  end
end
