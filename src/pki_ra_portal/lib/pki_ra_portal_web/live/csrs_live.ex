defmodule PkiRaPortalWeb.CsrsLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, csrs} = RaEngineClient.list_csrs()

    {:ok,
     assign(socket,
       page_title: "CSR Management",
       csrs: csrs,
       status_filter: "all",
       selected_csr: nil,
       reject_reason: ""
     )}
  end

  @impl true
  def handle_event("filter_status", %{"status" => status}, socket) do
    filters = if status == "all", do: [], else: [status: status]
    {:ok, csrs} = RaEngineClient.list_csrs(filters)
    {:noreply, assign(socket, csrs: csrs, status_filter: status)}
  end

  @impl true
  def handle_event("view_csr", %{"id" => id}, socket) do
    csr_id = String.to_integer(id)
    {:ok, csr} = RaEngineClient.get_csr(csr_id)
    {:noreply, assign(socket, selected_csr: csr)}
  end

  @impl true
  def handle_event("close_detail", _params, socket) do
    {:noreply, assign(socket, selected_csr: nil)}
  end

  @impl true
  def handle_event("approve_csr", %{"id" => id}, socket) do
    csr_id = String.to_integer(id)

    case RaEngineClient.approve_csr(csr_id, %{approved_by: socket.assigns.current_user["did"]}) do
      {:ok, _} ->
        filters = if socket.assigns.status_filter == "all", do: [], else: [status: socket.assigns.status_filter]
        {:ok, csrs} = RaEngineClient.list_csrs(filters)

        {:noreply,
         socket
         |> assign(csrs: csrs, selected_csr: nil)
         |> put_flash(:info, "CSR approved successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to approve CSR: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("reject_csr", %{"csr_id" => id, "reason" => reason}, socket) do
    csr_id = String.to_integer(id)

    case RaEngineClient.reject_csr(csr_id, reason, %{rejected_by: socket.assigns.current_user["did"]}) do
      {:ok, _} ->
        filters = if socket.assigns.status_filter == "all", do: [], else: [status: socket.assigns.status_filter]
        {:ok, csrs} = RaEngineClient.list_csrs(filters)

        {:noreply,
         socket
         |> assign(csrs: csrs, selected_csr: nil)
         |> put_flash(:info, "CSR rejected")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to reject CSR: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="csrs-page">
      <h1>CSR Management</h1>

      <section id="csr-filter">
        <form phx-change="filter_status">
          <label for="status">Filter by status:</label>
          <select name="status" id="status-filter">
            <option value="all" selected={@status_filter == "all"}>All</option>
            <option value="pending" selected={@status_filter == "pending"}>Pending</option>
            <option value="approved" selected={@status_filter == "approved"}>Approved</option>
            <option value="rejected" selected={@status_filter == "rejected"}>Rejected</option>
          </select>
        </form>
      </section>

      <section id="csr-table">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Subject</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Submitted</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="csr-list">
            <tr :for={csr <- @csrs} id={"csr-#{csr.id}"}>
              <td>{csr.id}</td>
              <td>{csr.subject}</td>
              <td>{csr.profile_name}</td>
              <td>{csr.status}</td>
              <td>{Calendar.strftime(csr.submitted_at, "%Y-%m-%d %H:%M")}</td>
              <td>
                <button phx-click="view_csr" phx-value-id={csr.id}>View</button>
                <button :if={csr.status == "pending"} phx-click="approve_csr" phx-value-id={csr.id}>
                  Approve
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section :if={@selected_csr} id="csr-detail">
        <h2>CSR Detail</h2>
        <p>ID: {@selected_csr.id}</p>
        <p>Subject: {@selected_csr.subject}</p>
        <p>Status: <span id="csr-status">{@selected_csr.status}</span></p>
        <p>Profile: {@selected_csr.profile_name}</p>
        <p>Public Key Algorithm: {@selected_csr.public_key_algorithm}</p>
        <p>Requestor: {@selected_csr.requestor_did}</p>

        <div :if={@selected_csr.status == "pending"} id="csr-actions">
          <button phx-click="approve_csr" phx-value-id={@selected_csr.id}>Approve</button>

          <form phx-submit="reject_csr" id="reject-form">
            <input type="hidden" name="csr_id" value={@selected_csr.id} />
            <label for="reason">Rejection Reason:</label>
            <textarea name="reason" id="reject-reason" required></textarea>
            <button type="submit">Reject</button>
          </form>
        </div>

        <button phx-click="close_detail">Close</button>
      </section>
    </div>
    """
  end
end
