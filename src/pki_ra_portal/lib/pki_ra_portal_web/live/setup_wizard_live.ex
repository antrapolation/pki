defmodule PkiRaPortalWeb.SetupWizardLive do
  use PkiRaPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Setup Wizard")}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 bg-base-200 flex items-center justify-center">
      <div class="card bg-base-100 shadow-xl max-w-lg w-full mx-4">
        <div class="card-body text-center">
          <h1 class="text-2xl font-bold">Setup Wizard</h1>
          <p class="text-base-content/60">Coming soon — this will be implemented in Task 6.</p>
          <.link navigate="/" class="btn btn-primary mt-4">Back to Dashboard</.link>
        </div>
      </div>
    </div>
    """
  end
end
