defmodule WardrikOAuth.Flow do
  @moduledoc """
  A flow is one sign-in under way, a process polling the server until the principal finishes.
  """

  use GenServer, restart: :temporary

  require Logger

  alias WardrikCore.Principal
  alias WardrikOAuth.Device
  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Token

  @lifetime :timer.minutes(15)

  @doc "Returns the URL of the flow under way for `provider` and `principal`, starting one if none is."
  @spec begin(map(), Provider.t(), Principal.t()) :: {:authorize, String.t()} | {:error, term()}
  def begin(settings, %Provider{} = provider, %Principal{} = principal) do
    child = {__MODULE__, {settings, provider, principal}}

    case DynamicSupervisor.start_child(settings.flows, child) do
      {:ok, pid} -> {:authorize, GenServer.call(pid, :url)}
      {:error, {:already_started, pid}} -> {:authorize, GenServer.call(pid, :url)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Describes the flow `id` names, for a page or a CLI to show its code."
  @spec describe(pid()) :: map()
  def describe(pid), do: GenServer.call(pid, :describe)

  @doc false
  def start_link({settings, provider, principal}) do
    name = {:via, Registry, {settings.registry, {:flow, provider.name, principal.id}}}
    GenServer.start_link(__MODULE__, {settings, provider, principal}, name: name)
  end

  @impl GenServer
  def init({settings, provider, principal}) do
    with {:ok, metadata} <- Metadata.discover(provider, settings.req_options),
         {:ok, device} <- Device.request(metadata, provider, settings.req_options) do
      id = 18 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
      {:ok, _owner} = Registry.register(settings.registry, {:id, id}, nil)
      Process.send_after(self(), :expire, min(@lifetime, :timer.seconds(device.expires_in)))
      schedule(:timer.seconds(device.interval))

      {:ok,
       %{
         settings: settings,
         provider: provider,
         principal: principal,
         metadata: metadata,
         device: device,
         interval: :timer.seconds(device.interval),
         url: settings.page <> "/device/" <> id
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl GenServer
  def handle_call(:url, _from, flow), do: {:reply, flow.url, flow}

  def handle_call(:describe, _from, flow) do
    {:reply,
     %{
       provider: flow.provider.name,
       principal: flow.principal,
       user_code: flow.device.user_code,
       verification_uri: flow.device.verification_uri
     }, flow}
  end

  @impl GenServer
  def handle_info(:poll, flow) do
    flow.metadata
    |> Device.poll(flow.provider, flow.device, flow.settings.req_options)
    |> polled(flow)
  end

  def handle_info(:expire, flow), do: done(flow, {:error, :expired})

  defp polled({:ok, %Token{} = token}, flow), do: done(flow, granted(flow, token))
  defp polled({:error, reason}, flow), do: done(flow, {:error, reason})

  defp polled(waiting, flow) do
    interval = Device.next_interval(waiting, flow.interval)
    schedule(interval)
    {:noreply, %{flow | interval: interval}}
  end

  defp granted(flow, token) do
    %{settings: settings, provider: provider, principal: principal} = flow

    with {:ok, _vsn} <- WardrikOAuth.keep(settings, provider, principal, token) do
      tell(settings.on_granted, provider.name, principal)
      :granted
    end
  end

  defp tell(nil, _name, _principal), do: :ok

  defp tell({module, function, args}, name, principal),
    do: apply(module, function, [name, principal | args])

  defp done(flow, outcome) do
    if outcome != :granted,
      do:
        Logger.info(
          "#{flow.provider.name} sign-in for #{flow.principal.id} ended: #{inspect(outcome)}"
        )

    :telemetry.execute([:wardrik_oauth, :flow, :done], %{}, %{
      provider: flow.provider.name,
      principal: flow.principal,
      outcome: outcome
    })

    {:stop, :normal, flow}
  end

  defp schedule(interval), do: Process.send_after(self(), :poll, interval)
end
