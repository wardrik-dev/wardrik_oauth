defmodule WardrikOAuth.Flow do
  @moduledoc """
  A flow is one sign-in under way, a process holding what it needs until the principal finishes.
  """

  use GenServer, restart: :temporary

  require Logger

  alias WardrikCore.Principal
  alias WardrikOAuth.Browser
  alias WardrikOAuth.Device
  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Registration
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

  @doc "Describes the flow, for a page or a CLI to show."
  @spec describe(pid()) :: map()
  def describe(pid), do: GenServer.call(pid, :describe)

  @doc "Finishes a browser flow with the parameters its callback carried."
  @spec finish(pid(), map()) :: {:ok, String.t()} | {:error, term()}
  def finish(pid, params), do: GenServer.call(pid, {:finish, params}, :timer.seconds(30))

  @doc false
  def start_link({settings, provider, principal}) do
    name = {:via, Registry, {settings.registry, {:flow, provider.name, principal.id}}}
    GenServer.start_link(__MODULE__, {settings, provider, principal}, name: name)
  end

  @impl GenServer
  def init({settings, provider, principal}) do
    with {:ok, metadata} <- Metadata.discover(provider, settings.req_options),
         {:ok, provider} <- Registration.client(settings, provider, metadata),
         flow = %{
           settings: settings,
           provider: provider,
           principal: principal,
           metadata: metadata
         },
         {:ok, flow} <- start(provider.flow, flow) do
      Process.send_after(self(), :expire, @lifetime)
      {:ok, flow}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl GenServer
  def handle_call(:url, _from, flow), do: {:reply, flow.url, flow}

  def handle_call(:describe, _from, flow), do: {:reply, described(flow), flow}

  def handle_call({:finish, %{"error" => error}}, _from, flow) do
    outcome = {:error, {:refused, error}}
    {:stop, :normal, outcome, ended(flow, outcome)}
  end

  def handle_call({:finish, %{"code" => code} = params}, _from, %{kind: :browser} = flow) do
    outcome = exchanged(flow, code, params["iss"])
    {:stop, :normal, finished(outcome, flow), ended(flow, outcome)}
  end

  def handle_call({:finish, _params}, _from, flow), do: {:reply, {:error, :no_code}, flow}

  @impl GenServer
  def handle_info(:poll, flow) do
    flow.metadata
    |> Device.poll(flow.provider, flow.device, flow.settings.req_options)
    |> polled(flow)
  end

  def handle_info(:expire, flow), do: {:stop, :normal, ended(flow, {:error, :expired})}

  defp start(:device, flow) do
    with {:ok, device} <- Device.request(flow.metadata, flow.provider, flow.settings.req_options) do
      id = random()
      {:ok, _owner} = Registry.register(flow.settings.registry, {:id, id}, nil)
      schedule(:timer.seconds(device.interval))

      {:ok,
       Map.merge(flow, %{
         kind: :device,
         device: device,
         interval: :timer.seconds(device.interval),
         url: flow.settings.page <> "/device/" <> id
       })}
    end
  end

  defp start(:browser, flow) do
    with {:ok, started} <- Browser.start(flow.metadata, flow.provider, redirect_uri(flow)) do
      {:ok, _owner} = Registry.register(flow.settings.registry, {:state, started.state}, nil)
      {:ok, Map.merge(flow, %{kind: :browser, url: started.url, verifier: started.verifier})}
    end
  end

  defp described(%{kind: :device} = flow) do
    %{
      provider: flow.provider.name,
      principal: flow.principal,
      user_code: flow.device.user_code,
      verification_uri: flow.device.verification_uri
    }
  end

  defp described(flow),
    do: %{provider: flow.provider.name, principal: flow.principal, url: flow.url}

  defp exchanged(flow, code, iss) do
    options = [redirect_uri: redirect_uri(flow), req_options: flow.settings.req_options]

    with :ok <- issuer(flow.metadata, iss),
         {:ok, token} <-
           Browser.exchange(flow.metadata, flow.provider, code, flow.verifier, options) do
      granted(flow, token)
    end
  end

  defp issuer(metadata, iss),
    do: if(Browser.issued_by?(metadata, iss), do: :ok, else: {:error, :wrong_issuer})

  defp finished(:granted, flow), do: {:ok, flow.provider.name}
  defp finished(outcome, _flow), do: outcome

  defp polled({:ok, %Token{} = token}, flow),
    do: {:stop, :normal, ended(flow, granted(flow, token))}

  defp polled({:error, reason}, flow), do: {:stop, :normal, ended(flow, {:error, reason})}

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

  defp ended(flow, outcome) do
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

    flow
  end

  defp redirect_uri(flow), do: flow.settings.page <> "/callback"

  defp random, do: 18 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  defp schedule(interval), do: Process.send_after(self(), :poll, interval)
end
