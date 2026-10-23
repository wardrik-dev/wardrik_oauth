defmodule WardrikOAuth do
  @moduledoc """
  OAuth sign-in for WardrikCore agents, with the grants kept sealed in a `WardrikVault`.

      children = [
        {WardrikVault, name: MyApp.Vault, store: store, keys: keys, grants: {WardrikOAuth, MyApp.OAuth}},
        {WardrikOAuth,
         name: MyApp.OAuth,
         vault: MyApp.Vault,
         page: "https://agents.example.com/oauth",
         on_granted: {MyApp.Agents, :granted, []},
         providers: [github: [issuer: "https://github.com/login/oauth", client_id: id, client_secret: secret]]}
      ]
  """

  @behaviour WardrikVault.Grants

  use Supervisor

  alias WardrikOAuth.Flow
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Renewal
  alias WardrikOAuth.Token

  @doc "Starts the sign-ins. Takes `:name`, `:vault`, `:page`, `:providers`, `:on_granted` and `:req_options`."
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    opts =
      Keyword.validate!(opts, [
        :name,
        :vault,
        :page,
        providers: [],
        on_granted: nil,
        req_options: []
      ])

    name = Keyword.fetch!(opts, :name)
    Supervisor.start_link(__MODULE__, Map.new(opts), name: name)
  end

  @doc "Describes the device sign-in `id` names, with the code to enter and where, or returns `:error`."
  @spec flow(atom(), String.t()) :: {:ok, map()} | :error
  def flow(oauth, id) do
    case Registry.lookup(registry(oauth), {:id, id}) do
      [{pid, _value}] -> {:ok, Flow.describe(pid)}
      [] -> :error
    end
  end

  @doc """
  Finishes the browser sign-in a callback's `state` names, with the `code` or `error` it carried.

  `WardrikOAuth.Plug` calls this. Call it yourself from a route of your own.
  """
  @spec finish(atom(), map()) :: {:ok, String.t()} | {:error, term()}
  def finish(oauth, %{"state" => state} = params) when is_binary(state) do
    case Registry.lookup(registry(oauth), {:state, state}) do
      [{pid, _value}] -> Flow.finish(pid, params)
      [] -> {:error, :no_such_flow}
    end
  end

  def finish(_oauth, _params), do: {:error, :no_such_flow}

  @impl WardrikVault.Grants
  def ask(_vault, name, principal, oauth) do
    settings = settings(oauth)

    with {:ok, provider} <- provider(settings, name),
         do: Flow.begin(settings, provider, principal)
  end

  @impl WardrikVault.Grants
  def renew(_vault, name, principal, %{value: value}, oauth) do
    settings = settings(oauth)

    with {:ok, provider} <- provider(settings, name) do
      case Renewal.renew(settings, provider, principal, value) do
        :ask -> Flow.begin(settings, provider, principal)
        renewed -> renewed
      end
    end
  end

  @impl WardrikVault.Grants
  def refused(_vault, name, principal, oauth) do
    settings = settings(oauth)

    with {:ok, provider} <- provider(settings, name),
         do: Renewal.expire(settings, provider, principal)

    :ok
  end

  @doc false
  def keep(settings, provider, principal, %Token{} = token) do
    condition = over_current(settings.vault, principal, provider.name)

    WardrikVault.put(
      settings.vault,
      principal,
      provider.name,
      Token.encode(token),
      [kind: :grant] ++ condition
    )
  end

  @impl Supervisor
  def init(opts) do
    settings = %{
      vault: Map.fetch!(opts, :vault),
      page: opts |> Map.fetch!(:page) |> String.trim_trailing("/"),
      providers:
        Map.new(opts.providers, fn {name, provider} ->
          {to_string(name), Provider.new(name, provider)}
        end),
      on_granted: opts.on_granted,
      req_options: opts.req_options,
      registry: registry(opts.name),
      flows: Module.concat(opts.name, Flows)
    }

    children = [
      {Registry, keys: :unique, name: settings.registry, meta: [settings: settings]},
      {DynamicSupervisor, name: settings.flows}
    ]

    Supervisor.init(children, strategy: :rest_for_one)
  end

  defp settings(oauth) do
    {:ok, settings} = Registry.meta(registry(oauth), :settings)
    settings
  end

  defp registry(oauth), do: Module.concat(oauth, Registry)

  defp provider(settings, name) do
    case Map.fetch(settings.providers, name) do
      {:ok, provider} -> {:ok, provider}
      :error -> {:error, :not_found}
    end
  end

  defp over_current(vault, principal, name) do
    case WardrikVault.lookup(vault, principal, name) do
      {:ok, _kind, _value, vsn} -> [if_vsn: vsn]
      {:error, :not_found} -> [if_vsn: nil]
      _unreadable -> []
    end
  end
end
