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
  alias WardrikOAuth.Registration
  alias WardrikOAuth.Renewal
  alias WardrikOAuth.Token

  @doc """
  Starts the sign-ins. Takes `:name`, `:vault`, `:store`, where providers added as it runs are
  kept, `:page`, `:providers`, `:on_granted`, `:client_name`, what a service shows of a client
  Wardrik registers itself, `"Wardrik"` unless set, `:req_options`, and `:check`.

  `:check` is a function each URL it sends a request to is held to first, answering `:ok` or
  `{:error, why}`. Give one where others name the services, as the users of a hosted app add
  providers by URL, and those services name the endpoints Wardrik reaches. Every `https` URL, and
  `http` on the machine itself, is reached unless it's given.
  """
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    opts =
      Keyword.validate!(opts, [
        :name,
        :vault,
        :store,
        :page,
        providers: [],
        on_granted: nil,
        client_name: "Wardrik",
        req_options: [],
        check: nil
      ])

    name = Keyword.fetch!(opts, :name)
    Supervisor.start_link(__MODULE__, Map.new(opts), name: name)
  end

  @doc """
  Adds the provider `name` as the app runs, on every node, as `:providers` takes one. Without a
  `client_id`, Wardrik registers itself with the service the first time someone signs in.

      :ok = WardrikOAuth.add_provider(MyApp.OAuth, "linear", resource: "https://mcp.linear.app/mcp")
  """
  @spec add_provider(atom(), String.t(), keyword()) :: :ok | {:error, String.t()}
  def add_provider(oauth, name, opts) when is_binary(name) do
    settings = settings(oauth)
    Provider.new(name, opts)

    if Map.has_key?(settings.providers, name) do
      {:error, "#{name} is a provider the app starts with"}
    else
      with {:ok, _vsn} <- WardrikStore.put(settings.store, provider_key(name), opts), do: :ok
    end
  rescue
    error in ArgumentError -> {:error, Exception.message(error)}
  end

  @doc "Removes the provider `name` added as the app ran, and the client registered for it."
  @spec remove_provider(atom(), String.t()) :: :ok | {:error, term()}
  def remove_provider(oauth, name) do
    settings = settings(oauth)

    with :ok <- WardrikStore.delete(settings.store, provider_key(name)),
         do: Registration.forget(settings, name)
  end

  @doc "Returns the names of the providers someone can sign in with."
  @spec providers(atom()) :: [String.t()]
  def providers(oauth) do
    settings = settings(oauth)

    added =
      settings.store
      |> WardrikStore.keys("providers/")
      |> Enum.map(&String.replace_prefix(&1, "providers/", ""))

    Enum.sort(Map.keys(settings.providers) ++ added)
  end

  @doc "Returns where `principal` signs in with the provider `name`, starting a sign-in unless one is under way."
  @spec authorize(atom(), String.t(), WardrikCore.Principal.t()) ::
          {:ok, String.t()} | {:error, term()}
  def authorize(oauth, name, principal) do
    settings = settings(oauth)

    with {:ok, provider} <- provider(settings, name),
         {:authorize, url} <- Flow.begin(settings, provider, principal),
         do: {:ok, url}
  end

  @doc "Describes the device sign-in `id` names, with the code to enter and where, or returns `:error`."
  @spec flow(atom(), String.t()) :: {:ok, map()} | :error
  def flow(oauth, id) do
    case Registry.lookup(registry(oauth), {:id, id}) do
      [{pid, _value}] -> described(pid)
      [] -> :error
    end
  end

  defp described(pid) do
    {:ok, Flow.describe(pid)}
  catch
    :exit, _ended -> :error
  end

  @doc """
  Finishes the browser sign-in a callback's `state` names, with the `code` or `error` it carried.

  `WardrikOAuth.Plug` calls this. Call it yourself from a route of your own.
  """
  @spec finish(atom(), map()) :: {:ok, String.t()} | {:error, term()}
  def finish(oauth, %{"state" => state} = params) when is_binary(state) do
    case Registry.lookup(registry(oauth), {:state, state}) do
      [{pid, _value}] -> finished(pid, params)
      [] -> {:error, :no_such_flow}
    end
  end

  def finish(_oauth, _params), do: {:error, :no_such_flow}

  defp finished(pid, params) do
    Flow.finish(pid, params)
  catch
    :exit, _ended -> {:error, :no_such_flow}
  end

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
      store: opts |> Map.fetch!(:store) |> WardrikStore.scope("wardrik_oauth"),
      client_name: opts.client_name,
      page: opts |> Map.fetch!(:page) |> String.trim_trailing("/"),
      providers:
        Map.new(opts.providers, fn {name, provider} ->
          {to_string(name), Provider.new(name, provider)}
        end),
      on_granted: opts.on_granted,
      req_options: checked(opts.check) ++ opts.req_options,
      registry: registry(opts.name),
      flows: Module.concat(opts.name, Flows)
    }

    children = [
      {Registry, keys: :unique, name: settings.registry, meta: [settings: settings]},
      {DynamicSupervisor, name: settings.flows}
    ]

    Supervisor.init(children, strategy: :rest_for_one)
  end

  defp checked(nil), do: []
  defp checked(check), do: [check: check]

  defp settings(oauth) do
    {:ok, settings} = Registry.meta(registry(oauth), :settings)
    settings
  rescue
    ArgumentError ->
      reraise ArgumentError,
              "#{inspect(oauth)} isn't started. Add {WardrikOAuth, name: #{inspect(oauth)}, ...} to your supervision tree, ahead of what uses it.",
              __STACKTRACE__
  end

  defp registry(oauth), do: Module.concat(oauth, Registry)

  defp provider(settings, name) do
    case Map.fetch(settings.providers, name) do
      {:ok, provider} -> {:ok, Registration.registered(settings, provider)}
      :error -> added(settings, name)
    end
  end

  defp added(settings, name) do
    case WardrikStore.get(settings.store, provider_key(name)) do
      nil -> {:error, :not_found}
      opts -> {:ok, Registration.registered(settings, Provider.new(name, opts))}
    end
  end

  defp provider_key(name), do: "providers/" <> name

  defp over_current(vault, principal, name) do
    case WardrikVault.lookup(vault, principal, name) do
      {:ok, _kind, _value, vsn} -> [if_vsn: vsn]
      {:error, :not_found} -> [if_vsn: nil]
      _unreadable -> []
    end
  end
end
