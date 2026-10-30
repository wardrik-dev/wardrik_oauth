defmodule WardrikOAuth do
  @moduledoc """
  OAuth sign-in for WardrikCore agents. Grants are sealed in a `WardrikVault`.

      children = [
        {WardrikVault, name: MyApp.Vault, store: store, keys: keys, grants: {WardrikOAuth, MyApp.OAuth}},
        {WardrikOAuth,
         name: MyApp.OAuth,
         vault: MyApp.Vault,
         store: store,
         page: "https://agents.example.com/oauth",
         on_granted: {MyApp.Agents, :granted, []},
         providers: [github: [issuer: "https://github.com/login/oauth", client_id: id, client_secret: secret]]}
      ]

  Mount `WardrikOAuth.Plug` at `page` to finish sign-ins. See `WardrikOAuth.Provider` for provider
  options.

  A provider's `client_secret` may be `{:secret, name}`. It's read from the vault's deployment
  secrets each time a sign-in needs it, so a new one takes effect at once. See
  `WardrikVault.value/2`.
  """

  @behaviour WardrikVault.Grants

  use Supervisor

  alias WardrikOAuth.ClientSecrets
  alias WardrikOAuth.Flow
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Registration
  alias WardrikOAuth.Renewal
  alias WardrikOAuth.Token

  @doc """
  Starts `WardrikOAuth`.

  ## Options

    * `:name` - required. The name functions reach it by.
    * `:vault` - required. The `WardrikVault` grants are sealed in.
    * `:store` - required. The `WardrikStore` for providers added at runtime and registered
      clients.
    * `:page` - required. The URL `WardrikOAuth.Plug` is mounted at, as
      `"https://agents.example.com/oauth"`.
    * `:providers` - providers to start with, as a keyword list of name and options. See
      `WardrikOAuth.Provider`. `[]` unless set.
    * `:on_granted` - `{module, function, args}` called with the provider's name and the principal,
      then `args`, after each grant.
    * `:client_name` - the name a service shows for a client Wardrik registers. `"Wardrik"`
      unless set.
    * `:req_options` - extra options for every `Req` request.
    * `:check` - a function called on each URL before a request is sent. It returns `:ok` or
      `{:error, reason}`. Use one when users add providers by URL. Without it, any `https` URL,
      and `http` on localhost, is reached.
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
  Adds the provider `name` at runtime, on every node.

      :ok = WardrikOAuth.add_provider(MyApp.OAuth, "linear", resource: "https://mcp.linear.app/mcp")

  Takes the same options as a provider in `:providers`. The `client_secret` is sealed in the vault,
  not kept in the store.

  Without a `client_id`, Wardrik gets one the first time someone signs in:

    1. If the service reads Client ID Metadata Documents and `page` is `https`, the `client_id` is
       the URL of the document `WardrikOAuth.Plug` serves.
    2. Otherwise, Wardrik registers itself with the service.

  Returns `{:error, reason}` for invalid options, or a name given in `:providers`.
  """
  @spec add_provider(atom(), String.t(), keyword()) :: :ok | {:error, String.t()}
  def add_provider(oauth, name, opts) when is_binary(name) do
    settings = settings(oauth)
    Provider.new(name, opts)
    {secret, kept} = Keyword.pop(opts, :client_secret)

    if Map.has_key?(settings.providers, name) do
      {:error, "#{name} is a provider the app starts with"}
    else
      with :ok <- ClientSecrets.seal(settings, provider_key(name), secret),
           {:ok, _vsn} <- WardrikStore.put(settings.store, provider_key(name), kept),
           do: :ok
    end
  rescue
    error in ArgumentError -> {:error, Exception.message(error)}
  end

  @doc """
  Returns the Client ID Metadata Document served at `{page}/client`.

  Its URL is Wardrik's `client_id` with services that read these documents.
  """
  @spec client_document(atom()) :: map()
  def client_document(oauth), do: oauth |> settings() |> Registration.document()

  @doc "Removes the provider `name`, added at runtime, and the client registered for it."
  @spec remove_provider(atom(), String.t()) :: :ok | {:error, term()}
  def remove_provider(oauth, name) do
    settings = settings(oauth)

    with :ok <- WardrikStore.delete(settings.store, provider_key(name)),
         :ok <- ClientSecrets.forget(settings, provider_key(name)),
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

  @doc """
  Returns the URL where `principal` signs in with the provider `name`.

  Starts a sign-in, or returns the URL of the one already under way.
  """
  @spec authorize(atom(), String.t(), WardrikCore.Principal.t()) ::
          {:ok, String.t()} | {:error, term()}
  def authorize(oauth, name, principal) do
    settings = settings(oauth)

    with {:ok, provider} <- provider(settings, name),
         {:authorize, url} <- Flow.begin(settings, provider, principal),
         do: {:ok, url}
  end

  @doc """
  Describes the device sign-in `id`.

  Returns `{:ok, map}` with `:provider`, `:principal`, `:user_code` and `:verification_uri`, or
  `:error` if the sign-in has ended.
  """
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
  Finishes a browser sign-in from its callback's query params.

  The params carry `"state"`, and `"code"` or `"error"`. Returns `{:ok, provider}` or
  `{:error, reason}`, and `{:error, :no_such_flow}` if the sign-in has ended.

  `WardrikOAuth.Plug` calls this. Call it yourself to handle the callback in your own route.
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
      {:ok, provider} -> configured(settings, provider)
      :error -> added(settings, name)
    end
  end

  defp configured(settings, %Provider{client_secret: secret} = provider) do
    case WardrikVault.value(settings.vault, secret) do
      {:ok, secret} ->
        {:ok, Registration.registered(settings, %{provider | client_secret: secret})}

      {:error, _reason} ->
        {:error, "#{provider.name}'s client_secret, #{inspect(secret)}, isn't sealed"}
    end
  end

  defp added(settings, name) do
    case WardrikStore.get(settings.store, provider_key(name)) do
      nil ->
        {:error, :not_found}

      opts ->
        {:ok,
         Registration.registered(settings, Provider.new(name, unsealed(settings, name, opts)))}
    end
  end

  defp unsealed(settings, name, opts) do
    case ClientSecrets.unseal(settings, provider_key(name)) do
      nil -> opts
      secret -> Keyword.put(opts, :client_secret, secret)
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
