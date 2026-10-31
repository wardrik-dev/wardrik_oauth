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

  Providers belong to owners. Those in `:providers` are the deployment's, and `add_provider/4`
  adds an org's or a person's. A principal signs in with the nearest provider of a name along
  `Wardrik.Owners.chain/1`.

  A provider's `client_secret` may be `{:secret, name}`. It's read from its owner's vault secrets
  each time it's needed, so a new one takes effect at once.

  Grants never fall back. Each belongs to the principal who signed in, and is renewed with the
  provider that issued it. If that provider is gone, the principal signs in again.
  """

  @behaviour WardrikVault.Grants

  use Supervisor

  alias Wardrik.Owners
  alias Wardrik.Resource
  alias WardrikCore.Principal
  alias WardrikOAuth.Flow
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Registration
  alias WardrikOAuth.Renewal
  alias WardrikOAuth.Token

  @schema NimbleOptions.new!(
            name: [type: :atom, required: true, doc: "The name functions reach it by."],
            vault: [type: :any, required: true, doc: "The `WardrikVault` grants are sealed in."],
            store: [
              type: :any,
              required: true,
              doc: "The `WardrikStore` for providers added at runtime and registered clients."
            ],
            page: [
              type: :string,
              required: true,
              doc: """
              The URL `WardrikOAuth.Plug` is mounted at, as `"https://agents.example.com/oauth"`.
              """
            ],
            providers: [
              type: {:list, {:tuple, [{:or, [:atom, :string]}, :keyword_list]}},
              default: [],
              doc: "Providers to start with, by name. See `WardrikOAuth.Provider`."
            ],
            on_granted: [
              type: {:or, [:mfa, nil]},
              default: nil,
              doc: """
              `{module, function, args}` called with the provider's name and the principal, then
              `args`, after each grant.
              """
            ],
            client_name: [
              type: :string,
              default: "Wardrik",
              doc: "The name a service shows for a client Wardrik registers."
            ],
            req_options: [
              type: :keyword_list,
              default: [],
              doc: "Extra options for every `Req` request."
            ],
            check: [
              type: {:or, [{:fun, 1}, nil]},
              default: nil,
              doc: """
              Called on each URL before a request is sent, returning `:ok` or `{:error, reason}`.
              Use one when users add providers by URL. Without it, any `https` URL, and `http` on
              localhost, is reached.
              """
            ]
          )

  @doc """
  Starts `WardrikOAuth`.

  ## Options

  #{NimbleOptions.docs(@schema)}
  """
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    opts = NimbleOptions.validate!(opts, @schema)
    name = Keyword.fetch!(opts, :name)
    Supervisor.start_link(__MODULE__, Map.new(opts), name: name)
  end

  @doc """
  Adds `owner`'s provider `name` at runtime, on every node.

      :ok =
        WardrikOAuth.add_provider(MyApp.OAuth, "acme", "linear",
          resource: "https://mcp.linear.app/mcp",
          client_id: "acme-linear",
          client_secret: {:secret, "LINEAR_CLIENT_SECRET"}
        )

  `owner` is `deployment`, an org like `acme`, or a person like `acme/@jon`. Takes the same
  options as a provider in `:providers`, but `client_secret` must be `{:secret, name}`, read from
  `owner`'s vault secrets.

  Without a `client_id`, Wardrik gets one the first time someone signs in:

    1. If the service reads Client ID Metadata Documents and `page` is `https`, the `client_id` is
       the URL of the document `WardrikOAuth.Plug` serves.
    2. Otherwise, Wardrik registers itself with the service.

  Returns `{:error, reason}` for invalid options, a `client_secret` given as is, or the
  deployment's provider of a name in `:providers`.
  """
  @spec add_provider(atom(), Owners.t(), String.t(), keyword()) :: :ok | {:error, String.t()}
  def add_provider(oauth, owner, name, opts) when is_binary(owner) and is_binary(name) do
    settings = settings(oauth)
    Provider.new(name, opts)

    cond do
      Owners.parse(owner) == :error ->
        {:error, "#{owner} isn't an owner"}

      is_binary(opts[:client_secret]) ->
        {:error, "#{name}'s client_secret must be {:secret, name}"}

      Map.has_key?(configured(settings, owner), name) ->
        {:error, "#{name} is a provider the app starts with"}

      true ->
        with {:ok, _vsn} <- WardrikStore.put(settings.store, provider_key(owner, name), opts),
             do: :ok
    end
  rescue
    error in [ArgumentError, NimbleOptions.ValidationError] -> {:error, Exception.message(error)}
  end

  @doc """
  Returns the Client ID Metadata Document served at `{page}/client`.

  Its URL is Wardrik's `client_id` with services that read these documents.
  """
  @spec client_document(atom()) :: map()
  def client_document(oauth), do: oauth |> settings() |> Registration.document()

  @doc "Removes `owner`'s provider `name`, added at runtime, and the client registered for it."
  @spec remove_provider(atom(), Owners.t(), String.t()) :: :ok | {:error, term()}
  def remove_provider(oauth, owner, name) do
    settings = settings(oauth)

    with :ok <- WardrikStore.delete(settings.store, provider_key(owner, name)),
         do: Registration.forget(settings, owner, name)
  end

  @doc """
  Returns the providers `owner` can sign in with, nearest first along `Wardrik.Owners.chain/1`.

      WardrikOAuth.providers(MyApp.OAuth, "acme/@jon")
      #=> [%WardrikOAuth.Provider{name: "linear", owner: "acme", source: :runtime, ...}, ...]

  Only the nearest provider of each name is given. A `client_secret` is as it was given, not read.
  """
  @spec providers(atom(), Owners.t()) :: [Provider.t()]
  def providers(oauth, owner) do
    settings = settings(oauth)

    owner
    |> Owners.chain()
    |> Enum.flat_map(&owned(settings, &1))
    |> Enum.uniq_by(& &1.name)
  end

  @doc """
  Returns the URL where `principal` signs in with the provider `name`, the nearest along
  `Wardrik.Owners.chain/1`.

  Starts a sign-in, or returns the URL of the one already under way.
  """
  @spec authorize(atom(), String.t(), Principal.t()) :: {:ok, String.t()} | {:error, term()}
  def authorize(oauth, name, principal) do
    with {:authorize, url} <- begin(settings(oauth), name, principal), do: {:ok, url}
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
  def ask(_vault, name, principal, oauth), do: begin(settings(oauth), name, principal)

  @impl WardrikVault.Grants
  def renew(_vault, name, principal, %{value: value}, oauth) do
    settings = settings(oauth)

    case renewed(settings, name, principal, value) do
      :ask -> begin(settings, name, principal)
      renewed -> renewed
    end
  end

  @impl WardrikVault.Grants
  def refused(_vault, name, principal, oauth),
    do: Renewal.expire(settings(oauth), name, principal)

  @doc false
  def keep(settings, provider, principal, %Token{} = token) do
    condition = over_current(settings.vault, principal, provider.name)

    WardrikVault.put(
      settings.vault,
      principal,
      provider.name,
      Token.encode(%{token | owner: provider.owner}),
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

  defp begin(settings, name, principal) do
    with {:ok, provider} <- resolve(settings, name, principal),
         do: Flow.begin(settings, provider, principal)
  end

  defp renewed(settings, name, principal, value) do
    with {:ok, token} <- Token.decode(value),
         {:ok, provider} <- issuer(settings, name, principal, token) do
      Renewal.renew(settings, provider, principal, token)
    else
      {:error, reason} when reason in [:unreadable, :not_found] -> :ask
      {:error, reason} -> {:error, reason}
    end
  end

  # Tokens kept before the issuing provider was recorded resolve as a sign-in would.
  defp issuer(settings, name, principal, %Token{owner: nil}),
    do: resolve(settings, name, principal)

  defp issuer(settings, name, _principal, %Token{owner: owner}),
    do: provider(settings, owner, name)

  defp resolve(settings, name, %Principal{id: id}) do
    id
    |> Owners.chain()
    |> Enum.find_value({:error, :not_found}, fn owner ->
      case provider(settings, owner, name) do
        {:error, :not_found} -> nil
        found -> found
      end
    end)
  end

  defp provider(settings, owner, name) do
    with {:ok, provider} <- defined(settings, owner, name), do: usable(settings, provider)
  end

  defp defined(settings, owner, name) do
    with :error <- Map.fetch(configured(settings, owner), name) do
      case WardrikStore.get(settings.store, provider_key(owner, name)) do
        nil -> {:error, :not_found}
        opts -> {:ok, added(owner, name, opts)}
      end
    end
  end

  defp owned(settings, owner) do
    prefix = provider_key(owner, "")

    added =
      for {key, opts, _vsn} <- WardrikStore.entries(settings.store, prefix),
          do: added(owner, String.replace_prefix(key, prefix, ""), opts)

    Enum.sort_by(Map.values(configured(settings, owner)) ++ added, & &1.name)
  end

  defp configured(settings, owner),
    do: if(owner == Resource.deployment(), do: settings.providers, else: %{})

  defp added(owner, name, opts),
    do: %{Provider.new(name, opts) | owner: owner, source: :runtime}

  defp usable(settings, %Provider{client_secret: secret} = provider) do
    case client_secret(settings, provider) do
      {:ok, value} ->
        {:ok, Registration.registered(settings, %{provider | client_secret: value})}

      {:error, _reason} ->
        {:error,
         "#{provider.name}'s client_secret, #{inspect(secret)}, isn't sealed for #{provider.owner}"}
    end
  end

  defp client_secret(settings, %Provider{client_secret: {:secret, name}, owner: owner}),
    do: WardrikVault.fetch(settings.vault, %Principal{id: owner}, name)

  defp client_secret(_settings, %Provider{client_secret: secret}), do: {:ok, secret}

  defp provider_key(owner, name), do: "providers/" <> Provider.path(owner, name)

  defp over_current(vault, principal, name) do
    case WardrikVault.lookup(vault, principal, name) do
      {:ok, _kind, _value, vsn} -> [if_vsn: vsn]
      {:error, :not_found} -> [if_vsn: nil]
      _unreadable -> []
    end
  end
end
