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

  With `:resolver`, your app says which provider each principal signs in with. See
  `WardrikOAuth.Resolver`. Without it, providers belong to owners: those in `:providers` are the
  deployment's, and `add_provider/4` adds an org's or a person's. See `WardrikOAuth.Owners`.

  Grants never fall back. Each belongs to the principal who signed in, and is refreshed only by
  the provider that issued it. If they now sign in with another, they sign in again.
  """

  @behaviour WardrikVault.Grants

  use Supervisor

  alias WardrikCore.Principal
  alias WardrikOAuth.Flow
  alias WardrikOAuth.Owners
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Registration
  alias WardrikOAuth.Renewal
  alias WardrikOAuth.Resolver
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
            resolver: [
              type: {:or, [:mod_arg, nil]},
              default: nil,
              doc: """
              `{module, config}`, the `WardrikOAuth.Resolver` that gives each principal's
              providers. Without it, they're resolved along the owner chain.
              """
            ],
            providers: [
              type: {:list, {:tuple, [{:or, [:atom, :string]}, :keyword_list]}},
              default: [],
              doc: """
              The deployment's providers, by name, without `:resolver`. See
              `WardrikOAuth.Provider`.
              """
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

    if opts[:resolver] && opts[:providers] != [],
      do: raise(ArgumentError, "Give providers through :resolver, not :providers, when it's set")

    Supervisor.start_link(__MODULE__, Map.new(opts), name: name)
  end

  @doc """
  Adds `owner`'s provider `name` at runtime, on every node, without `:resolver`.

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

  Returns `{:error, reason}` for invalid options, a `client_secret` given as is, the
  deployment's provider of a name in `:providers`, or with `:resolver`.
  """
  @spec add_provider(atom(), Wardrik.Owners.t(), String.t(), keyword()) ::
          :ok | {:error, String.t()}
  def add_provider(oauth, owner, name, opts) when is_binary(owner) and is_binary(name) do
    settings = settings(oauth)
    Provider.new(name, opts)

    cond do
      settings.resolver ->
        {:error, "providers come from the resolver"}

      Wardrik.Owners.parse(owner) == :error ->
        {:error, "#{owner} isn't an owner"}

      is_binary(opts[:client_secret]) ->
        {:error, "#{name}'s client_secret must be {:secret, name}"}

      Owners.configured?(settings, owner, name) ->
        {:error, "#{name} is a provider the app starts with"}

      true ->
        with {:ok, _vsn} <- WardrikStore.put(settings.store, Owners.store_key(owner, name), opts),
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
  @spec remove_provider(atom(), Wardrik.Owners.t(), String.t()) :: :ok | {:error, term()}
  def remove_provider(oauth, owner, name) do
    settings = settings(oauth)

    with :ok <- WardrikStore.delete(settings.store, Owners.store_key(owner, name)),
         do: Registration.forget(settings, Owners.key(owner, name))
  end

  @doc """
  Returns the providers `owner` can sign in with, nearest first along `Wardrik.Owners.chain/1`.

      WardrikOAuth.providers(MyApp.OAuth, "acme/@jon")
      #=> [%WardrikOAuth.Provider{name: "linear", owner: "acme", source: :runtime, ...}, ...]

  Only the nearest provider of each name is given. A `client_secret` is as it was given, not read.
  With `:resolver`, there are none: your app knows its own.
  """
  @spec providers(atom(), Wardrik.Owners.t()) :: [Provider.t()]
  def providers(oauth, owner) do
    case settings(oauth) do
      %{resolver: nil} = settings -> Owners.providers(settings, owner)
      _resolved -> []
    end
  end

  @doc """
  Returns the URL where `principal` signs in with the provider `name`, as it resolves for them.

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
  Finishes a browser sign-in from its callback's query params, for the principal `as` names.

      WardrikOAuth.finish(MyApp.OAuth, params, as: current_principal)
      #=> {:ok, %{provider: "github", principal: %WardrikCore.Principal{id: "acme/@jon"}}}

  The params carry `"state"`, and `"code"` or `"error"`. Only the principal who started the sign-in
  can finish it: anyone else gets `{:error, :wrong_principal}`, and the sign-in stays open for
  them. That stops someone else's link from connecting your account to their agents. Returns
  `{:error, :no_such_flow}` if the sign-in has ended.

  `as` is whoever your app knows is at the browser, as from their session. `WardrikOAuth.Plug`
  calls this with the principal its `:principal` option returns.
  """
  @spec finish(atom(), map(), keyword()) ::
          {:ok, %{provider: String.t(), principal: Principal.t()}} | {:error, term()}
  def finish(oauth, params, opts) do
    %Principal{} = principal = Keyword.fetch!(opts, :as)

    with %{"state" => state} when is_binary(state) <- params,
         [{pid, _value}] <- Registry.lookup(registry(oauth), {:state, state}) do
      finished(pid, params, principal)
    else
      _none -> {:error, :no_such_flow}
    end
  end

  defp finished(pid, params, principal) do
    Flow.finish(pid, params, principal)
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
      Token.encode(%{token | provider: provider.key}),
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
      resolver: opts.resolver,
      providers:
        Map.new(opts.providers, fn {name, provider} ->
          {to_string(name), Owners.deployment(name, provider)}
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

  # A fresh token is used as it is. An expired one is refreshed only by the provider that issued
  # it, so its refresh token and the provider's client never meet another app's.
  defp renewed(settings, name, principal, value) do
    case Token.decode(value) do
      {:ok, token} ->
        if Token.fresh?(token),
          do: {:ok, token.access_token},
          else: refreshed(settings, name, principal, token)

      {:error, :unreadable} ->
        :ask
    end
  end

  defp refreshed(settings, name, principal, token) do
    case resolve(settings, name, principal) do
      {:ok, %Provider{key: key} = provider} ->
        if key == issuer(settings, name, token),
          do: Renewal.renew(settings, provider, principal, token),
          else: :ask

      {:error, :not_found} ->
        :ask

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Tokens kept before the issuer was recorded came from the deployment's provider.
  defp issuer(%{resolver: nil}, name, %Token{provider: nil}),
    do: Owners.key(Wardrik.Resource.deployment(), name)

  defp issuer(_settings, _name, %Token{provider: key}), do: key

  defp resolve(settings, name, principal) do
    with {:ok, provider} <- Resolver.resolve(settings, name, principal),
         do: {:ok, Registration.registered(settings, provider)}
  end

  defp over_current(vault, principal, name) do
    case WardrikVault.lookup(vault, principal, name) do
      {:ok, _kind, _value, vsn} -> [if_vsn: vsn]
      {:error, :not_found} -> [if_vsn: nil]
      _unreadable -> []
    end
  end
end
