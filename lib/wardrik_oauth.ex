defmodule WardrikOAuth do
  @moduledoc """
  OAuth sign-in for WardrikCore agents. Tokens are sealed in a `WardrikVault`.

      children = [
        {WardrikVault, name: MyApp.Vault, store: store, keys: keys, grants: {WardrikOAuth, MyApp.OAuth}},
        {WardrikOAuth,
         name: MyApp.OAuth,
         vault: MyApp.Vault,
         store: store,
         page: "https://agents.example.com/oauth",
         resolver: {MyApp.OAuthApps, []},
         on_granted: {MyApp.Agents, :granted, []}}
      ]

    * Mount `WardrikOAuth.Plug` at `page` to finish sign-ins.
    * `:resolver` gives the OAuth app each user signs in with. See `WardrikOAuth.Resolver`.
    * A token is refreshed only by the OAuth app that issued it.
  """

  @behaviour WardrikVault.Grants

  use Supervisor

  alias WardrikCore.Principal
  alias WardrikOAuth.Flow
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Registration
  alias WardrikOAuth.Renewal
  alias WardrikOAuth.Resolver
  alias WardrikOAuth.Token
  alias WardrikVault.Grants
  alias WardrikVault.Secret

  @schema NimbleOptions.new!(
            name: [type: :atom, required: true, doc: "The name functions reach it by."],
            vault: [type: :any, required: true, doc: "The `WardrikVault` grants are sealed in."],
            store: [
              type: :any,
              required: true,
              doc: "The `WardrikStore` for the clients Wardrik registers."
            ],
            page: [
              type: :string,
              required: true,
              doc: """
              The URL `WardrikOAuth.Plug` is mounted at, as `"https://agents.example.com/oauth"`.
              """
            ],
            resolver: [
              type: :mod_arg,
              required: true,
              doc: """
              `{module, config}`, the `WardrikOAuth.Resolver` that gives each user's providers.
              """
            ],
            on_granted: [
              type: {:or, [:mfa, nil]},
              default: nil,
              doc: """
              `{module, function, args}` called with the provider's name and the principal, then
              `args`, after each sign-in.
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
              Called on each URL before a request, returning `:ok` or `{:error, reason}`. Use one
              when users add providers by URL. Without it, any `https` URL, and `http` on
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
    Supervisor.start_link(__MODULE__, Map.new(opts), name: Keyword.fetch!(opts, :name))
  end

  @doc "Returns the Client ID Metadata Document served at `{page}/client`."
  @spec client_document(atom()) :: map()
  def client_document(oauth), do: oauth |> settings() |> Registration.document()

  @doc """
  Forgets the client Wardrik registered for the provider `key`. Call it when you delete that app.

      :ok = WardrikOAuth.forget_client(MyApp.OAuth, "linear/app_1")
  """
  @spec forget_client(atom(), String.t()) :: :ok | {:error, term()}
  def forget_client(oauth, key), do: oauth |> settings() |> Registration.forget(key)

  @doc """
  Returns the URL where `principal` signs in with the provider `name`.

  Starts a sign-in, or returns the URL of the one under way.
  """
  @spec authorize(atom(), String.t(), Principal.t()) :: {:ok, String.t()} | {:error, term()}
  def authorize(oauth, name, principal) do
    with {:authorize, url} <- begin(settings(oauth), name, principal), do: {:ok, url}
  end

  @doc """
  Describes the device sign-in `id`, for a CLI to show its code.

  Returns `{:ok, map}` with `:provider`, `:principal`, `:user_code` and `:verification_uri`, or
  `:error` if it has ended.
  """
  @spec flow(atom(), String.t()) :: {:ok, map()} | :error
  def flow(oauth, id) do
    case Registry.lookup(registry(oauth), {:id, id}) do
      [{pid, _value}] -> described(pid)
      [] -> :error
    end
  end

  @doc """
  Returns whether `principal`'s sign-in to the provider `name` is under way.

      WardrikOAuth.signing_in?(MyApp.OAuth, "github", principal)
      #=> true

  `false` once it's granted, declined or expired.
  """
  @spec signing_in?(atom(), String.t(), Principal.t()) :: boolean()
  def signing_in?(oauth, name, %Principal{id: id}),
    do: Registry.lookup(registry(oauth), {:flow, name, id}) != []

  defp described(pid) do
    {:ok, Flow.describe(pid)}
  catch
    :exit, _ended -> :error
  end

  @doc """
  Finishes a browser sign-in from its callback's query params. `WardrikOAuth.Plug` calls it.

      WardrikOAuth.finish(MyApp.OAuth, params, as: current_principal)
      #=> {:ok, %{provider: "github", principal: %WardrikCore.Principal{id: "user:jon"}}}

  `as:` is who is signed in to your app at the browser.

    * `{:error, :wrong_principal}` - someone else started it. It stays open for them.
    * `{:error, :no_such_flow}` - it has ended.
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
  def ask(%Grants.Request{name: name, principal: principal}, oauth),
    do: begin(settings(oauth), name, principal)

  @impl WardrikVault.Grants
  def renew(%Grants.Request{name: name, principal: principal, grant: %{value: value}}, oauth) do
    settings = settings(oauth)

    case renewed(settings, name, principal, value) do
      :ask -> begin(settings, name, principal)
      renewed -> renewed
    end
  end

  @impl WardrikVault.Grants
  def refused(%Grants.Request{name: name, principal: principal}, oauth),
    do: Renewal.expire(settings(oauth), name, principal)

  @doc false
  def keep(settings, provider, principal, %Token{} = token) do
    condition = over_current(settings.vault, principal, provider.name)

    value = Token.encode(%{token | provider: provider.key})
    secret = %Secret{principal: principal, name: provider.name, value: value}
    WardrikVault.put(settings.vault, secret, [kind: :grant] ++ condition)
  end

  @impl Supervisor
  def init(opts) do
    settings = %{
      vault: Map.fetch!(opts, :vault),
      store: opts |> Map.fetch!(:store) |> WardrikStore.scope("wardrik_oauth"),
      client_name: opts.client_name,
      page: opts |> Map.fetch!(:page) |> String.trim_trailing("/"),
      resolver: opts.resolver,
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
        if key == token.provider,
          do: Renewal.renew(settings, provider: provider, principal: principal, token: token),
          else: :ask

      {:error, :not_found} ->
        :ask

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp resolve(settings, name, principal) do
    with {:ok, provider} <-
           Resolver.resolve(settings, %Resolver.Request{name: name, principal: principal}),
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
