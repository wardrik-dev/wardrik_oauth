# WardrikOAuth

OAuth sign-in for [WardrikCore](https://hexdocs.pm/wardrik_core) agents. Each grant is sealed in a
[WardrikVault](https://hexdocs.pm/wardrik_vault).

## Install

```elixir
def deps do
  [
    {:wardrik_oauth, "~> 0.1.0-rc.2"}
  ]
end
```

## Start it

Register an OAuth app with each service. Your app says which one each principal signs in with,
through a resolver. Pass `WardrikOAuth` to the vault as its `grants`:

```elixir
children = [
  {WardrikStore, store},
  {WardrikVault, name: MyApp.Vault, store: store, keys: keys, grants: {WardrikOAuth, MyApp.OAuth}},
  {WardrikOAuth,
   name: MyApp.OAuth,
   vault: MyApp.Vault,
   store: store,
   page: "https://agents.example.com/oauth",
   resolver: {MyApp.OAuthApps, []},
   on_granted: {MyApp.SignIns, :granted, []}}
]
```

The resolver returns the provider a principal signs in with by its name:

```elixir
defmodule MyApp.OAuthApps do
  @behaviour WardrikOAuth.Resolver

  alias WardrikOAuth.Provider

  @impl true
  def provider(%{name: "google"}, _opts) do
    google =
      Provider.new("google",
        issuer: "https://accounts.google.com",
        client_id: System.fetch_env!("GOOGLE_CLIENT_ID"),
        scopes: ~w(openid email https://www.googleapis.com/auth/calendar.readonly),
        authorization_params: %{access_type: "offline", prompt: "consent"}
      )

    {:ok, %{google | key: "google", client_secret: System.fetch_env!("GOOGLE_CLIENT_SECRET")}}
  end

  def provider(%{name: "linear", principal: principal}, _opts) do
    case MyApp.Orgs.linear_app(principal.id) do
      nil ->
        {:error, :not_found}

      app ->
        linear =
          Provider.new("linear",
            authorization_endpoint: "https://linear.app/oauth/authorize",
            token_endpoint: "https://api.linear.app/oauth/token",
            client_id: app.client_id,
            scopes: ~w(read)
          )

        {:ok, %{linear | key: "linear/" <> app.id, client_secret: app.client_secret}}
    end
  end

  def provider(_request, _opts), do: {:error, :not_found}
end
```

A provider has the same name as the credential it grants. A tool that needs `google` signs in
through the `google` provider. Its `key` names the OAuth app, and is unique to it. Two apps never
share a registered client or a grant.

Endpoints are discovered from the `issuer`'s metadata. For a service without metadata, like
Linear, give `authorization_endpoint` and `token_endpoint`.

`authorization_params` are sent with a browser sign-in. Google only returns a refresh token when
asked for `access_type: "offline"`.

The client secret is sent in the form by default. Some services, like Notion, want HTTP Basic
instead. Set `client_auth: :basic`:

```elixir
Provider.new("notion",
  authorization_endpoint: "https://api.notion.com/v1/oauth/authorize",
  token_endpoint: "https://api.notion.com/v1/oauth/token",
  client_id: System.fetch_env!("NOTION_CLIENT_ID"),
  client_auth: :basic,
  authorization_params: %{owner: "user"}
)
```

### Provider options

| Option | Value | Default |
| --- | --- | --- |
| `issuer` | the authorization server, whose metadata names its endpoints | discovered from `resource` |
| `resource` | the API or MCP server the token is for | not sent |
| `authorization_endpoint`, `token_endpoint` | the endpoints, for a service without metadata | discovered |
| `client_id`, `client_secret` | your OAuth app's credentials | Wardrik's own, if the service allows; see [Without a client ID](#without-a-client-id) |
| `client_auth` | `:post` or `:basic`, how the secret is sent | `:post` |
| `scopes` | scopes to ask for | none |
| `flow` | `:browser` or `:device` | `:browser` |
| `authorization_params` | extra parameters for a browser sign-in | none |

A provider needs an `issuer`, a `resource`, or both endpoints.

## Give it to agents

Pass the vault as the agent's `credentials`. A tool asks for a credential by the provider's name,
as an MCP server's `credential_name` does:

```elixir
children = [
  # The store, vault and WardrikOAuth above, then:
  {WardrikMCP,
   name: MyApp.MCP,
   servers: [
     github: [
       transport: {:streamable_http, base_url: "https://api.githubcopilot.com/mcp/"},
       credential_name: "github"
     ]
   ]},
  {WardrikCore, backend: {WardrikStore.Durable, store: store}}
]

WardrikCore.start_agent(
  agent_id: "acme/@jon/digest",
  model: "anthropic:claude-haiku-4-5",
  principal: %WardrikCore.Principal{id: "acme/@jon"},
  credentials: {WardrikVault, MyApp.Vault},
  capabilities: [{WardrikMCP, name: MyApp.MCP, servers: [:github]}]
)
```

If Jon hasn't signed in, the first call that needs `github` parks on a sign-in. Once Jon signs in,
`on_granted` is called with the provider's name and Jon's principal. Resume the waiting agents
there:

```elixir
defmodule MyApp.SignIns do
  alias WardrikCore.Authorization

  def granted(provider, principal) do
    WardrikCore.list()
    |> Enum.map(&WardrikCore.whereis/1)
    |> Enum.filter(&waits_on?(&1, to_string(provider), principal))
    |> Enum.each(&WardrikCore.resume(&1, %{}, %{principal: principal}))
  end

  defp waits_on?(nil, _credential, _principal), do: false

  defp waits_on?(agent, credential, principal) do
    case WardrikCore.parked(agent) do
      {:tool_calls, results} -> Enum.any?(results, &signs_in?(&1, credential, principal))
      _reason -> false
    end
  end

  defp signs_in?({_call, {:park, %Authorization{credential: credential, principal: %{id: id}}}}, credential, %{id: id}),
    do: true

  defp signs_in?(_result, _credential, _principal), do: false
end
```

[Wardrik](https://hexdocs.pm/wardrik) does all of this for you. See
[Credentials and sign-ins](https://hexdocs.pm/wardrik/credentials.html).

## Grants

Each grant belongs to the principal who signed in, and records the key of the provider that
issued it. An expired grant is refreshed only by that provider. If the resolver now gives the
principal another app, they sign in again.

The resolver runs as each sign-in starts and as each expired grant is refreshed, so a changed
client secret takes no restart.

A provider without a `client_id` gets one the first time someone signs in. See
[Without a client ID](#without-a-client-id). The client is kept in the store under the provider's
`key`, so this happens once. Once you delete an app, forget its client:

```elixir
:ok = WardrikOAuth.forget_client(MyApp.OAuth, "linear/" <> app.id)
```

`client_name` is the name the service shows. `"Wardrik"` unless set.

## Mount the pages

Sign-ins come back to your app. Mount `WardrikOAuth.Plug` at `page`. In a Phoenix router:

```elixir
scope "/" do
  forward "/oauth", WardrikOAuth.Plug, oauth: MyApp.OAuth, principal: {MyApp.Session, :principal, []}
end
```

In a `Plug.Router`:

```elixir
forward "/oauth",
  to: WardrikOAuth.Plug,
  init_opts: [oauth: MyApp.OAuth, principal: {MyApp.Session, :principal, []}]
```

It serves three paths under `page`:

| Path | What it does |
| --- | --- |
| `/callback` | Finishes a browser sign-in. Register it as each OAuth app's redirect URI, as `https://agents.example.com/oauth/callback`. |
| `/device/:id` | Shows a device sign-in's code and where to enter it. |
| `/client` | Serves the Client ID Metadata Document for Wardrik's own `client_id`. |

`principal` returns who your app knows is at the browser. A sign-in finishes only for the
principal who started it.

To handle the callback in your own route, call `WardrikOAuth.finish/3` with its query params and
`as:` the principal. It returns `{:ok, %{provider: name, principal: principal}}` or
`{:error, reason}`.

### Without a client ID

A provider with no `client_id` gets Wardrik's own the first time someone signs in. It's kept in the
store for every node.

1. If the service supports Client ID Metadata Documents (`client_id_metadata_document_supported`
   in its metadata) and `page` is `https` and not localhost, the `client_id` is the `/client`
   URL, as `https://agents.example.com/oauth/client`. Nothing is registered. The consent screen shows
   `client_name`.
2. Otherwise, Wardrik registers itself at the service's `registration_endpoint` (RFC 7591).
3. If neither is possible, sign-in fails with `{:no_client, name}`. Give the provider your own
   `client_id`.

## Sign in

When a tool needs a credential its principal hasn't granted, the call parks on a sign-in URL.

* Browser sign-in (the default): the URL is the service's own page. The principal signs in there
  and returns to `/callback`.
* Device sign-in (`flow: :device`): the URL is `/device/:id`, which shows a code to enter on any
  device. `WardrikOAuth.flow/2` returns the same code, for a CLI to show.

Once the principal grants access:

1. The token is sealed in the vault.
2. `on_granted` is called with the provider's name and the principal. Resume parked turns there.

A sign-in expires after 15 minutes. Only one runs per provider and principal at a time. Asking
again returns the same URL.

`[:wardrik_oauth, :flow, :done]` is emitted when each sign-in ends, with `:provider`, `:principal`
and `:outcome` in its metadata.

## Renewing

An expired token is refreshed before the principal is asked again. A token the service refused is
refreshed on its next use. If it can't be refreshed, the principal is asked to sign in again.

Refreshes take a cluster-wide lock, so two nodes never spend the same refresh token.
