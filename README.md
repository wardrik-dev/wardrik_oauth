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

Register an OAuth app with each service and add it as a provider. Pass `WardrikOAuth` to the vault
as its `grants`:

```elixir
children = [
  {WardrikStore, store},
  {WardrikVault, name: MyApp.Vault, store: store, keys: keys, grants: {WardrikOAuth, MyApp.OAuth}},
  {WardrikOAuth,
   name: MyApp.OAuth,
   vault: MyApp.Vault,
   store: store,
   page: "https://agents.example.com/oauth",
   on_granted: {MyApp.SignIns, :granted, []},
   providers: [
     google: [
       issuer: "https://accounts.google.com",
       client_id: System.fetch_env!("GOOGLE_CLIENT_ID"),
       client_secret: System.fetch_env!("GOOGLE_CLIENT_SECRET"),
       scopes: ~w(openid email https://www.googleapis.com/auth/calendar.readonly),
       authorization_params: %{access_type: "offline", prompt: "consent"}
     ],
     linear: [
       authorization_endpoint: "https://linear.app/oauth/authorize",
       token_endpoint: "https://api.linear.app/oauth/token",
       client_id: System.fetch_env!("LINEAR_CLIENT_ID"),
       client_secret: System.fetch_env!("LINEAR_CLIENT_SECRET"),
       scopes: ~w(read)
     ],
     github: [
       issuer: "https://github.com/login/oauth",
       client_id: System.fetch_env!("GITHUB_CLIENT_ID"),
       client_secret: {:secret, "GITHUB_CLIENT_SECRET"},
       scopes: ~w(repo),
       flow: :device
     ]
   ]}
]
```

A provider has the same name as the credential it grants. A tool that needs `google` signs in
through the `google` provider.

Endpoints are discovered from the `issuer`'s metadata. For a service without metadata, like
Linear, give `authorization_endpoint` and `token_endpoint`.

`authorization_params` are sent with a browser sign-in. Google only returns a refresh token when
asked for `access_type: "offline"`.

The client secret is sent in the form by default. Some services, like Notion, want HTTP Basic
instead. Set `client_auth: :basic`:

```elixir
notion: [
  authorization_endpoint: "https://api.notion.com/v1/oauth/authorize",
  token_endpoint: "https://api.notion.com/v1/oauth/token",
  client_id: System.fetch_env!("NOTION_CLIENT_ID"),
  client_secret: System.fetch_env!("NOTION_CLIENT_SECRET"),
  client_auth: :basic,
  authorization_params: %{owner: "user"}
]
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

### Secrets in the vault

A `client_secret` of `{:secret, name}` is read from the provider's owner's vault secrets each
time it's needed. Providers in `:providers` are the deployment's. Changing it takes no restart:

```elixir
WardrikVault.put(MyApp.Vault, WardrikVault.deployment(), "GITHUB_CLIENT_SECRET", secret)
```

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

## Add providers at runtime

Providers added at runtime belong to an owner: `deployment`, an org like `acme`, or a person like
`acme/@maria`. They're kept in the store, so every node sees them:

```elixir
:ok =
  WardrikOAuth.add_provider(MyApp.OAuth, "acme", "linear",
    resource: "https://mcp.linear.app/mcp",
    client_id: "acme-linear",
    client_secret: {:secret, "LINEAR_CLIENT_SECRET"}
  )

WardrikOAuth.authorize(MyApp.OAuth, "linear", %WardrikCore.Principal{id: "acme/@maria"})
#=> {:ok, "https://mcp.linear.app/authorize?client_id=acme-linear&state=..."}

WardrikOAuth.providers(MyApp.OAuth, "acme/@maria")
#=> [%WardrikOAuth.Provider{name: "linear", owner: "acme", source: :runtime, ...}, ...]

:ok = WardrikOAuth.remove_provider(MyApp.OAuth, "acme", "linear")
```

A principal signs in with the nearest provider of a name along `Wardrik.Owners.chain/1`, so
`acme`'s `linear` comes ahead of the deployment's for Maria, and isn't offered outside `acme`. A
runtime provider's `client_secret` is only `{:secret, name}`, read from its owner's vault secrets.

Grants don't fall back. Each belongs to the principal who signed in, and is renewed with the
provider that issued it. If that provider is removed, the principal signs in again.

A provider without a `client_id` gets one the first time someone signs in. See
[Without a client ID](#without-a-client-id). The client is kept in the store, so this happens
once. `client_name` is the name the service shows. `"Wardrik"` unless set.

## Mount the pages

Sign-ins come back to your app. Mount `WardrikOAuth.Plug` at `page`. In a Phoenix router:

```elixir
scope "/" do
  forward "/oauth", WardrikOAuth.Plug, oauth: MyApp.OAuth
end
```

In a `Plug.Router`:

```elixir
forward "/oauth", to: WardrikOAuth.Plug, init_opts: [oauth: MyApp.OAuth]
```

It serves three paths under `page`:

| Path | What it does |
| --- | --- |
| `/callback` | Finishes a browser sign-in. Register it as each OAuth app's redirect URI, as `https://agents.example.com/oauth/callback`. |
| `/device/:id` | Shows a device sign-in's code and where to enter it. |
| `/client` | Serves the Client ID Metadata Document for Wardrik's own `client_id`. |

To handle the callback in your own route, call `WardrikOAuth.finish/2` with its query params. It
returns `{:ok, provider}` or `{:error, reason}`.

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
