# WardrikOAuth

OAuth sign-in for [WardrikCore](https://hexdocs.pm/wardrik_core) agents, with each grant kept sealed
in a [WardrikVault](https://hexdocs.pm/wardrik_vault).

## Install

```elixir
def deps do
  [
    {:wardrik_oauth, "~> 0.1"}
  ]
end
```

## Start it

Register an OAuth app with each service, and give its client ID and secret as a provider. Give the
vault `WardrikOAuth` as its grants:

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

A provider is named like the credential it grants, so a tool that needs `google` signs in through
the `google` provider. Its endpoints are found from the `issuer`'s metadata. For a service that
publishes none, like Linear, give `authorization_endpoint` and `token_endpoint` instead.

`authorization_params` are sent with a browser sign-in. Google hands back a refresh token only
when asked for `access_type: "offline"`.

The client's secret is sent in the form by default. Some services, like Notion, want it in an HTTP
Basic header instead, so set `client_auth: :basic`:

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

| Option | Takes | Unless set |
| --- | --- | --- |
| `issuer` | the authorization server, whose metadata names its endpoints | found from `resource` |
| `resource` | the API or MCP server the token is for | not sent |
| `authorization_endpoint`, `token_endpoint` | the endpoints, for a service that publishes no metadata | discovered |
| `client_id`, `client_secret` | your OAuth app's | Wardrik's own, where the service allows; see [Without a client ID](#without-a-client-id) |
| `client_auth` | `:post` or `:basic`, how the secret is sent | `:post` |
| `scopes` | what to ask for | none |
| `flow` | `:browser` or `:device` | `:browser` |
| `authorization_params` | more to send with a browser sign-in | none |

A `client_secret` written `{:secret, name}`, as GitHub's above, is the deployment's secret of that
name in the vault, read each time a sign-in needs it, so changing it takes no restart:
`WardrikVault.put(MyApp.Vault, WardrikVault.deployment(), "GITHUB_CLIENT_SECRET", secret)`.

## Give it to agents

An agent reads its principal's grants through the vault, as its `credentials`. A tool asks for the
credential by the provider's name, like an MCP server's `credential_name`:

```elixir
children = [
  # ...the store, vault and WardrikOAuth above, then:
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

The first call that needs `github` before Jon has signed in waits on a sign-in. Once Jon has,
`on_granted` gets the provider's name and Jon's principal. Resume the agents waiting on it there:

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

With [Wardrik](https://hexdocs.pm/wardrik), all of this is done for you. See
[Credentials and sign-ins](https://hexdocs.pm/wardrik/credentials.html).

## Add providers as the app runs

A provider can be added while the app runs, and every node sees it. One without a `client_id`
registers Wardrik with the service the first time someone signs in, as RFC 7591 says, the way an
MCP server's own authorization server expects:

```elixir
:ok = WardrikOAuth.add_provider(MyApp.OAuth, "linear", resource: "https://mcp.linear.app/mcp")
WardrikOAuth.authorize(MyApp.OAuth, "linear", maria)
#=> {:ok, "https://mcp.linear.app/authorize?client_id=...&state=..."}

WardrikOAuth.providers(MyApp.OAuth)
#=> ["github", "google", "linear"]


:ok = WardrikOAuth.remove_provider(MyApp.OAuth, "linear")
```

The registration is kept in the store, so it happens once. `client_name` names Wardrik on the
service's page, `"Wardrik"` unless set. `providers/1` lists the providers someone can sign in with.

## Mount the pages

A sign-in comes back to your app, so mount `WardrikOAuth.Plug` at `page`. In a Phoenix router:

```elixir
scope "/" do
  forward "/oauth", WardrikOAuth.Plug, oauth: MyApp.OAuth
end
```

In a `Plug.Router`, served by Bandit or Cowboy:

```elixir
forward "/oauth", to: WardrikOAuth.Plug, init_opts: [oauth: MyApp.OAuth]
```

It serves three pages under `page`:

| Path | What it does |
| --- | --- |
| `/callback` | Finishes a browser sign-in. Register `page` followed by `/callback` as each OAuth app's redirect URI, like `https://agents.example.com/oauth/callback`. |
| `/device/:id` | Shows a device sign-in's code, and where to enter it. |
| `/client` | The Client ID Metadata Document a service reads Wardrik's `client_id` from. |

### Without a client ID

A provider given no `client_id`, as one an MCP server's owner adds by its URL, gets Wardrik's own
the first time someone signs in, and every node keeps it:

- Where the service reads Client ID Metadata Documents, as its metadata's
  `client_id_metadata_document_supported` says, and `page` is `https` on a host the service can
  reach, the `client_id` is the URL of the document at `/client`, as
  `https://agents.example.com/oauth/client`. Nothing is registered, and the consent screen shows
  `client_name`.
- Otherwise Wardrik registers itself with the service's `registration_endpoint`, as RFC 7591 says.
- With neither, signing in fails with `{:no_client, name}`, and the provider needs a `client_id` of
  your own.

To handle the callback in a route of your own, call `WardrikOAuth.finish/2` with its query
parameters. It returns `{:ok, provider}` or `{:error, reason}`.

## Sign in

When a tool needs a credential its principal hasn't authorized, its call parks on a sign-in URL.

- In a browser sign-in, the default, it's the service's own page. The principal signs in there, and
  comes back to `/callback`.
- In a device sign-in, `flow: :device`, it's `/device/:id`, which shows a code to enter on any
  device. `WardrikOAuth.flow/2` returns the same code, for a CLI to show.

Once they've authorized, the token is sealed in the vault, and `on_granted` is called with the
provider's name and the principal. Resume the turns parked on it from there.
`[:wardrik_oauth, :flow, :done]` is emitted as every sign-in ends, for watching.

A sign-in ends after 15 minutes. Only one runs for a provider and principal at a time, and asking
again returns the same URL.

## Renewing

An expired token is refreshed before anyone is asked again, and a token a service refused is
refreshed on its next use. When it can't be refreshed, the principal is asked to sign in again.

Refreshes take a cluster-wide lock, so two nodes never spend the same refresh token.
