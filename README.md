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
   on_granted: {MyApp.Agents, :granted, []},
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
       client_secret: System.fetch_env!("GITHUB_CLIENT_SECRET"),
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
| `client_id`, `client_secret` | your OAuth app's | registered by Wardrik, where the service allows |
| `client_auth` | `:post` or `:basic`, how the secret is sent | `:post` |
| `scopes` | what to ask for | none |
| `flow` | `:browser` or `:device` | `:browser` |
| `authorization_params` | more to send with a browser sign-in | none |

## Add providers as the app runs

A provider can be added while the app runs, and every node sees it. One without a `client_id`
registers Wardrik with the service the first time someone signs in, as RFC 7591 says, the way an
MCP server's own authorization server expects:

```elixir
:ok = WardrikOAuth.add_provider(MyApp.OAuth, "linear", resource: "https://mcp.linear.app/mcp")
{:ok, url} = WardrikOAuth.authorize(MyApp.OAuth, "linear", maria)

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

It serves two pages under `page`:

| Path | What it does |
| --- | --- |
| `/callback` | Finishes a browser sign-in. Register `page` followed by `/callback` as each OAuth app's redirect URI, like `https://agents.example.com/oauth/callback`. |
| `/device/:id` | Shows a device sign-in's code, and where to enter it. |

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
