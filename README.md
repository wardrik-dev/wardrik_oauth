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

Give the vault `WardrikOAuth` as its grants, and start `WardrikOAuth` with the vault's name and the
providers people can authorize:

```elixir
children = [
  {WardrikStore, store},
  {WardrikVault, name: MyApp.Vault, store: store, keys: keys, grants: {WardrikOAuth, MyApp.OAuth}},
  {WardrikOAuth,
   name: MyApp.OAuth,
   vault: MyApp.Vault,
   page: "https://agents.example.com/oauth",
   on_granted: {MyApp.Agents, :granted, []},
   providers: [
     github: [
       issuer: "https://github.com/login/oauth",
       client_id: System.fetch_env!("GITHUB_CLIENT_ID"),
       client_secret: System.fetch_env!("GITHUB_CLIENT_SECRET"),
       scopes: ~w(repo)
     ]
   ]}
]
```

A provider is named like the credential it grants. Give it an `issuer`, or a `resource` whose
metadata names one. Its endpoints are found from the issuer's metadata.

## Sign in

When a tool needs `github` for a principal who hasn't authorized it, its call parks on a URL:
`page` followed by `/device/<id>`. Show the principal the code for it:

```elixir
WardrikOAuth.flow(MyApp.OAuth, id)
#=> {:ok, %{provider: "github", user_code: "WDJB-MJHT", verification_uri: "https://github.com/login/device", ...}}
```

They enter the code on any device. Once they have, the token is sealed in the vault, and
`on_granted` is called with the provider's name and the principal. Resume the turns parked on it
from there. `[:wardrik_oauth, :flow, :done]` is emitted as every sign-in ends, for watching.

A sign-in ends after 15 minutes, or when its code expires. Only one runs for a provider and
principal at a time.

## Renewing

An expired token is refreshed before anyone is asked again, and a token a service refused is
refreshed on its next use. When it can't be refreshed, the principal is asked to sign in again.

Refreshes take a cluster-wide lock, so two nodes never spend the same refresh token.
