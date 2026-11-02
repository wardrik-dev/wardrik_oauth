# WardrikOAuth

OAuth sign-in for [WardrikCore](https://hexdocs.pm/wardrik_core) agents. Tokens are sealed in a
[WardrikVault](https://hexdocs.pm/wardrik_vault). [Wardrik](https://hexdocs.pm/wardrik) sets this
up for you; see [Credentials and sign-ins](https://hexdocs.pm/wardrik/credentials.html).

## Install

```elixir
{:wardrik_oauth, "~> 0.1.0-rc.2"}
```

## Start it

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

Your resolver returns the OAuth app each user signs in with, by name:

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

  def provider(%{name: "linear", principal: user}, _opts) do
    case MyApp.Teams.linear_app(user.id) do
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

- A provider's name is the credential a tool asks for, such as `"google"`.
- Its `key` names the OAuth app. Two keys never share a client or a token.
- See `WardrikOAuth.Provider` for every option, such as `flow: :device` or `client_auth: :basic`.
- Without a `client_id`, Wardrik registers its own where the service allows.
  See `WardrikOAuth.Registration`.

## Mount the pages

```elixir
forward "/oauth", WardrikOAuth.Plug,
  oauth: MyApp.OAuth,
  principal: {MyApp.Session, :principal, []}
```

- `/callback` finishes a browser sign-in. Register it as each OAuth app's redirect URI.
- `/device/:id` shows a device sign-in's code.
- `/client` serves Wardrik's own client ID document.
- `:principal` returns who is signed in to your app at the browser. Only they can finish their
  sign-in.

## Give it to agents

Pass the vault as an agent's `credentials`. Tools ask for a credential by name, as a `WardrikMCP`
server's `credential_name: "github"` does.

```elixir
WardrikCore.start_agent(
  agent_id: "digest",
  model: "anthropic:claude-haiku-4-5",
  principal: %WardrikCore.Principal{id: "user:jon"},
  credentials: {WardrikVault, MyApp.Vault},
  capabilities: [{WardrikMCP, name: MyApp.MCP, servers: [:github]}]
)
```

- A tool that needs `github` before Jon signs in parks on a sign-in URL.
- Once he signs in, the token is sealed and `on_granted` is called with `"github"` and Jon.
  Resume the parked agent there.
```elixir
defmodule MyApp.SignIns do
  alias WardrikCore.Authorization

  def granted(name, user) do
    for id <- WardrikCore.list(),
        agent = WardrikCore.whereis(id),
        agent != nil,
        waits_on?(agent, name, user),
        do: WardrikCore.resume(agent, %{}, %{principal: user})
  end

  defp waits_on?(agent, name, %{id: id}) do
    case WardrikCore.parked(agent) do
      {:tool_calls, results} ->
        Enum.any?(results, &match?({_call, {:park, %Authorization{credential: ^name, principal: %{id: ^id}}}}, &1))

      _reason ->
        false
    end
  end
end
```

- A sign-in expires after 15 minutes. Asking again while one is under way returns the same URL.
- An expired token is refreshed by the OAuth app that issued it. If that fails, Jon signs in again.
