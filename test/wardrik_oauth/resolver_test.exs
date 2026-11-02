defmodule WardrikOAuth.Test.Apps do
  @moduledoc "Resolves each principal's providers as the test set them, in an `Agent`."
  @behaviour WardrikOAuth.Resolver

  @impl true
  def provider(name, principal, apps) do
    Agent.get(apps, fn set ->
      send(set.test, {:resolved, name, principal.id})
      Map.get(set, {principal.id, name}, {:error, :not_found})
    end)
  end
end

defmodule WardrikOAuth.ResolverTest do
  use ExUnit.Case, async: false

  alias WardrikCore.Principal
  alias WardrikOAuth.GitHub
  alias WardrikOAuth.Provider

  @jon %Principal{id: "user_jon"}
  @ada %Principal{id: "user_ada"}

  setup {Req.Test, :set_req_test_to_shared}

  setup context do
    {:ok, polls} = Agent.start_link(fn -> [] end)
    Req.Test.stub(GitHub, GitHub.plug(polls, self()))

    store = WardrikStore.ETS.new(name: :"store #{context.test}")
    vault = :"vault #{context.test}"
    oauth = :"oauth #{context.test}"
    test = self()
    apps = start_supervised!({Agent, fn -> %{test: test} end})

    start_supervised!({WardrikStore, store})

    start_supervised!(
      {WardrikVault,
       name: vault,
       store: store,
       keys: [WardrikVault.generate_key()],
       grants: {WardrikOAuth, oauth}}
    )

    start_supervised!(
      {WardrikOAuth,
       name: oauth,
       vault: vault,
       store: store,
       page: "https://agents.test/oauth",
       resolver: {WardrikOAuth.Test.Apps, apps},
       req_options: [plug: {Req.Test, GitHub}]}
    )

    %{oauth: oauth, vault: vault, apps: apps}
  end

  defp give(apps, principal, name, result),
    do: Agent.update(apps, &Map.put(&1, {principal.id, name}, result))

  defp app(key, client_id, secret \\ nil) do
    opts = [issuer: GitHub.issuer()] ++ if(client_id, do: [client_id: client_id], else: [])
    provider = Provider.new("github", opts)
    {:ok, %{provider | key: key, client_secret: secret}}
  end

  defp client_id({_signs_in, url}), do: URI.decode_query(URI.parse(url).query)["client_id"]

  defp sign_in(oauth, principal) do
    {:ok, url} = WardrikOAuth.authorize(oauth, "github", principal)
    state = URI.decode_query(URI.parse(url).query)["state"]
    params = %{"state" => state, "code" => "c", "iss" => GitHub.issuer()}
    {:ok, _signed_in} = WardrikOAuth.finish(oauth, params, as: principal)
  end

  test "signs each principal in only with the provider the resolver gives them", %{
    oauth: oauth,
    apps: apps
  } do
    give(apps, @jon, "github", app("acme-github", "acme-client"))
    give(apps, @ada, "github", app("globex-github", "globex-client"))

    assert client_id(WardrikOAuth.authorize(oauth, "github", @jon)) == "acme-client"
    assert_received {:resolved, "github", "user_jon"}
    assert client_id(WardrikOAuth.authorize(oauth, "github", @ada)) == "globex-client"

    assert WardrikOAuth.authorize(oauth, "github", %Principal{id: "user_bo"}) ==
             {:error, :not_found}

    assert WardrikOAuth.providers(oauth, "acme") == []

    assert WardrikOAuth.add_provider(oauth, "acme", "github", issuer: GitHub.issuer()) ==
             {:error, "providers come from the resolver"}
  end

  test "refreshes a grant only with the provider that issued it, never another app's client", %{
    oauth: oauth,
    vault: vault,
    apps: apps
  } do
    give(apps, @jon, "github", app("acme-github", "acme-client", "acme-secret"))
    sign_in(oauth, @jon)

    give(apps, @jon, "github", app("globex-github", "globex-client", "globex-secret"))
    :ok = WardrikVault.refused("github", @jon, vault)

    assert {:authorize, url} = WardrikVault.resolve("github", @jon, vault)
    assert client_id({:authorize, url}) == "globex-client"
    refute_received {:refreshed, _token}

    give(apps, @jon, "github", app("acme-github", "acme-client", "acme-secret-2"))
    assert WardrikVault.resolve("github", @jon, vault) == {:ok, "fresh"}
    assert_received {:refreshed_as, "acme-client", "acme-secret-2"}
  end

  test "keeps the client it registers for each app, not each name", %{oauth: oauth, apps: apps} do
    give(apps, @jon, "github", app("acme-github", nil))
    give(apps, @ada, "github", app("globex-github", nil))

    assert {:ok, _url} = WardrikOAuth.authorize(oauth, "github", @jon)
    assert_receive {:registered, _request}
    assert {:ok, _url} = WardrikOAuth.authorize(oauth, "github", @ada)
    assert_receive {:registered, _request}
  end

  test "signs in with nothing the resolver doesn't give as it should", %{
    oauth: oauth,
    apps: apps
  } do
    give(apps, @jon, "github", {:error, :down})
    assert WardrikOAuth.authorize(oauth, "github", @jon) == {:error, :down}

    {:ok, github} = app("acme-github", "acme-client")

    for {given, why} <- [
          {%{github | name: "gitlab"}, "it's named gitlab"},
          {%{github | key: nil}, "it has no key"},
          {%{github | key: ""}, "it has no key"},
          {%{github | client_secret: {:secret, "GITHUB"}},
           "its client_secret isn't the secret itself"}
        ] do
      give(apps, @jon, "github", {:ok, given})

      assert WardrikOAuth.authorize(oauth, "github", @jon) ==
               {:error, "github doesn't resolve: #{why}"}
    end

    give(apps, @jon, "github", github)

    assert WardrikOAuth.authorize(oauth, "github", @jon) ==
             {:error, "github doesn't resolve: it's #{inspect(github)}"}

    refute_received {:registered, _request}
  end

  test "takes providers from the resolver alone" do
    assert_raise ArgumentError, ~r/through :resolver/, fn ->
      WardrikOAuth.start_link(
        name: :both,
        vault: :vault,
        store: :store,
        page: "https://agents.test/oauth",
        resolver: {WardrikOAuth.Test.Apps, nil},
        providers: [github: [issuer: GitHub.issuer()]]
      )
    end
  end
end
