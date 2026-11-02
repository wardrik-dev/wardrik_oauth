defmodule WardrikOAuth.ResolverTest do
  use ExUnit.Case, async: false

  defp credential(name, principal),
    do: %WardrikCore.Credentials.Request{name: name, principal: principal}

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
    opts =
      [key: key, issuer: GitHub.issuer()] ++
        if(client_id, do: [client_id: client_id], else: []) ++
        if(secret, do: [client_secret: secret], else: [])

    {:ok, Provider.new("github", opts)}
  end

  defp client_id({:ok, %{url: url}}), do: client_id({:authorize, url})
  defp client_id({:authorize, url}), do: URI.decode_query(URI.parse(url).query)["client_id"]

  defp sign_in(oauth, principal) do
    {:ok, %{url: url}} = WardrikOAuth.authorize(oauth, "github", principal)
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
  end

  test "refreshes a grant only with the provider that issued it, never another app's client", %{
    oauth: oauth,
    vault: vault,
    apps: apps
  } do
    give(apps, @jon, "github", app("acme-github", "acme-client", "acme-secret"))
    sign_in(oauth, @jon)

    give(apps, @jon, "github", app("globex-github", "globex-client", "globex-secret"))
    :ok = WardrikVault.refused(credential("github", @jon), vault)

    assert {:authorize, url} = WardrikVault.resolve(credential("github", @jon), vault)
    assert client_id({:authorize, url}) == "globex-client"
    refute_received {:refreshed, _token}

    give(apps, @jon, "github", app("acme-github", "acme-client", "acme-secret-2"))
    assert WardrikVault.resolve(credential("github", @jon), vault) == {:ok, "fresh"}
    assert_received {:refreshed_as, "acme-client", "acme-secret-2"}
  end

  test "keeps the client it registers for each app, not each name", %{oauth: oauth, apps: apps} do
    give(apps, @jon, "github", app("acme-github", nil))
    give(apps, @ada, "github", app("globex-github", nil))

    assert {:ok, _sign_in} = WardrikOAuth.authorize(oauth, "github", @jon)
    assert_receive {:registered, _request}
    assert {:ok, _sign_in} = WardrikOAuth.authorize(oauth, "github", @ada)
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

  test "needs a resolver" do
    assert_raise NimbleOptions.ValidationError, ~r/required :resolver option not found/, fn ->
      WardrikOAuth.start_link(
        name: :unresolved,
        vault: :vault,
        store: :store,
        page: "https://agents.test/oauth"
      )
    end
  end

  test "forgets the client it registered for an app", %{oauth: oauth, apps: apps} do
    give(apps, @jon, "github", app("acme-github", nil))
    assert {:ok, _sign_in} = WardrikOAuth.authorize(oauth, "github", @jon)
    assert_receive {:registered, _request}

    assert :ok = WardrikOAuth.forget_client(oauth, "acme-github")
    give(apps, @ada, "github", app("acme-github", nil))
    assert {:ok, _sign_in} = WardrikOAuth.authorize(oauth, "github", @ada)
    assert_receive {:registered, _request}
  end
end
