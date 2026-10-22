defmodule WardrikOAuthTest do
  use ExUnit.Case, async: false

  alias WardrikCore.Principal
  alias WardrikOAuth.GitHub
  alias WardrikOAuth.Token

  @jon %Principal{id: "user:jon"}
  @granted %{"access_token" => "gho_granted", "refresh_token" => "rt_1", "expires_in" => 3600}

  setup {Req.Test, :set_req_test_to_shared}

  setup context do
    {:ok, polls} = Agent.start_link(fn -> context[:polls] || [@granted] end)
    Req.Test.stub(GitHub, GitHub.plug(polls, self()))

    test = self()

    :telemetry.attach(
      context.test,
      [:wardrik_oauth, :flow, :done],
      &WardrikOAuth.TestHook.handle_event/4,
      test
    )

    on_exit(fn -> :telemetry.detach(context.test) end)

    store = WardrikStore.ETS.new(name: :"store #{context.test}")
    vault = :"vault #{context.test}"
    oauth = :"oauth #{context.test}"

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
       page: "https://agents.test/oauth/",
       on_granted: {WardrikOAuth.TestHook, :granted, [test]},
       req_options: [plug: {Req.Test, GitHub}],
       providers: [
         github: [
           issuer: GitHub.issuer(),
           client_id: "client",
           client_secret: "secret",
           scopes: ["repo"]
         ],
         copilot: [resource: "https://api.github.test/mcp/", client_id: "client"]
       ]}
    )

    %{vault: vault, oauth: oauth}
  end

  defp keep(vault, token),
    do: WardrikVault.put(vault, @jon, "github", Token.encode(token), kind: :grant)

  defp token(fields),
    do: struct!(Token, [token_endpoint: "https://github.test/login/oauth/access_token"] ++ fields)

  describe "signing in on another device" do
    @tag polls: [%{"error" => "authorization_pending"}, @granted]
    test "shows the code, then keeps the grant once it's entered", %{vault: vault, oauth: oauth} do
      assert {:authorize, "https://agents.test/oauth/device/" <> id = url} =
               WardrikVault.resolve("github", @jon, vault)

      assert {:ok,
              %{user_code: "WDJB-MJHT", verification_uri: "https://github.test/login/device"}} =
               WardrikOAuth.flow(oauth, id)

      assert WardrikVault.resolve("github", @jon, vault) == {:authorize, url}

      assert_receive {:granted, "github", "user:jon"}
      assert_receive {:done, :granted}
      assert WardrikVault.resolve("github", @jon, vault) == {:ok, "gho_granted"}
      assert WardrikOAuth.flow(oauth, id) == :error
    end

    @tag polls: [%{"error" => "access_denied"}]
    test "ends when the principal refuses", %{vault: vault} do
      assert {:authorize, _url} = WardrikVault.resolve("github", @jon, vault)

      assert_receive {:done, {:error, :access_denied}}
      refute_received {:granted, _name, _id}
    end

    test "finds the issuer from the resource's metadata", %{vault: vault} do
      assert {:authorize, _url} = WardrikVault.resolve("copilot", @jon, vault)
      assert_receive {:granted, "copilot", "user:jon"}
    end

    test "waits five seconds longer when the server asks it to slow down" do
      assert WardrikOAuth.Device.next_interval(:slow_down, 5_000) == 10_000
      assert WardrikOAuth.Device.next_interval(:pending, 5_000) == 5_000
    end

    test "asks nothing for a name it has no provider for", %{vault: vault} do
      assert WardrikVault.resolve("linear", @jon, vault) == {:error, :not_found}
    end
  end

  describe "renewing a grant" do
    test "gives a fresh token as it is", %{vault: vault} do
      {:ok, _vsn} =
        keep(vault, token(access_token: "still good", refresh_token: "rt", expires_at: nil))

      assert WardrikVault.resolve("github", @jon, vault) == {:ok, "still good"}
      refute_received {:refreshed, _token}
    end

    test "refreshes an expired one, keeping its refresh token", %{vault: vault} do
      {:ok, _vsn} = keep(vault, token(access_token: "old", refresh_token: "rt", expires_at: 0))

      assert WardrikVault.resolve("github", @jon, vault) == {:ok, "fresh"}
      assert_received {:refreshed, "rt"}

      {:ok, json} = WardrikVault.fetch(vault, @jon, "github")
      assert {:ok, %Token{access_token: "fresh", refresh_token: "rt"}} = Token.decode(json)
    end

    test "asks again when the refresh token is spent, or there is none", %{vault: vault} do
      {:ok, _vsn} = keep(vault, token(access_token: "old", refresh_token: "spent", expires_at: 0))
      assert {:authorize, _url} = WardrikVault.resolve("github", @jon, vault)
      assert_receive {:granted, "github", "user:jon"}

      {:ok, _vsn} = keep(vault, token(access_token: "old", expires_at: 0))
      assert {:authorize, _url} = WardrikVault.resolve("github", @jon, vault)
    end

    test "refreshes a grant a service refused", %{vault: vault} do
      {:ok, _vsn} =
        keep(vault, token(access_token: "revoked", refresh_token: "rt", expires_at: nil))

      assert :ok = WardrikVault.refused("github", @jon, vault)
      assert WardrikVault.resolve("github", @jon, vault) == {:ok, "fresh"}
    end

    test "asks again for a grant it can't read", %{vault: vault} do
      {:ok, _vsn} = WardrikVault.put(vault, @jon, "github", "not json", kind: :grant)

      assert {:authorize, _url} = WardrikVault.resolve("github", @jon, vault)
    end
  end
end
