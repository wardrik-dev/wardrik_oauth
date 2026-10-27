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
       store: store,
       page: "https://agents.test/oauth/",
       on_granted: {WardrikOAuth.TestHook, :granted, [test]},
       req_options: [plug: {Req.Test, GitHub}],
       providers: [
         github: [
           issuer: GitHub.issuer(),
           client_id: "client",
           client_secret: "secret",
           scopes: ["repo"],
           flow: :device
         ],
         copilot: [resource: "https://api.github.test/mcp/", client_id: "client", flow: :device],
         github_web: [issuer: GitHub.issuer(), client_id: "client", client_secret: "secret"],
         google: [
           issuer: "https://accounts.test",
           client_id: "google-client",
           client_secret: "google-secret",
           scopes: ["openid", "email"],
           authorization_params: %{access_type: "offline", prompt: "consent"}
         ],
         notion: [
           authorization_endpoint: "https://notion.test/v1/oauth/authorize",
           token_endpoint: "https://notion.test/v1/oauth/token",
           client_id: "notion client",
           client_secret: "notion:secret",
           client_auth: :basic
         ],
         linear: [
           authorization_endpoint: "https://linear.test/oauth/authorize",
           token_endpoint: "https://linear.test/oauth/token",
           client_id: "linear-client",
           client_secret: "linear-secret",
           scopes: ["read"]
         ]
       ]}
    )

    %{vault: vault, oauth: oauth}
  end

  defp get(oauth, path) do
    :get
    |> Plug.Test.conn(path)
    |> WardrikOAuth.Plug.call(WardrikOAuth.Plug.init(oauth: oauth))
  end

  defp state({:authorize, url}), do: URI.decode_query(URI.parse(url).query)["state"]

  defp challenge(verifier),
    do: :sha256 |> :crypto.hash(verifier) |> Base.url_encode64(padding: false)

  defp keep(vault, token),
    do: WardrikVault.put(vault, @jon, "github", Token.encode(token), kind: :grant)

  defp token(fields),
    do: struct!(Token, [token_endpoint: "https://github.test/login/oauth/access_token"] ++ fields)

  test "says which sign-ins aren't started" do
    assert_raise ArgumentError, ~r/^MyApp.Missing isn't started/, fn ->
      WardrikOAuth.providers(MyApp.Missing)
    end
  end

  describe "providers added as the app runs" do
    test "registers Wardrik with a service once, and signs in through it", %{oauth: oauth} do
      assert :ok =
               WardrikOAuth.add_provider(oauth, "tracker",
                 resource: "https://api.github.test/mcp/"
               )

      assert "tracker" in WardrikOAuth.providers(oauth)

      assert {:ok, url} = WardrikOAuth.authorize(oauth, "tracker", @jon)
      assert URI.decode_query(URI.parse(url).query)["client_id"] == "registered-client"

      assert_receive {:registered,
                      %{
                        "client_name" => "Wardrik",
                        "redirect_uris" => ["https://agents.test/oauth/callback"],
                        "token_endpoint_auth_method" => "none"
                      }}

      assert {:ok, _url} = WardrikOAuth.authorize(oauth, "tracker", %Principal{id: "user:ada"})
      refute_received {:registered, _request}
    end

    test "is the client of a service that reads its document by the document's URL", %{
      oauth: oauth
    } do
      :ok = WardrikOAuth.add_provider(oauth, "documents", issuer: "https://documents.test")

      assert {:ok, url} = WardrikOAuth.authorize(oauth, "documents", @jon)

      assert URI.decode_query(URI.parse(url).query)["client_id"] ==
               "https://agents.test/oauth/client"

      refute_received {:registered, _request}

      state = state({:authorize, url})
      assert get(oauth, "/callback?state=#{state}&code=c0de").status == 200
      assert_receive {:exchanged, %{"client_id" => "https://agents.test/oauth/client"}}

      conn = get(oauth, "/client")
      assert conn.status == 200
      assert ["application/json" <> _charset] = Plug.Conn.get_resp_header(conn, "content-type")

      assert JSON.decode!(conn.resp_body) == %{
               "client_id" => "https://agents.test/oauth/client",
               "client_name" => "Wardrik",
               "redirect_uris" => ["https://agents.test/oauth/callback"],
               "grant_types" => [
                 "authorization_code",
                 "urn:ietf:params:oauth:grant-type:device_code",
                 "refresh_token"
               ],
               "response_types" => ["code"],
               "token_endpoint_auth_method" => "none"
             }
    end

    test "registers itself where its pages aren't served where a service could read them",
         %{vault: vault} do
      store = WardrikStore.ETS.new(name: :local_store)
      start_supervised!({WardrikStore, store}, id: :local_store)

      start_supervised!(
        {WardrikOAuth,
         name: :local_oauth,
         vault: vault,
         store: store,
         page: "http://localhost:4747/oauth",
         req_options: [plug: {Req.Test, GitHub}]},
        id: :local_oauth
      )

      :ok = WardrikOAuth.add_provider(:local_oauth, "documents", issuer: "https://documents.test")

      assert {:ok, url} = WardrikOAuth.authorize(:local_oauth, "documents", @jon)
      assert URI.decode_query(URI.parse(url).query)["client_id"] == "registered-client"

      assert_received {:registered,
                       %{"redirect_uris" => ["http://localhost:4747/oauth/callback"]}}
    end

    test "says why a provider doesn't read, or can't be signed in with", %{oauth: oauth} do
      assert {:error, "github is a provider the app starts with"} =
               WardrikOAuth.add_provider(oauth, "github",
                 resource: "https://api.github.test/mcp/"
               )

      assert {:error, "The nowhere provider needs" <> _} =
               WardrikOAuth.add_provider(oauth, "nowhere", [])

      assert :ok = WardrikOAuth.add_provider(oauth, "accounts", issuer: "https://accounts.test")
      assert {:error, {:no_client, "accounts"}} = WardrikOAuth.authorize(oauth, "accounts", @jon)
    end

    test "forgets a provider it's told to", %{oauth: oauth} do
      :ok = WardrikOAuth.add_provider(oauth, "tracker", resource: "https://api.github.test/mcp/")

      assert :ok = WardrikOAuth.remove_provider(oauth, "tracker")
      refute "tracker" in WardrikOAuth.providers(oauth)
      assert {:error, :not_found} = WardrikOAuth.authorize(oauth, "tracker", @jon)
    end
  end

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
      assert WardrikVault.resolve("asana", @jon, vault) == {:error, :not_found}
    end

    @tag polls: []
    test "shows the code on its page", %{vault: vault, oauth: oauth} do
      {:authorize, "https://agents.test/oauth/device/" <> id} =
        WardrikVault.resolve("github", @jon, vault)

      conn = get(oauth, "/device/" <> id)
      assert conn.status == 200
      assert conn.resp_body =~ "WDJB-MJHT"
      assert conn.resp_body =~ ~s(href="https://github.test/login/device")

      assert get(oauth, "/device/nope").status == 404
      assert get(oauth, "/elsewhere").status == 404
    end
  end

  describe "signing in in a browser" do
    test "sends the principal to the service, and keeps the grant when they come back",
         %{vault: vault, oauth: oauth} do
      assert {:authorize, url} = WardrikVault.resolve("google", @jon, vault)
      %URI{host: "accounts.test", path: "/authorize", query: query} = URI.parse(url)
      params = URI.decode_query(query)

      assert %{
               "hd" => "example.com",
               "client_id" => "google-client",
               "redirect_uri" => "https://agents.test/oauth/callback",
               "scope" => "openid email",
               "access_type" => "offline",
               "prompt" => "consent",
               "code_challenge_method" => "S256"
             } = params

      assert WardrikVault.resolve("google", @jon, vault) == {:authorize, url}

      callback = "/callback?" <> URI.encode_query(%{state: params["state"], code: "the-code"})
      conn = get(oauth, callback)
      assert conn.status == 200
      assert conn.resp_body =~ "signed in to google"

      assert_received {:exchanged, %{"code" => "the-code", "code_verifier" => verifier} = form}
      assert form["client_secret"] == "google-secret"
      assert challenge(verifier) == params["code_challenge"]
      assert_receive {:granted, "google", "user:jon"}
      assert WardrikVault.resolve("google", @jon, vault) == {:ok, "browser_token"}

      replayed = get(oauth, callback)
      assert replayed.status == 400
      assert replayed.resp_body =~ "already used"
    end

    test "uses the endpoints an app names, with nothing to discover", %{
      vault: vault,
      oauth: oauth
    } do
      assert {:authorize, "https://linear.test/oauth/authorize?" <> query} =
               WardrikVault.resolve("linear", @jon, vault)

      state = URI.decode_query(query)["state"]

      assert {:ok, "linear"} = WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"})
      assert_received {:exchanged, %{"client_id" => "linear-client"}}
    end

    test "sends the secret in the form by default", %{vault: vault, oauth: oauth} do
      state = state(WardrikVault.resolve("linear", @jon, vault))
      {:ok, "linear"} = WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"})

      assert_received {:exchanged, %{"client_secret" => "linear-secret"}}
      assert_received {:client_auth, []}
    end

    test "sends the secret in a Basic header when the app asks", %{vault: vault, oauth: oauth} do
      state = state(WardrikVault.resolve("notion", @jon, vault))
      {:ok, "notion"} = WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"})

      assert_received {:exchanged, form}
      refute Map.has_key?(form, "client_secret")
      assert_received {:client_auth, ["Basic " <> encoded]}
      assert Base.decode64!(encoded) == "notion+client:notion%3Asecret"
    end

    test "takes a code only from the issuer that promised to say so", %{
      vault: vault,
      oauth: oauth
    } do
      state = state(WardrikVault.resolve("github_web", @jon, vault))
      evil = %{"state" => state, "code" => "c", "iss" => "https://evil.test"}

      assert {:error, :wrong_issuer} = WardrikOAuth.finish(oauth, evil)
      assert_receive {:done, {:error, :wrong_issuer}}
      refute_received {:exchanged, _form}

      state = state(WardrikVault.resolve("github_web", @jon, vault))
      honest = %{"state" => state, "code" => "c", "iss" => GitHub.issuer()}
      assert {:ok, "github_web"} = WardrikOAuth.finish(oauth, honest)
    end

    test "ends when the principal declines", %{vault: vault, oauth: oauth} do
      state = state(WardrikVault.resolve("google", @jon, vault))

      conn = get(oauth, "/callback?" <> URI.encode_query(%{state: state, error: "access_denied"}))
      assert conn.status == 400
      assert conn.resp_body =~ "declined"
      assert_receive {:done, {:error, {:refused, "access_denied"}}}
    end

    test "needs a state, and a code", %{vault: vault, oauth: oauth} do
      assert WardrikOAuth.finish(oauth, %{"code" => "c"}) == {:error, :no_such_flow}

      state = state(WardrikVault.resolve("google", @jon, vault))
      assert WardrikOAuth.finish(oauth, %{"state" => state}) == {:error, :no_code}
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
