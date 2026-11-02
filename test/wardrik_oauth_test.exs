defmodule WardrikOAuthTest do
  use ExUnit.Case, async: false

  defp credential(name, principal),
    do: %WardrikCore.Credentials.Request{name: name, principal: principal}

  alias WardrikCore.Principal
  alias WardrikOAuth.GitHub
  alias WardrikOAuth.Token
  alias WardrikVault.Secret

  @jon %Principal{id: "user:jon"}
  @acme_jon %Principal{id: "acme/@jon"}
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
       resolver:
         {WardrikOAuth.Test.Fixed,
          [
            github: [
              issuer: GitHub.issuer(),
              client_id: "client",
              client_secret: "secret",
              scopes: ["repo"],
              flow: :device
            ],
            copilot: [
              resource: "https://api.github.test/mcp/",
              client_id: "client",
              flow: :device
            ],
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
            ],
            tracker: [resource: "https://api.github.test/mcp/"],
            documents: [issuer: "https://documents.test"],
            accounts: [issuer: "https://accounts.test"]
          ]}}
    )

    %{vault: vault, oauth: oauth, store: WardrikStore.scope(store, "wardrik_oauth")}
  end

  defp flow_ended(oauth, name, %Principal{id: id}) do
    [{pid, _value}] = Registry.lookup(Module.concat(oauth, Registry), {:flow, name, id})
    ref = Process.monitor(pid)
    {:DOWN, ref, :process, pid, :normal}
  end

  defp get(oauth, path, as \\ @jon) do
    :get
    |> Plug.Test.conn(path)
    |> WardrikOAuth.Plug.call(
      WardrikOAuth.Plug.init(oauth: oauth, principal: {__MODULE__, :at, [as]})
    )
  end

  def at(_conn, principal), do: principal

  defp state({:authorize, url}), do: URI.decode_query(URI.parse(url).query)["state"]

  defp challenge(verifier),
    do: :sha256 |> :crypto.hash(verifier) |> Base.url_encode64(padding: false)

  defp keep(vault, token) do
    secret = %Secret{principal: @jon, name: "github", value: Token.encode(token)}
    WardrikVault.put(vault, secret, kind: :grant)
  end

  defp sign_in(oauth, name, principal) do
    {:ok, url} = WardrikOAuth.authorize(oauth, name, principal)

    WardrikOAuth.finish(
      oauth,
      %{"state" => state({:authorize, url}), "code" => "c", "iss" => GitHub.issuer()},
      as: principal
    )
  end

  defp token(fields) do
    issued = [
      token_endpoint: "https://github.test/login/oauth/access_token",
      provider: "fixed/github"
    ]

    struct!(Token, Keyword.merge(issued, fields))
  end

  test "says which sign-ins aren't started" do
    assert_raise ArgumentError, ~r/^MyApp.Missing isn't started/, fn ->
      WardrikOAuth.client_document(MyApp.Missing)
    end
  end

  describe "a provider without a client ID" do
    test "keeps a registered client's secret sealed in the vault", %{oauth: oauth, store: store} do
      {:ok, url} = WardrikOAuth.authorize(oauth, "tracker", @acme_jon)

      assert WardrikStore.get(store, "registrations/fixed/tracker") == %{
               "client_id" => "registered-client"
             }

      {:ok, %{provider: "tracker"}} =
        WardrikOAuth.finish(
          oauth,
          %{"state" => state({:authorize, url}), "code" => "c", "iss" => GitHub.issuer()},
          as: @acme_jon
        )

      assert_received {:exchanged, %{"client_secret" => "registered-secret"}}
    end

    test "registers Wardrik with a service once, and signs in through it", %{oauth: oauth} do
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
         resolver: {WardrikOAuth.Test.Fixed, [documents: [issuer: "https://documents.test"]]},
         req_options: [plug: {Req.Test, GitHub}]},
        id: :local_oauth
      )

      assert {:ok, url} = WardrikOAuth.authorize(:local_oauth, "documents", @jon)
      assert URI.decode_query(URI.parse(url).query)["client_id"] == "registered-client"

      assert_received {:registered,
                       %{"redirect_uris" => ["http://localhost:4747/oauth/callback"]}}
    end

    test "says why it can't be signed in with", %{oauth: oauth} do
      assert {:error, {:no_client, "accounts"}} = WardrikOAuth.authorize(oauth, "accounts", @jon)
    end
  end

  describe "signing in on another device" do
    @tag polls: [%{"error" => "authorization_pending"}, @granted]
    test "shows the code, then keeps the grant once it's entered", %{vault: vault, oauth: oauth} do
      assert {:authorize, "https://agents.test/oauth/device/" <> id = url} =
               WardrikVault.resolve(credential("github", @jon), vault)

      assert {:ok,
              %{user_code: "WDJB-MJHT", verification_uri: "https://github.test/login/device"}} =
               WardrikOAuth.flow(oauth, id)

      assert WardrikVault.resolve(credential("github", @jon), vault) == {:authorize, url}
      assert WardrikOAuth.signing_in?(oauth, "github", @jon)
      refute WardrikOAuth.signing_in?(oauth, "github", @acme_jon)
      ended = flow_ended(oauth, "github", @jon)

      assert_receive {:granted, "github", "user:jon"}
      assert_receive {:done, :granted}
      assert_receive ^ended
      assert WardrikVault.resolve(credential("github", @jon), vault) == {:ok, "gho_granted"}
      assert WardrikOAuth.flow(oauth, id) == :error
      refute WardrikOAuth.signing_in?(oauth, "github", @jon)
    end

    @tag polls: [%{"error" => "access_denied"}]
    test "ends when the principal refuses", %{vault: vault} do
      assert {:authorize, _url} = WardrikVault.resolve(credential("github", @jon), vault)

      assert_receive {:done, {:error, :access_denied}}
      refute_received {:granted, _name, _id}
    end

    test "finds the issuer from the resource's metadata", %{vault: vault} do
      assert {:authorize, _url} = WardrikVault.resolve(credential("copilot", @jon), vault)
      assert_receive {:granted, "copilot", "user:jon"}
    end

    test "waits five seconds longer when the server asks it to slow down" do
      assert WardrikOAuth.Device.next_interval(:slow_down, 5_000) == 10_000
      assert WardrikOAuth.Device.next_interval(:pending, 5_000) == 5_000
    end

    test "asks nothing for a name it has no provider for", %{vault: vault} do
      assert WardrikVault.resolve(credential("asana", @jon), vault) == {:error, :not_found}
    end

    @tag polls: []
    test "shows the code on its page", %{vault: vault, oauth: oauth} do
      {:authorize, "https://agents.test/oauth/device/" <> id} =
        WardrikVault.resolve(credential("github", @jon), vault)

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
      assert {:authorize, url} = WardrikVault.resolve(credential("google", @jon), vault)
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

      assert WardrikVault.resolve(credential("google", @jon), vault) == {:authorize, url}

      callback = "/callback?" <> URI.encode_query(%{state: params["state"], code: "the-code"})
      conn = get(oauth, callback)
      assert conn.status == 200
      assert conn.resp_body =~ "signed in to google"

      assert_received {:exchanged, %{"code" => "the-code", "code_verifier" => verifier} = form}
      assert form["client_secret"] == "google-secret"
      assert challenge(verifier) == params["code_challenge"]
      assert_receive {:granted, "google", "user:jon"}
      assert WardrikVault.resolve(credential("google", @jon), vault) == {:ok, "browser_token"}

      replayed = get(oauth, callback)
      assert replayed.status == 400
      assert replayed.resp_body =~ "already used"
    end

    test "uses the endpoints an app names, with nothing to discover", %{
      vault: vault,
      oauth: oauth
    } do
      assert {:authorize, "https://linear.test/oauth/authorize?" <> query} =
               WardrikVault.resolve(credential("linear", @jon), vault)

      state = URI.decode_query(query)["state"]

      assert {:ok, %{provider: "linear"}} =
               WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"}, as: @jon)

      assert_received {:exchanged, %{"client_id" => "linear-client"}}
    end

    test "sends the secret in the form by default", %{vault: vault, oauth: oauth} do
      state = state(WardrikVault.resolve(credential("linear", @jon), vault))

      {:ok, %{provider: "linear"}} =
        WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"}, as: @jon)

      assert_received {:exchanged, %{"client_secret" => "linear-secret"}}
      assert_received {:client_auth, []}
    end

    test "sends the secret in a Basic header when the app asks", %{vault: vault, oauth: oauth} do
      state = state(WardrikVault.resolve(credential("notion", @jon), vault))

      {:ok, %{provider: "notion"}} =
        WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"}, as: @jon)

      assert_received {:exchanged, form}
      refute Map.has_key?(form, "client_secret")
      assert_received {:client_auth, ["Basic " <> encoded]}
      assert Base.decode64!(encoded) == "notion+client:notion%3Asecret"
    end

    test "takes a code only from the issuer that promised to say so", %{
      vault: vault,
      oauth: oauth
    } do
      state = state(WardrikVault.resolve(credential("github_web", @jon), vault))
      evil = %{"state" => state, "code" => "c", "iss" => "https://evil.test"}

      assert {:error, :wrong_issuer} = WardrikOAuth.finish(oauth, evil, as: @jon)
      assert_receive {:done, {:error, :wrong_issuer}}
      refute_received {:exchanged, _form}

      state = state(WardrikVault.resolve(credential("github_web", @jon), vault))
      honest = %{"state" => state, "code" => "c", "iss" => GitHub.issuer()}
      assert {:ok, %{provider: "github_web"}} = WardrikOAuth.finish(oauth, honest, as: @jon)
    end

    test "ends when the principal declines", %{vault: vault, oauth: oauth} do
      state = state(WardrikVault.resolve(credential("google", @jon), vault))

      conn = get(oauth, "/callback?" <> URI.encode_query(%{state: state, error: "access_denied"}))
      assert conn.status == 400
      assert conn.resp_body =~ "declined"
      assert_receive {:done, {:error, {:refused, "access_denied"}}}
    end

    test "finishes only for the principal who started it, and stays open for them", %{
      vault: vault,
      oauth: oauth
    } do
      state = state(WardrikVault.resolve(credential("linear", @jon), vault))
      someone = %Principal{id: "acme/@mallory"}

      assert {:error, :wrong_principal} =
               WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"}, as: someone)

      assert {:error, :wrong_principal} =
               WardrikOAuth.finish(oauth, %{"state" => state, "error" => "access_denied"},
                 as: someone
               )

      refute_received {:exchanged, _form}
      assert WardrikVault.resolve(credential("linear", someone), vault) != {:ok, "browser_token"}

      assert {:ok, %{provider: "linear", principal: @jon}} =
               WardrikOAuth.finish(oauth, %{"state" => state, "code" => "c"}, as: @jon)
    end

    test "finishes a callback only for whoever the app says is at the browser", %{
      vault: vault,
      oauth: oauth
    } do
      state = state(WardrikVault.resolve(credential("google", @jon), vault))
      callback = "/callback?" <> URI.encode_query(%{state: state, code: "the-code"})

      assert %{status: 401, resp_body: body} = get(oauth, callback, nil)
      assert body =~ "can't tell who you are"

      assert %{status: 400, resp_body: body} =
               get(oauth, callback, %Principal{id: "acme/@mallory"})

      assert body =~ "Someone else started this sign-in"
      refute_received {:exchanged, _form}

      assert get(oauth, callback).status == 200
    end

    test "needs a state, and a code", %{vault: vault, oauth: oauth} do
      assert WardrikOAuth.finish(oauth, %{"code" => "c"}, as: @jon) == {:error, :no_such_flow}

      state = state(WardrikVault.resolve(credential("google", @jon), vault))
      assert WardrikOAuth.finish(oauth, %{"state" => state}, as: @jon) == {:error, :no_code}
    end
  end

  describe "renewing a grant" do
    test "gives a fresh token as it is", %{vault: vault} do
      {:ok, _vsn} =
        keep(vault, token(access_token: "still good", refresh_token: "rt", expires_at: nil))

      assert WardrikVault.resolve(credential("github", @jon), vault) == {:ok, "still good"}
      refute_received {:refreshed, _token}
    end

    test "refreshes an expired one, keeping its refresh token", %{vault: vault} do
      {:ok, _vsn} = keep(vault, token(access_token: "old", refresh_token: "rt", expires_at: 0))

      assert WardrikVault.resolve(credential("github", @jon), vault) == {:ok, "fresh"}
      assert_received {:refreshed, "rt"}

      {:ok, json} = WardrikVault.fetch(vault, @jon, "github")

      assert {:ok, %Token{access_token: "fresh", refresh_token: "rt", provider: "fixed/github"}} =
               Token.decode(json)
    end

    test "asks again when the refresh token is spent, or there is none", %{vault: vault} do
      {:ok, _vsn} = keep(vault, token(access_token: "old", refresh_token: "spent", expires_at: 0))
      assert {:authorize, _url} = WardrikVault.resolve(credential("github", @jon), vault)
      assert_receive {:granted, "github", "user:jon"}

      {:ok, _vsn} = keep(vault, token(access_token: "old", expires_at: 0))
      assert {:authorize, _url} = WardrikVault.resolve(credential("github", @jon), vault)
    end

    test "refreshes a grant a service refused", %{vault: vault} do
      {:ok, _vsn} =
        keep(vault, token(access_token: "revoked", refresh_token: "rt", expires_at: nil))

      assert :ok = WardrikVault.refused(credential("github", @jon), vault)
      assert WardrikVault.resolve(credential("github", @jon), vault) == {:ok, "fresh"}
    end

    test "asks again for a grant it can't read", %{vault: vault} do
      {:ok, _vsn} =
        WardrikVault.put(vault, %Secret{principal: @jon, name: "github", value: "not json"},
          kind: :grant
        )

      assert {:authorize, _url} = WardrikVault.resolve(credential("github", @jon), vault)
    end
  end

  describe "the provider that issued a grant" do
    test "is recorded with it", %{oauth: oauth, vault: vault} do
      assert {:ok, %{provider: "github_web"}} = sign_in(oauth, "github_web", @acme_jon)

      {:ok, json} = WardrikVault.fetch(vault, @acme_jon, "github_web")
      assert {:ok, %Token{provider: "fixed/github_web"}} = Token.decode(json)
    end

    test "alone renews it", %{vault: vault} do
      keep_web(vault, provider: "fixed/github_web")
      assert WardrikVault.resolve(credential("github_web", @acme_jon), vault) == {:ok, "fresh"}

      keep_web(vault, provider: "acme/github_web")
      assert {:authorize, _url} = WardrikVault.resolve(credential("github_web", @acme_jon), vault)

      keep_web(vault, provider: nil)
      assert {:authorize, _url} = WardrikVault.resolve(credential("github_web", @acme_jon), vault)
    end
  end

  defp keep_web(vault, fields) do
    value =
      Token.encode(token([access_token: "old", refresh_token: "rt", expires_at: 0] ++ fields))

    secret = %Secret{principal: @acme_jon, name: "github_web", value: value}
    {:ok, _vsn} = WardrikVault.put(vault, secret, kind: :grant)
  end
end
