defmodule WardrikOAuth.PartsTest do
  use ExUnit.Case, async: true

  alias WardrikOAuth.Device
  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Token

  @req [plug: {Req.Test, __MODULE__}]
  @issuer "https://auth.test"

  defp serve(fun), do: Req.Test.stub(__MODULE__, fn conn -> fun.(conn.request_path, conn) end)

  defp provider(opts \\ []),
    do:
      Provider.new(:test, [issuer: @issuer, client_id: "client", client_secret: "secret"] ++ opts)

  defp metadata(device_endpoint \\ "https://auth.test/device"),
    do: %Metadata{
      issuer: @issuer,
      token_endpoint: "https://auth.test/token",
      device_authorization_endpoint: device_endpoint
    }

  test "never shows a secret or a token" do
    refute inspect(provider()) =~ "secret"

    refute inspect(%Token{access_token: "gho_x", refresh_token: "rt_x", token_endpoint: "e"}) =~
             "_x"
  end

  test "needs an issuer or a resource" do
    assert_raise ArgumentError, ~r/needs an :issuer or a :resource/, fn ->
      Provider.new(:test, client_id: "client")
    end
  end

  describe "discovering metadata" do
    test "falls back to OpenID's path" do
      serve(fn
        "/.well-known/openid-configuration", conn ->
          Req.Test.json(conn, %{
            "issuer" => @issuer,
            "token_endpoint" => "https://auth.test/token"
          })

        _other, conn ->
          Plug.Conn.send_resp(conn, 404, "")
      end)

      assert {:ok, %Metadata{device_authorization_endpoint: nil}} =
               Metadata.discover(provider(), @req)
    end

    test "refuses metadata for another issuer, or none it can read" do
      serve(fn _path, conn -> Req.Test.json(conn, %{"issuer" => "https://evil.test"}) end)

      assert {:error, {:issuer_mismatch, "https://evil.test"}} =
               Metadata.discover(provider(), @req)

      serve(fn _path, conn -> Req.Test.json(conn, %{"issuer" => @issuer}) end)
      assert {:error, :metadata_unreadable} = Metadata.discover(provider(), @req)
    end

    test "needs the resource to name an authorization server" do
      serve(fn _path, conn -> Req.Test.json(conn, %{}) end)
      resource = Provider.new(:test, resource: "https://mcp.test/mcp", client_id: "client")

      assert {:error, {:no_authorization_server, _url}} = Metadata.discover(resource, @req)
    end

    test "won't ask an insecure URL" do
      insecure = Provider.new(:test, issuer: "http://auth.test", client_id: "client")
      assert {:error, {:insecure_url, _url}} = Metadata.discover(insecure, @req)
    end
  end

  describe "a device flow" do
    test "needs a server that offers one" do
      assert {:error, {:no_device_flow, @issuer}} =
               Device.request(metadata(nil), provider(), @req)
    end

    test "reads what the server refuses or garbles" do
      serve(fn _path, conn ->
        conn |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_client"})
      end)

      assert {:error, {:token_refused, "invalid_client", nil}} =
               Device.request(metadata(), provider(), @req)

      serve(fn _path, conn ->
        Req.Test.json(conn, %{"device_code" => "d", "user_code" => "u"})
      end)

      assert {:error, :device_unreadable} = Device.request(metadata(), provider(), @req)

      serve(fn _path, conn -> Req.Test.json(conn, %{}) end)
      assert {:error, :device_unreadable} = Device.request(metadata(), provider(), @req)
    end

    test "polls again when the server fails or can't be reached" do
      device = %Device{
        device_code: "d",
        user_code: "u",
        verification_uri: "v",
        expires_in: 60,
        interval: 5
      }

      serve(fn _path, conn -> conn |> Plug.Conn.put_status(503) |> Req.Test.json(%{}) end)
      assert {:retry, {:http, 503}} = Device.poll(metadata(), provider(), device, @req)

      serve(fn _path, conn -> Req.Test.transport_error(conn, :econnrefused) end)
      assert {:retry, %Req.TransportError{}} = Device.poll(metadata(), provider(), device, @req)

      serve(fn _path, conn -> Req.Test.json(conn, %{"error" => "expired_token"}) end)
      assert {:error, :expired} = Device.poll(metadata(), provider(), device, @req)

      serve(fn _path, conn ->
        conn |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_grant"})
      end)

      assert {:error, {:token_refused, "invalid_grant", nil}} =
               Device.poll(metadata(), provider(), device, @req)
    end
  end
end
