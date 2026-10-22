defmodule WardrikOAuth.GitHub do
  @moduledoc "A stub GitHub the tests sign in with: device codes, polls answered in turn, and refreshes."

  @issuer "https://github.test/login/oauth"

  def issuer, do: @issuer

  def plug(polls, test) do
    fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      answer(conn, conn.method, conn.request_path, URI.decode_query(body), polls, test)
    end
  end

  defp answer(conn, "GET", "/.well-known/oauth-protected-resource/mcp", _form, _polls, _test),
    do: Req.Test.json(conn, %{"authorization_servers" => [@issuer]})

  defp answer(
         conn,
         "GET",
         "/.well-known/oauth-authorization-server/login/oauth",
         _form,
         _polls,
         _test
       ) do
    Req.Test.json(conn, %{
      "issuer" => @issuer,
      "token_endpoint" => "https://github.test/login/oauth/access_token",
      "device_authorization_endpoint" => "https://github.test/login/device/code"
    })
  end

  defp answer(conn, "POST", "/login/device/code", _form, _polls, _test) do
    Req.Test.json(conn, %{
      "device_code" => "device-123",
      "user_code" => "WDJB-MJHT",
      "verification_uri" => "https://github.test/login/device",
      "expires_in" => 900,
      "interval" => 0
    })
  end

  defp answer(
         conn,
         "POST",
         "/login/oauth/access_token",
         %{"grant_type" => "refresh_token"} = form,
         _polls,
         test
       ) do
    send(test, {:refreshed, form["refresh_token"]})

    case form["refresh_token"] do
      "spent" -> Req.Test.json(conn, %{"error" => "bad_refresh_token"})
      _good -> Req.Test.json(conn, %{"access_token" => "fresh", "expires_in" => 3600})
    end
  end

  defp answer(conn, "POST", "/login/oauth/access_token", _device, polls, _test),
    do: Req.Test.json(conn, Agent.get_and_update(polls, fn [next | rest] -> {next, rest} end))

  defp answer(conn, _method, _path, _form, _polls, _test),
    do: conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{})
end

defmodule WardrikOAuth.TestHook do
  @moduledoc "What the tests' sign-ins call once granted, and the telemetry they watch."

  def granted(name, principal, test), do: send(test, {:granted, name, principal.id})

  def handle_event(_event, _measurements, metadata, test),
    do: send(test, {:done, metadata.outcome})
end
