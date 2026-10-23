defmodule WardrikOAuth.Plug do
  @moduledoc """
  The pages a sign-in comes back to, for your app's router to mount at `WardrikOAuth`'s `page`.

      forward "/oauth", WardrikOAuth.Plug, oauth: MyApp.OAuth
  """

  @behaviour Plug

  import Plug.Conn

  alias Plug.HTML

  @impl Plug
  def init(opts), do: Keyword.fetch!(opts, :oauth)

  @impl Plug
  def call(%Plug.Conn{method: "GET", path_info: ["callback"]} = conn, oauth) do
    conn = fetch_query_params(conn)

    case WardrikOAuth.finish(oauth, conn.query_params) do
      {:ok, provider} ->
        page(
          conn,
          200,
          "Signed in",
          "You're signed in to #{escape(provider)}. You can close this tab."
        )

      {:error, reason} ->
        page(conn, 400, "Sign-in didn't finish", failed(reason))
    end
  end

  def call(%Plug.Conn{method: "GET", path_info: ["device", id]} = conn, oauth) do
    case WardrikOAuth.flow(oauth, id) do
      {:ok, %{user_code: code, verification_uri: uri, provider: provider}} ->
        page(conn, 200, "Sign in to #{escape(provider)}", """
        <p>Enter this code:</p>
        <p class="code">#{escape(code)}</p>
        <p><a href="#{escape(uri)}">#{escape(uri)}</a></p>
        """)

      :error ->
        page(conn, 404, "Sign-in not found", ended())
    end
  end

  def call(conn, _oauth), do: send_resp(conn, 404, "Not found")

  defp failed({:refused, _error}), do: "The sign-in was declined."
  defp failed(:no_such_flow), do: ended()
  defp failed(_reason), do: "The sign-in couldn't be finished. Ask again to start a new one."

  defp ended, do: "This sign-in has ended, or was already used. Ask again to start a new one."

  defp page(conn, status, title, body) do
    conn
    |> put_resp_content_type("text/html")
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(status, """
    <!doctype html>
    <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
    <title>#{title}</title>
    <style>body{font:16px system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem}.code{font:2rem monospace;letter-spacing:.2rem}</style>
    </head><body><h1>#{title}</h1>#{body}</body></html>
    """)
  end

  defp escape(text), do: text |> HTML.html_escape() |> IO.iodata_to_binary()
end
