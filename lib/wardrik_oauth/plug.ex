defmodule WardrikOAuth.Plug do
  @moduledoc """
  Serves the sign-in pages. Mount it at `WardrikOAuth`'s `page`.

      forward "/oauth", WardrikOAuth.Plug,
        oauth: MyApp.OAuth,
        principal: {MyApp.Session, :principal, []}

  ## Paths

    * `GET /callback` - finishes a browser sign-in.
    * `GET /device/:id` - shows a device sign-in's code and where to enter it.
    * `GET /client` - the Client ID Metadata Document for Wardrik's `client_id`.

  ## Options

    * `:oauth` - required. The `WardrikOAuth` name.
    * `:principal` - required. `{module, function, args}`, called with the conn and then `args`.
      Returns the `WardrikCore.Principal` at the browser, as your app knows them from their
      session, or `nil` if it can't tell. A callback finishes only for the principal who started
      the sign-in, so someone else's link can't connect your account to their agents. See
      `WardrikOAuth.finish/3`.
  """

  @behaviour Plug

  import Plug.Conn

  alias Plug.HTML

  @impl Plug
  def init(opts) do
    {module, function, args} = Keyword.fetch!(opts, :principal)
    %{oauth: Keyword.fetch!(opts, :oauth), principal: {module, function, args}}
  end

  @impl Plug
  def call(%Plug.Conn{method: "GET", path_info: ["callback"]} = conn, %{oauth: oauth} = opts) do
    conn = fetch_query_params(conn)

    case principal(conn, opts) do
      nil -> page(conn, 401, "Sign-in didn't finish", unknown())
      principal -> finished(conn, WardrikOAuth.finish(oauth, conn.query_params, as: principal))
    end
  end

  def call(%Plug.Conn{method: "GET", path_info: ["device", id]} = conn, %{oauth: oauth}) do
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

  def call(%Plug.Conn{method: "GET", path_info: ["client"]} = conn, %{oauth: oauth}) do
    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("cache-control", "public, max-age=3600")
    |> send_resp(200, JSON.encode!(WardrikOAuth.client_document(oauth)))
  end

  def call(conn, _opts), do: send_resp(conn, 404, "Not found")

  defp principal(conn, %{principal: {module, function, args}}),
    do: apply(module, function, [conn | args])

  defp finished(conn, outcome) do
    case outcome do
      {:ok, %{provider: provider}} ->
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

  defp failed({:refused, _error}), do: "The sign-in was declined."
  defp failed(:no_such_flow), do: ended()

  defp failed(:wrong_principal),
    do: "Someone else started this sign-in, so it can't connect your account."

  defp failed(_reason), do: "The sign-in couldn't be finished. Ask again to start a new one."

  defp unknown,
    do: "This page can't tell who you are. Sign in to the app that sent you here, and ask again."

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
