defmodule WardrikOAuth.Request do
  @moduledoc "Sends the requests a flow makes to an authorization server."

  alias WardrikOAuth.Provider

  @timeout :timer.seconds(15)

  @doc "Gets JSON from `url`."
  @spec get_json(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def get_json(url, req_options) do
    with :ok <- secure(url) do
      case Req.get(url, options(req_options)) do
        {:ok, %Req.Response{status: 200, body: %{} = body}} -> {:ok, body}
        {:ok, %Req.Response{status: status}} -> {:error, {:http, status, url}}
        {:error, reason} -> {:error, {:unreachable, reason}}
      end
    end
  end

  @doc """
  Posts `form` to `url` as `provider`'s client, and returns the status with the JSON it answered.

  The client's secret goes in the form, or in an HTTP Basic header when the provider's
  `client_auth` is `:basic`.
  """
  @spec post_as(String.t(), Provider.t(), map(), keyword()) ::
          {:ok, pos_integer(), map()} | {:error, term()}
  def post_as(url, %Provider{} = provider, form, req_options) do
    {form, headers} = authenticated(provider, Map.put(form, "client_id", provider.client_id))

    with :ok <- secure(url) do
      case Req.post(url, [form: form] ++ options(req_options, headers)) do
        {:ok, %Req.Response{status: status, body: %{} = body}} -> {:ok, status, body}
        {:ok, %Req.Response{status: status}} -> {:ok, status, %{}}
        {:error, reason} -> {:error, {:unreachable, reason}}
      end
    end
  end

  @doc "Reads an OAuth error answer as `{:token_refused, error, description}`."
  @spec refusal(pos_integer(), map()) :: {:token_refused, String.t(), String.t() | nil}
  def refusal(status, body) do
    description = body["error_description"]

    {:token_refused, body["error"] || "http_#{status}",
     description && String.slice(description, 0, 200)}
  end

  @doc "Puts `value` in `form` under `key`, unless it's empty."
  @spec present(map(), String.t(), term()) :: map()
  def present(form, _key, nil), do: form
  def present(form, _key, ""), do: form
  def present(form, key, value), do: Map.put(form, key, value)

  defp authenticated(%Provider{client_auth: :basic, client_secret: secret} = provider, form)
       when is_binary(secret) do
    pair = URI.encode_www_form(provider.client_id) <> ":" <> URI.encode_www_form(secret)
    {form, [{"authorization", "Basic " <> Base.encode64(pair)}]}
  end

  defp authenticated(%Provider{client_secret: secret}, form),
    do: {present(form, "client_secret", secret), []}

  defp options(req_options, headers \\ []) do
    [
      headers: [{"accept", "application/json"} | headers],
      redirect: false,
      retry: false,
      receive_timeout: @timeout
    ] ++ req_options
  end

  defp secure(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host} when is_binary(host) -> :ok
      %URI{scheme: "http", host: host} when host in ["localhost", "127.0.0.1", "::1"] -> :ok
      _other -> {:error, {:insecure_url, url}}
    end
  end
end
