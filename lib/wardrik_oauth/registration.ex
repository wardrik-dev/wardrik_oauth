defmodule WardrikOAuth.Registration do
  @moduledoc """
  Makes Wardrik a client of an authorization server it has no `client_id` for.

  This happens once for each provider, by its key. The client is kept in the store for every node.

    1. If the server reads Client ID Metadata Documents and `page` is `https`, the `client_id` is
       `{page}/client`. Nothing is registered.
    2. Otherwise, Wardrik registers itself at the server's `registration_endpoint` (RFC 7591).
    3. If neither is possible, it returns `{:error, {:no_client, name}}`.
  """

  alias WardrikOAuth.ClientSecrets
  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Request

  @device "urn:ietf:params:oauth:grant-type:device_code"

  @doc "Returns `provider` with a client: its own, the one kept, or one registered now."
  @spec client(map(), Provider.t(), Metadata.t()) :: {:ok, Provider.t()} | {:error, term()}
  def client(_settings, %Provider{client_id: id} = provider, _metadata) when is_binary(id),
    do: {:ok, provider}

  def client(settings, provider, metadata) do
    case WardrikStore.get(settings.store, key(provider)) do
      nil -> register(settings, provider, metadata)
      registered -> {:ok, applied(settings, provider, registered)}
    end
  end

  @doc "Returns `provider` with the client kept for it, if there is one."
  @spec registered(map(), Provider.t()) :: Provider.t()
  def registered(_settings, %Provider{client_id: id} = provider) when is_binary(id), do: provider

  def registered(settings, provider) do
    case WardrikStore.get(settings.store, key(provider)) do
      nil -> provider
      registered -> applied(settings, provider, registered)
    end
  end

  @doc "Deletes the client registered for the provider `key`."
  @spec forget(map(), String.t()) :: :ok | {:error, term()}
  def forget(settings, key) do
    with :ok <- WardrikStore.delete(settings.store, "registrations/" <> key),
         do: ClientSecrets.forget(settings, "registrations/" <> key)
  end

  @doc "Returns the Client ID Metadata Document served at `{page}/client`."
  @spec document(map()) :: map()
  def document(settings) do
    settings
    |> fields(["authorization_code", @device, "refresh_token"])
    |> Map.put("client_id", document_url(settings))
  end

  defp register(settings, provider, metadata) do
    if metadata.documents_supported? and public?(settings.page),
      do: kept(settings, provider, %{"client_id" => document_url(settings)}),
      else: dynamic(settings, provider, metadata.registration_endpoint)
  end

  defp dynamic(_settings, provider, nil), do: {:error, {:no_client, provider.name}}

  defp dynamic(settings, provider, endpoint) do
    case Request.post_json(endpoint, request(settings, provider), settings.req_options) do
      {:ok, status, %{"client_id" => _id} = answer} when status in [200, 201] ->
        kept(settings, provider, Map.take(answer, ["client_id", "client_secret"]))

      {:ok, status, body} ->
        {:error, Request.refusal(status, body)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp kept(settings, provider, registered) do
    {secret, client} = Map.pop(registered, "client_secret")

    case WardrikStore.put(settings.store, key(provider), client, if_vsn: nil) do
      {:ok, _vsn} -> sealed(settings, provider, client["client_id"], secret)
      {:error, :conflict} -> {:ok, registered(settings, provider)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp sealed(settings, provider, id, secret) do
    with :ok <- ClientSecrets.seal(settings, key(provider), secret),
         do: {:ok, applied(provider, id, secret)}
  end

  defp request(settings, provider), do: fields(settings, grant_types(provider.flow))

  defp fields(settings, grant_types) do
    %{
      "client_name" => settings.client_name,
      "redirect_uris" => [settings.page <> "/callback"],
      "grant_types" => grant_types,
      "response_types" => ["code"],
      "token_endpoint_auth_method" => "none"
    }
  end

  defp grant_types(:device), do: [@device, "refresh_token"]
  defp grant_types(:browser), do: ["authorization_code", "refresh_token"]

  defp applied(settings, provider, %{"client_id" => id}),
    do: applied(provider, id, ClientSecrets.unseal(settings, key(provider)))

  defp applied(provider, id, secret), do: %{provider | client_id: id, client_secret: secret}

  defp document_url(settings), do: settings.page <> "/client"

  defp public?(page) do
    case URI.parse(page) do
      %URI{scheme: "https", host: host} -> host not in ["localhost", "127.0.0.1", "::1"]
      _other -> false
    end
  end

  defp key(%Provider{key: key}), do: "registrations/" <> key
end
