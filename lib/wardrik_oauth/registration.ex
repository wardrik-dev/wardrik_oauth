defmodule WardrikOAuth.Registration do
  @moduledoc """
  Registers Wardrik as a client of an authorization server it has no `client_id` for, as RFC 7591
  says, once, and keeps the registration in the store for every node.
  """

  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Request

  @device "urn:ietf:params:oauth:grant-type:device_code"

  @doc "Returns `provider` with its client: its own, the one kept, or one registered now."
  @spec client(map(), Provider.t(), Metadata.t()) :: {:ok, Provider.t()} | {:error, term()}
  def client(_settings, %Provider{client_id: id} = provider, _metadata) when is_binary(id),
    do: {:ok, provider}

  def client(settings, provider, metadata) do
    case WardrikStore.get(settings.store, key(provider.name)) do
      nil -> register(settings, provider, metadata)
      registered -> {:ok, applied(provider, registered)}
    end
  end

  @doc "Returns `provider` with the client registered for it, where one was."
  @spec registered(map(), Provider.t()) :: Provider.t()
  def registered(_settings, %Provider{client_id: id} = provider) when is_binary(id), do: provider

  def registered(settings, provider) do
    case WardrikStore.get(settings.store, key(provider.name)) do
      nil -> provider
      registered -> applied(provider, registered)
    end
  end

  @doc "Forgets the client registered for the provider `name`."
  @spec forget(map(), String.t()) :: :ok | {:error, term()}
  def forget(settings, name), do: WardrikStore.delete(settings.store, key(name))

  defp register(_settings, provider, %Metadata{registration_endpoint: nil}),
    do: {:error, {:no_client, provider.name}}

  defp register(settings, provider, %Metadata{registration_endpoint: endpoint}) do
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
    case WardrikStore.put(settings.store, key(provider.name), registered, if_vsn: nil) do
      {:ok, _vsn} -> {:ok, applied(provider, registered)}
      {:error, :conflict} -> {:ok, registered(settings, provider)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp request(settings, provider) do
    %{
      "client_name" => settings.client_name,
      "redirect_uris" => [settings.page <> "/callback"],
      "grant_types" => grant_types(provider.flow),
      "response_types" => ["code"],
      "token_endpoint_auth_method" => "none"
    }
  end

  defp grant_types(:device), do: [@device, "refresh_token"]
  defp grant_types(:browser), do: ["authorization_code", "refresh_token"]

  defp applied(provider, registered),
    do: %{
      provider
      | client_id: registered["client_id"],
        client_secret: registered["client_secret"]
    }

  defp key(name), do: "registrations/" <> name
end
