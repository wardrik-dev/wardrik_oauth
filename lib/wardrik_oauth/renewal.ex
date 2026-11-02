defmodule WardrikOAuth.Renewal do
  @moduledoc """
  Keeps a principal's grant usable by refreshing it when it expires.

  Refreshes take a cluster-wide lock, so two nodes never spend the same refresh token.
  """

  alias WardrikCore.Principal
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Request
  alias WardrikOAuth.Token

  @doc """
  Returns the grant's access token, refreshing it first with `provider` if it has expired.

  Returns `:ask` if the principal must sign in again.
  """
  @spec renew(map(), Provider.t(), Principal.t(), Token.t()) ::
          {:ok, String.t()} | :ask | {:error, term()}
  def renew(settings, provider, principal, %Token{} = token) do
    if Token.fresh?(token),
      do: {:ok, token.access_token},
      else: refresh(settings, provider, principal)
  end

  @doc "Marks the grant `name` expired, so the next use refreshes it."
  @spec expire(map(), String.t(), Principal.t()) :: :ok
  def expire(settings, name, principal) do
    locked(name, principal, fn ->
      with {:ok, token, vsn} <- current(settings, name, principal) do
        WardrikVault.put(
          settings.vault,
          principal,
          name,
          Token.encode(Token.expire(token)),
          kind: :grant,
          if_vsn: vsn
        )
      end
    end)

    :ok
  end

  defp refresh(settings, provider, principal) do
    locked(provider.name, principal, fn ->
      case current(settings, provider.name, principal) do
        {:ok, token, vsn} -> refreshed(settings, provider, principal, token, vsn)
        :none -> :ask
      end
    end)
  end

  defp refreshed(settings, provider, principal, token, vsn) do
    cond do
      Token.fresh?(token) -> {:ok, token.access_token}
      Token.renewable?(token) -> exchange(settings, provider, principal, token, vsn)
      true -> :ask
    end
  end

  defp exchange(settings, provider, principal, token, vsn) do
    case post_refresh(settings, provider, token) do
      {:ok, fresh} ->
        fresh = %{Token.carry_refresh(fresh, token) | provider: provider.key}

        WardrikVault.put(settings.vault, principal, provider.name, Token.encode(fresh),
          kind: :grant,
          if_vsn: vsn
        )

        {:ok, fresh.access_token}

      {:error, {:token_refused, _error, _description}} ->
        :ask

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp post_refresh(settings, provider, token) do
    form =
      %{}
      |> Map.merge(%{"grant_type" => "refresh_token", "refresh_token" => token.refresh_token})
      |> Request.present("resource", provider.resource)

    with {:ok, status, body} <-
           Request.post_as(token.token_endpoint, provider, form, settings.req_options),
         do: Token.from_response(status, body, token.token_endpoint)
  end

  defp current(settings, name, principal) do
    with {:ok, :grant, value, vsn} <- WardrikVault.lookup(settings.vault, principal, name),
         {:ok, token} <- Token.decode(value) do
      {:ok, token, vsn}
    else
      _none -> :none
    end
  end

  defp locked(name, %Principal{id: id}, fun) do
    case :global.trans({{WardrikOAuth, name, id}, self()}, fun, [node() | Node.list()], 20) do
      :aborted -> {:error, :renewing}
      result -> result
    end
  end
end
