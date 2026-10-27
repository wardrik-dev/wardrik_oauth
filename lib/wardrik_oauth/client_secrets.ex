defmodule WardrikOAuth.ClientSecrets do
  @moduledoc """
  Keeps the client secrets of the providers added as the app runs, and of the clients Wardrik
  registers, sealed in the vault rather than the store, under a principal of their own that no
  agent acts as.
  """

  alias WardrikCore.Principal

  @owner %Principal{id: "wardrik_oauth"}

  @doc "Seals `secret` as `name`'s, or does nothing where there's none."
  @spec seal(map(), String.t(), String.t() | nil) :: :ok | {:error, term()}
  def seal(_settings, _name, nil), do: :ok

  def seal(settings, name, secret) do
    case WardrikVault.put(settings.vault, @owner, name, secret) do
      {:ok, _vsn} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Returns `name`'s secret, or `nil` where it has none."
  @spec unseal(map(), String.t()) :: String.t() | nil
  def unseal(settings, name) do
    case WardrikVault.fetch(settings.vault, @owner, name) do
      {:ok, secret} -> secret
      {:error, _none} -> nil
    end
  end

  @doc "Forgets `name`'s secret."
  @spec forget(map(), String.t()) :: :ok
  def forget(settings, name) do
    WardrikVault.delete(settings.vault, @owner, name)
    :ok
  end
end
