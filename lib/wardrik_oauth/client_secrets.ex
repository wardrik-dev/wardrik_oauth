defmodule WardrikOAuth.ClientSecrets do
  @moduledoc """
  Seals the secrets of clients Wardrik registers in the vault, not the store.

  Secrets are kept under a principal of their own that no agent acts as.
  """

  alias WardrikCore.Principal

  @owner %Principal{id: "wardrik_oauth"}

  @doc "Seals `secret` under `name`. Does nothing if `secret` is `nil`."
  @spec seal(map(), String.t(), String.t() | nil) :: :ok | {:error, term()}
  def seal(_settings, _name, nil), do: :ok

  def seal(settings, name, secret) do
    case WardrikVault.put(settings.vault, @owner, name, secret) do
      {:ok, _vsn} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Returns the secret under `name`, or `nil`."
  @spec unseal(map(), String.t()) :: String.t() | nil
  def unseal(settings, name) do
    case WardrikVault.fetch(settings.vault, @owner, name) do
      {:ok, secret} -> secret
      {:error, _none} -> nil
    end
  end

  @doc "Deletes the secret under `name`."
  @spec forget(map(), String.t()) :: :ok
  def forget(settings, name) do
    WardrikVault.delete(settings.vault, @owner, name)
    :ok
  end
end
