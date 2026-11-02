defmodule WardrikOAuth.ClientSecrets do
  @moduledoc """
  Seals the secrets of clients Wardrik registers in the vault, not the store.

  Secrets are kept under a principal of their own that no agent acts as.
  """

  alias WardrikCore.Principal
  alias WardrikVault.Secret

  @owner %Principal{id: "wardrik_oauth"}

  @doc """
  Seals the `:secret` under `:name`. Does nothing if `:secret` is `nil`.

      :ok = ClientSecrets.seal(settings, name: "acme/linear", secret: secret)
  """
  @spec seal(map(), name: String.t(), secret: String.t() | nil) :: :ok | {:error, term()}
  def seal(settings, args) do
    name = Keyword.fetch!(args, :name)

    case Keyword.fetch!(args, :secret) do
      nil -> :ok
      secret -> sealed(settings, name, secret)
    end
  end

  defp sealed(settings, name, secret) do
    sealed = %Secret{principal: @owner, name: name, value: secret}

    case WardrikVault.put(settings.vault, sealed, kind: :client_secret) do
      {:ok, _vsn} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Returns the secret under `name`, or `nil`."
  @spec unseal(map(), String.t()) :: String.t() | nil
  def unseal(settings, name) do
    case WardrikVault.fetch(settings.vault, @owner, name, kind: :client_secret) do
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
