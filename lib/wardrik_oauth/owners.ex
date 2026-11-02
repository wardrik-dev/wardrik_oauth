defmodule WardrikOAuth.Owners do
  @moduledoc """
  Resolves providers along the owner chain, as `WardrikOAuth` does without `:resolver`. See
  `WardrikOAuth.Resolver`.

  Each provider belongs to an `owner`: `deployment`, an org like `acme`, or a person like
  `acme/@jon`. Those in `:providers` are the deployment's, with `source: :config`. Those added
  with `WardrikOAuth.add_provider/4` have `source: :runtime`.

  A principal signs in with the nearest provider of a name along `Wardrik.Owners.chain/1`. Its
  `{:secret, name}` client secret is read from its owner's vault secrets.
  """

  alias Wardrik.Owners
  alias Wardrik.Resource
  alias WardrikCore.Principal
  alias WardrikOAuth.Provider

  @doc "Returns the nearest provider `name` along the chain of `principal`."
  @spec resolve(map(), String.t(), Principal.t()) :: {:ok, Provider.t()} | {:error, term()}
  def resolve(settings, name, %Principal{id: id}) do
    id
    |> Owners.chain()
    |> Enum.find_value({:error, :not_found}, fn owner ->
      case provider(settings, owner, name) do
        {:error, :not_found} -> nil
        found -> found
      end
    end)
  end

  @doc "Returns the providers `owner` can sign in with, nearest first."
  @spec providers(map(), Owners.t()) :: [Provider.t()]
  def providers(settings, owner) do
    owner
    |> Owners.chain()
    |> Enum.flat_map(&owned(settings, &1))
    |> Enum.uniq_by(& &1.name)
  end

  @doc "Returns whether the deployment's providers include `name`."
  @spec configured?(map(), Owners.t(), String.t()) :: boolean()
  def configured?(settings, owner, name), do: Map.has_key?(configured(settings, owner), name)

  @doc "Returns the deployment's provider `name`, given its options."
  @spec deployment(atom() | String.t(), keyword()) :: Provider.t()
  def deployment(name, opts) do
    name |> Provider.new(opts) |> belonging(Resource.deployment(), :config)
  end

  @doc "Returns the key of `owner`'s provider `name`."
  @spec key(Owners.t(), String.t()) :: String.t()
  def key(owner, name), do: URI.encode_www_form(owner) <> "/" <> name

  @doc "Returns the store key of `owner`'s provider `name`, added at runtime."
  @spec store_key(Owners.t(), String.t()) :: String.t()
  def store_key(owner, name), do: "providers/" <> key(owner, name)

  defp provider(settings, owner, name) do
    with {:ok, provider} <- defined(settings, owner, name), do: usable(settings, provider)
  end

  defp defined(settings, owner, name) do
    with :error <- Map.fetch(configured(settings, owner), name) do
      case WardrikStore.get(settings.store, store_key(owner, name)) do
        nil -> {:error, :not_found}
        opts -> {:ok, added(owner, name, opts)}
      end
    end
  end

  defp owned(settings, owner) do
    prefix = store_key(owner, "")

    added =
      for {key, opts, _vsn} <- WardrikStore.entries(settings.store, prefix),
          do: added(owner, String.replace_prefix(key, prefix, ""), opts)

    Enum.sort_by(Map.values(configured(settings, owner)) ++ added, & &1.name)
  end

  defp belonging(provider, owner, source),
    do: %{provider | owner: owner, source: source, key: key(owner, provider.name)}

  defp configured(settings, owner),
    do: if(owner == Resource.deployment(), do: settings.providers, else: %{})

  defp added(owner, name, opts), do: name |> Provider.new(opts) |> belonging(owner, :runtime)

  defp usable(settings, %Provider{client_secret: secret} = provider) do
    case client_secret(settings, provider) do
      {:ok, value} ->
        {:ok, %{provider | client_secret: value}}

      {:error, _reason} ->
        {:error,
         "#{provider.name}'s client_secret, #{inspect(secret)}, isn't sealed for #{provider.owner}"}
    end
  end

  defp client_secret(settings, %Provider{client_secret: {:secret, name}, owner: owner}),
    do: WardrikVault.fetch(settings.vault, %Principal{id: owner}, name, kind: :client_secret)

  defp client_secret(_settings, %Provider{client_secret: secret}), do: {:ok, secret}
end
