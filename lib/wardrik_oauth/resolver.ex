defmodule WardrikOAuth.Resolver do
  @moduledoc """
  Says which OAuth app each principal signs in with, by name.

      {WardrikOAuth, name: MyApp.OAuth, resolver: {MyApp.OAuthApps, []}, ...}

      defmodule MyApp.OAuthApps do
        @behaviour WardrikOAuth.Resolver

        @impl true
        def provider(name, %WardrikCore.Principal{id: id}, _config) do
          case MyApp.OAuthApps.for_user(id, name) do
            nil ->
              {:error, :not_found}

            app ->
              provider = WardrikOAuth.Provider.new(name, app.options)
              {:ok, %{provider | key: app.id, client_secret: MyApp.Secrets.read!(app.secret)}}
          end
        end
      end

  Wardrik resolves the provider as each sign-in starts, and as each expired grant is refreshed.
  A grant is refreshed only by the provider whose `key` issued it. If the principal resolves to
  another, they sign in again with it, so no app's client ever sees another app's grant.

  The provider's `name` is the one asked for, its `key` names the OAuth app, unique to it, and
  its `client_secret` is the secret itself, or `nil`. An error stops the sign-in with it.

  Without `:resolver`, providers are resolved along the owner chain. See `WardrikOAuth.Owners`.
  """

  alias WardrikCore.Principal
  alias WardrikOAuth.Provider

  @doc "Returns the provider `principal` signs in with as `name`."
  @callback provider(name :: String.t(), principal :: Principal.t(), config :: term()) ::
              {:ok, Provider.t()} | {:error, :not_found} | {:error, term()}

  @doc "Returns the provider `principal` signs in with as `name`, or why there's none."
  @spec resolve(map(), String.t(), Principal.t()) :: {:ok, Provider.t()} | {:error, term()}
  def resolve(%{resolver: nil} = settings, name, principal),
    do: settings |> WardrikOAuth.Owners.resolve(name, principal) |> read(name)

  def resolve(%{resolver: {module, config}}, name, principal),
    do: name |> module.provider(principal, config) |> read(name)

  defp read({:ok, %Provider{name: name, key: key, client_secret: secret} = provider}, name)
       when is_binary(key) and key != "" and (is_binary(secret) or is_nil(secret)),
       do: {:ok, provider}

  defp read({:ok, %Provider{} = provider}, name), do: {:error, unread(name, why(provider, name))}
  defp read({:error, reason}, _name), do: {:error, reason}
  defp read(other, name), do: {:error, unread(name, "it's #{inspect(other)}")}

  defp why(%Provider{name: other}, name) when other != name, do: "it's named #{other}"

  defp why(%Provider{client_secret: secret}, _name)
       when not (is_binary(secret) or is_nil(secret)),
       do: "its client_secret isn't the secret itself"

  defp why(_provider, _name), do: "it has no key"

  defp unread(name, why), do: "#{name} doesn't resolve: #{why}"
end
