defmodule WardrikOAuth.Resolver do
  @moduledoc """
  Says which OAuth app each user signs in with, by name.

      {WardrikOAuth, name: MyApp.OAuth, resolver: {MyApp.OAuthApps, []}, ...}

      defmodule MyApp.OAuthApps do
        @behaviour WardrikOAuth.Resolver

        @impl true
        def provider(%{name: name, principal: %WardrikCore.Principal{id: id}}, _opts) do
          case MyApp.OAuthApps.for_user(id, name) do
            nil ->
              {:error, :not_found}

            app ->
              opts = [key: app.id, client_secret: MyApp.Secrets.read!(app.secret)] ++ app.options
              {:ok, WardrikOAuth.Provider.new(name, opts)}
          end
        end
      end

    * Called as each sign-in starts, and as each expired token is refreshed.
    * Return a provider with the `name` asked for, a `key` unique to the OAuth app, and the
      `client_secret` itself, or `nil`.
    * If the `key` changed since the token was issued, the user signs in again.
    * An error stops the sign-in.
  """

  alias WardrikOAuth.Provider
  alias WardrikOAuth.Resolver.Request

  @doc "Returns the provider the request's principal signs in with by its name."
  @callback provider(Request.t(), opts :: term()) ::
              {:ok, Provider.t()} | {:error, :not_found} | {:error, term()}

  @doc "Returns the provider the request's principal signs in with by its name, or why there's none."
  @spec resolve(map(), Request.t()) :: {:ok, Provider.t()} | {:error, term()}
  def resolve(%{resolver: {module, opts}}, %Request{name: name} = request),
    do: request |> module.provider(opts) |> read(name)

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
