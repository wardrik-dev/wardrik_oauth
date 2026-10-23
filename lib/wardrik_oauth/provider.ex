defmodule WardrikOAuth.Provider do
  @moduledoc """
  A provider is an OAuth app with a service, named like the credential it grants: one you
  registered, with its `client_id`, or one Wardrik registers itself, where the service lets it.
  """

  @derive {Inspect, except: [:client_secret]}
  @enforce_keys [:name]
  defstruct [
    :name,
    :issuer,
    :resource,
    :client_id,
    :client_secret,
    :authorization_endpoint,
    :token_endpoint,
    scopes: [],
    flow: :browser,
    client_auth: :post,
    authorization_params: %{}
  ]

  @typedoc "An OAuth app a principal can authorize."
  @type t() :: %__MODULE__{
          name: String.t(),
          issuer: String.t() | nil,
          resource: String.t() | nil,
          client_id: String.t() | nil,
          client_secret: String.t() | nil,
          authorization_endpoint: String.t() | nil,
          token_endpoint: String.t() | nil,
          scopes: [String.t()],
          flow: :browser | :device,
          client_auth: :post | :basic,
          authorization_params: %{optional(String.t()) => String.t()}
        }

  @options [
    :issuer,
    :resource,
    :client_id,
    :client_secret,
    :authorization_endpoint,
    :token_endpoint,
    scopes: [],
    flow: :browser,
    client_auth: :post,
    authorization_params: %{}
  ]

  @own_params ~w(response_type client_id redirect_uri scope state code_challenge code_challenge_method resource)

  @doc "Builds a provider from its name and options."
  @spec new(atom() | String.t(), keyword()) :: t()
  def new(name, opts) do
    opts =
      opts
      |> Keyword.validate!(@options)
      |> Keyword.update(:authorization_params, %{}, &params!/1)
      |> Keyword.update!(:client_auth, &client_auth!/1)

    provider = struct!(__MODULE__, [name: to_string(name)] ++ opts)

    if findable?(provider),
      do: provider,
      else:
        raise(
          ArgumentError,
          "The #{name} provider needs an :issuer, a :resource, or its endpoints"
        )
  end

  @doc "Returns whether the provider names its own endpoints, so nothing needs discovering."
  @spec endpoints?(t()) :: boolean()
  def endpoints?(%__MODULE__{authorization_endpoint: authorize, token_endpoint: token}),
    do: is_binary(authorize) and is_binary(token)

  defp findable?(%__MODULE__{issuer: nil, resource: nil} = provider), do: endpoints?(provider)
  defp findable?(_provider), do: true

  defp client_auth!(how) when how in [:post, :basic], do: how

  defp client_auth!(how),
    do: raise(ArgumentError, "client_auth is :post or :basic, not #{inspect(how)}")

  defp params!(params) do
    params = Map.new(params, fn {key, value} -> {to_string(key), to_string(value)} end)

    case Enum.filter(Map.keys(params), fn key -> key in @own_params end) do
      [] -> params
      own -> raise ArgumentError, "authorization_params can't set #{Enum.join(own, ", ")}"
    end
  end
end
