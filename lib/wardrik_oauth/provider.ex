defmodule WardrikOAuth.Provider do
  @schema NimbleOptions.new!(
            issuer: [
              type: :string,
              doc: "The authorization server, whose metadata names its endpoints."
            ],
            resource: [
              type: :string,
              doc: "The API or MCP server the token is for. Finds the issuer if none is given."
            ],
            authorization_endpoint: [
              type: :string,
              doc: "Where people sign in, for a service without metadata."
            ],
            token_endpoint: [
              type: :string,
              doc: "Where codes become tokens, for a service without metadata."
            ],
            client_id: [
              type: :string,
              doc: """
              Your OAuth app's client ID. Without it, Wardrik becomes the client where the
              service allows. See `WardrikOAuth.add_provider/3`.
              """
            ],
            client_secret: [
              type: {:or, [:string, {:tuple, [{:in, [:secret]}, :string]}]},
              doc: "The client secret, or `{:secret, name}` to read it from the vault."
            ],
            client_auth: [
              type: {:in, [:post, :basic]},
              default: :post,
              doc: "`:post` sends the secret in the form, `:basic` as HTTP Basic."
            ],
            scopes: [type: {:list, :string}, default: [], doc: "The scopes to ask for."],
            flow: [
              type: {:in, [:browser, :device]},
              default: :browser,
              doc: "How people sign in."
            ],
            authorization_params: [
              type: {:custom, __MODULE__, :params, []},
              default: %{},
              doc: """
              Extra parameters for a browser sign-in, as `%{access_type: "offline"}`. Can't set
              the ones Wardrik sends itself.
              """
            ]
          )

  @moduledoc """
  An OAuth app with a service. It has the same name as the credential it grants.

      github: [
        issuer: "https://github.com/login/oauth",
        client_id: System.fetch_env!("GITHUB_CLIENT_ID"),
        client_secret: {:secret, "GITHUB_CLIENT_SECRET"},
        scopes: ~w(repo),
        flow: :device
      ]

  ## Options

  #{NimbleOptions.docs(@schema)}

  A provider needs an `:issuer`, a `:resource`, or both endpoints.
  """

  @own_params ~w(response_type client_id redirect_uri scope state code_challenge code_challenge_method resource)

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

  @typedoc "An OAuth app a principal can grant access to."
  @type t() :: %__MODULE__{
          name: String.t(),
          issuer: String.t() | nil,
          resource: String.t() | nil,
          client_id: String.t() | nil,
          client_secret: WardrikVault.value(),
          authorization_endpoint: String.t() | nil,
          token_endpoint: String.t() | nil,
          scopes: [String.t()],
          flow: :browser | :device,
          client_auth: :post | :basic,
          authorization_params: %{optional(String.t()) => String.t()}
        }

  @doc """
  Builds a provider from its name and options.

  Raises `NimbleOptions.ValidationError` on invalid options, or `ArgumentError` if nothing names
  the server.
  """
  @spec new(atom() | String.t(), keyword()) :: t()
  def new(name, opts) do
    opts = NimbleOptions.validate!(opts, @schema)
    provider = struct!(__MODULE__, [name: to_string(name)] ++ opts)

    if findable?(provider),
      do: provider,
      else:
        raise(
          ArgumentError,
          "The #{name} provider needs an :issuer, a :resource, or its endpoints"
        )
  end

  @doc "Returns whether the provider names both endpoints, so none need discovering."
  @spec endpoints?(t()) :: boolean()
  def endpoints?(%__MODULE__{authorization_endpoint: authorize, token_endpoint: token}),
    do: is_binary(authorize) and is_binary(token)

  defp findable?(%__MODULE__{issuer: nil, resource: nil} = provider), do: endpoints?(provider)
  defp findable?(_provider), do: true

  @doc false
  def params(params) when is_map(params) or is_list(params) do
    params = Map.new(params, fn {key, value} -> {to_string(key), to_string(value)} end)

    case Enum.filter(Map.keys(params), &(&1 in @own_params)) do
      [] -> {:ok, params}
      own -> {:error, "authorization_params can't set #{Enum.join(own, ", ")}"}
    end
  end

  def params(params), do: {:error, "authorization_params is a map, not #{inspect(params)}"}
end
