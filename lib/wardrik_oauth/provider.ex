defmodule WardrikOAuth.Provider do
  @moduledoc """
  A provider is an account a principal can authorize, named like the credential it grants.

      github: [
        issuer: "https://github.com/login/oauth",
        resource: "https://api.githubcopilot.com/mcp/",
        client_id: System.fetch_env!("GITHUB_CLIENT_ID"),
        client_secret: System.fetch_env!("GITHUB_CLIENT_SECRET"),
        scopes: ~w(repo)
      ]

  `:client_id` is required. Give `:issuer`, `:resource`, or both. Without an issuer, it's found
  from the resource's metadata.
  """

  @derive {Inspect, except: [:client_secret]}
  @enforce_keys [:name, :client_id]
  defstruct [:name, :issuer, :resource, :client_id, :client_secret, scopes: []]

  @typedoc "A provider a principal can authorize."
  @type t() :: %__MODULE__{
          name: String.t(),
          issuer: String.t() | nil,
          resource: String.t() | nil,
          client_id: String.t(),
          client_secret: String.t() | nil,
          scopes: [String.t()]
        }

  @doc "Builds a provider from its name and options."
  @spec new(atom() | String.t(), keyword()) :: t()
  def new(name, opts) do
    opts = Keyword.validate!(opts, [:issuer, :resource, :client_id, :client_secret, scopes: []])

    if is_nil(opts[:issuer]) and is_nil(opts[:resource]),
      do: raise(ArgumentError, "The #{name} provider needs an :issuer or a :resource")

    struct!(__MODULE__, [name: to_string(name)] ++ opts)
  end
end
