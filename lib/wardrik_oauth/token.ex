defmodule WardrikOAuth.Token do
  @moduledoc """
  A token an authorization server granted. Kept in the vault as JSON.
  """

  alias WardrikOAuth.Request

  @derive {Inspect, only: [:expires_at, :scope]}
  @enforce_keys [:access_token, :token_endpoint]
  defstruct [:access_token, :refresh_token, :expires_at, :scope, :token_endpoint]

  @typedoc "An access token and what came with it."
  @type t() :: %__MODULE__{
          access_token: String.t(),
          refresh_token: String.t() | nil,
          expires_at: integer() | nil,
          scope: String.t() | nil,
          token_endpoint: String.t()
        }

  @margin_seconds 30
  @fields ~w(access_token refresh_token expires_at scope token_endpoint)

  @doc "Reads a token endpoint's response. Returns the token, or the error it holds."
  @spec from_response(pos_integer(), map(), String.t()) :: {:ok, t()} | {:error, term()}
  def from_response(_status, %{"access_token" => access_token} = body, token_endpoint)
      when is_binary(access_token) do
    {:ok,
     %__MODULE__{
       access_token: access_token,
       refresh_token: body["refresh_token"],
       expires_at: expires_at(body["expires_in"]),
       scope: body["scope"],
       token_endpoint: token_endpoint
     }}
  end

  def from_response(status, body, _token_endpoint), do: {:error, Request.refusal(status, body)}

  @doc "Returns whether the token is valid for more than 30 more seconds."
  @spec fresh?(t()) :: boolean()
  def fresh?(%__MODULE__{expires_at: nil}), do: true

  def fresh?(%__MODULE__{expires_at: expires_at}),
    do: expires_at - @margin_seconds > System.system_time(:second)

  @doc "Returns whether the token can be refreshed."
  @spec renewable?(t()) :: boolean()
  def renewable?(%__MODULE__{refresh_token: refresh_token}), do: is_binary(refresh_token)

  @doc "Marks the token expired, so the next use refreshes it."
  @spec expire(t()) :: t()
  def expire(%__MODULE__{} = token), do: %{token | expires_at: 0}

  @doc "Copies `old`'s refresh token into `new` if `new` has none."
  @spec carry_refresh(t(), t()) :: t()
  def carry_refresh(%__MODULE__{refresh_token: nil} = new, %__MODULE__{} = old),
    do: %{new | refresh_token: old.refresh_token}

  def carry_refresh(%__MODULE__{} = new, _old), do: new

  @doc "Encodes the token as JSON."
  @spec encode(t()) :: String.t()
  def encode(%__MODULE__{} = token), do: token |> Map.from_struct() |> JSON.encode!()

  @doc "Decodes a token from JSON."
  @spec decode(String.t()) :: {:ok, t()} | {:error, :unreadable}
  def decode(json) do
    case JSON.decode(json) do
      {:ok, %{"access_token" => access_token, "token_endpoint" => endpoint} = map}
      when is_binary(access_token) and is_binary(endpoint) ->
        {:ok, struct!(__MODULE__, Enum.map(Map.take(map, @fields), &field/1))}

      _other ->
        {:error, :unreadable}
    end
  end

  defp field({key, value}), do: {String.to_existing_atom(key), value}

  defp expires_at(seconds) when is_integer(seconds), do: System.system_time(:second) + seconds
  defp expires_at(_none), do: nil
end
