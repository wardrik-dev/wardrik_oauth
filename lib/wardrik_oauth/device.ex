defmodule WardrikOAuth.Device do
  @moduledoc """
  Device sign-in (RFC 8628): the principal enters a code on any device.
  """

  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Request
  alias WardrikOAuth.Token

  @grant "urn:ietf:params:oauth:grant-type:device_code"
  @longest_seconds 1800

  @enforce_keys [:device_code, :user_code, :verification_uri, :expires_in, :interval]
  defstruct [:device_code, :user_code, :verification_uri, :expires_in, :interval]

  @typedoc "The code the server gave and where to enter it."
  @type t() :: %__MODULE__{
          device_code: String.t(),
          user_code: String.t(),
          verification_uri: String.t(),
          expires_in: pos_integer(),
          interval: non_neg_integer()
        }

  @typedoc "The result of one poll."
  @type poll() :: {:ok, Token.t()} | :pending | :slow_down | {:retry, term()} | {:error, term()}

  @doc "Requests a code for the principal to enter."
  @spec request(Metadata.t(), Provider.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def request(%Metadata{device_authorization_endpoint: nil, issuer: issuer}, _provider, _req),
    do: {:error, {:no_device_flow, issuer}}

  def request(%Metadata{} = metadata, %Provider{} = provider, req_options) do
    form =
      %{}
      |> Request.present("scope", Enum.join(provider.scopes, " "))
      |> Request.present("resource", provider.resource)

    case Request.post_as(metadata.device_authorization_endpoint, provider, form, req_options) do
      {:ok, 200, body} -> read(body)
      {:ok, status, body} -> {:error, Request.refusal(status, body)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "Polls the token endpoint once to see if the principal has entered the code."
  @spec poll(Metadata.t(), Provider.t(), t(), keyword()) :: poll()
  def poll(%Metadata{} = metadata, %Provider{} = provider, %__MODULE__{} = device, req_options) do
    form =
      %{}
      |> Map.merge(%{"grant_type" => @grant, "device_code" => device.device_code})
      |> Request.present("resource", provider.resource)

    metadata.token_endpoint
    |> Request.post_as(provider, form, req_options)
    |> polled(metadata.token_endpoint)
  end

  @doc "Returns milliseconds to wait before the next poll. Adds 5 seconds after `:slow_down`."
  @spec next_interval(poll(), non_neg_integer()) :: non_neg_integer()
  def next_interval(:slow_down, interval_ms), do: interval_ms + :timer.seconds(5)
  def next_interval(_poll, interval_ms), do: interval_ms

  defp polled({:ok, _status, %{"error" => "authorization_pending"}}, _endpoint), do: :pending
  defp polled({:ok, _status, %{"error" => "slow_down"}}, _endpoint), do: :slow_down

  defp polled({:ok, _status, %{"error" => "access_denied"}}, _endpoint),
    do: {:error, :access_denied}

  defp polled({:ok, _status, %{"error" => "expired_token"}}, _endpoint), do: {:error, :expired}
  defp polled({:ok, status, _body}, _endpoint) when status >= 500, do: {:retry, {:http, status}}
  defp polled({:ok, status, body}, endpoint), do: Token.from_response(status, body, endpoint)
  defp polled({:error, {:unreachable, reason}}, _endpoint), do: {:retry, reason}
  defp polled({:error, reason}, _endpoint), do: {:error, reason}

  defp read(%{"device_code" => device_code, "user_code" => user_code} = body) do
    case {body["verification_uri"] || body["verification_url"], body["expires_in"]} do
      {uri, expires_in} when is_binary(uri) and is_integer(expires_in) and expires_in > 0 ->
        {:ok,
         %__MODULE__{
           device_code: device_code,
           user_code: user_code,
           verification_uri: uri,
           expires_in: min(expires_in, @longest_seconds),
           interval: interval(body["interval"])
         }}

      _missing ->
        {:error, :device_unreadable}
    end
  end

  defp read(_body), do: {:error, :device_unreadable}

  defp interval(seconds) when is_integer(seconds) and seconds >= 0, do: seconds
  defp interval(_absent), do: 5
end
