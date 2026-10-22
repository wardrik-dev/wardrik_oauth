defmodule WardrikOAuth.Metadata do
  @moduledoc """
  Metadata is what an authorization server says about itself, found from its issuer.
  """

  alias WardrikOAuth.Provider
  alias WardrikOAuth.Request

  @enforce_keys [:issuer, :token_endpoint]
  defstruct [:issuer, :token_endpoint, :device_authorization_endpoint]

  @typedoc "What an authorization server says about itself."
  @type t() :: %__MODULE__{
          issuer: String.t(),
          token_endpoint: String.t(),
          device_authorization_endpoint: String.t() | nil
        }

  @doc "Finds the metadata of `provider`'s authorization server."
  @spec discover(Provider.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def discover(%Provider{} = provider, req_options) do
    with {:ok, issuer} <- issuer(provider, req_options),
         {:ok, body} <- server_metadata(issuer, req_options),
         :ok <- same_issuer(body, issuer) do
      read(body)
    end
  end

  defp issuer(%Provider{issuer: issuer}, _req_options) when is_binary(issuer), do: {:ok, issuer}

  defp issuer(%Provider{resource: resource}, req_options) do
    case Request.get_json(well_known(resource, "oauth-protected-resource"), req_options) do
      {:ok, %{"authorization_servers" => [issuer | _rest]}} -> {:ok, issuer}
      {:ok, _body} -> {:error, {:no_authorization_server, resource}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp server_metadata(issuer, req_options) do
    case Request.get_json(well_known(issuer, "oauth-authorization-server"), req_options) do
      {:ok, body} -> {:ok, body}
      {:error, _reason} -> Request.get_json(openid(issuer), req_options)
    end
  end

  defp same_issuer(%{"issuer" => said}, issuer) do
    if trimmed(said) == trimmed(issuer), do: :ok, else: {:error, {:issuer_mismatch, said}}
  end

  defp same_issuer(_body, issuer), do: {:error, {:issuer_mismatch, issuer}}

  defp read(%{"issuer" => issuer, "token_endpoint" => token_endpoint} = body) do
    {:ok,
     %__MODULE__{
       issuer: issuer,
       token_endpoint: token_endpoint,
       device_authorization_endpoint: body["device_authorization_endpoint"]
     }}
  end

  defp read(_body), do: {:error, :metadata_unreadable}

  defp well_known(url, suffix) do
    uri = URI.parse(url)
    path = trimmed(uri.path || "")
    URI.to_string(%{uri | path: "/.well-known/#{suffix}#{path}", query: nil, fragment: nil})
  end

  defp openid(issuer), do: trimmed(issuer) <> "/.well-known/openid-configuration"

  defp trimmed(url), do: String.trim_trailing(url, "/")
end
