defmodule WardrikOAuth.Browser do
  @moduledoc """
  A browser flow signs a principal in on the service's page, with the authorization code flow and PKCE.
  """

  alias WardrikOAuth.Metadata
  alias WardrikOAuth.Provider
  alias WardrikOAuth.Request
  alias WardrikOAuth.Token

  @doc "Builds the URL that starts a sign-in, with its `state` and PKCE verifier."
  @spec start(Metadata.t(), Provider.t(), String.t()) ::
          {:ok, %{url: String.t(), state: String.t(), verifier: String.t()}} | {:error, term()}
  def start(%Metadata{authorization_endpoint: nil, issuer: issuer}, _provider, _redirect_uri),
    do: {:error, {:no_browser_flow, issuer}}

  def start(%Metadata{} = metadata, %Provider{} = provider, redirect_uri) do
    state = random()
    verifier = random()

    query =
      %{
        "response_type" => "code",
        "client_id" => provider.client_id,
        "redirect_uri" => redirect_uri,
        "state" => state,
        "code_challenge" => challenge(verifier),
        "code_challenge_method" => "S256"
      }
      |> Request.present("scope", Enum.join(provider.scopes, " "))
      |> Request.present("resource", provider.resource)
      |> Map.merge(provider.authorization_params)

    url =
      metadata.authorization_endpoint
      |> URI.new!()
      |> URI.append_query(URI.encode_query(query))
      |> URI.to_string()

    {:ok, %{url: url, state: state, verifier: verifier}}
  end

  @doc "Returns whether a callback's `iss` names the issuer, or needn't."
  @spec issued_by?(Metadata.t(), String.t() | nil) :: boolean()
  def issued_by?(%Metadata{issuer: nil, iss_supported?: false}, _iss), do: true
  def issued_by?(%Metadata{issuer: issuer}, issuer) when is_binary(issuer), do: true
  def issued_by?(%Metadata{iss_supported?: supported?}, nil), do: not supported?
  def issued_by?(%Metadata{}, _other), do: false

  @doc "Exchanges the code a principal came back with for a token."
  @spec exchange(Metadata.t(), Provider.t(), String.t(), String.t(), keyword()) ::
          {:ok, Token.t()} | {:error, term()}
  def exchange(%Metadata{} = metadata, %Provider{} = provider, code, verifier, opts) do
    form =
      %{}
      |> Map.merge(%{
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => Keyword.fetch!(opts, :redirect_uri),
        "code_verifier" => verifier
      })
      |> Request.present("resource", provider.resource)

    with {:ok, status, body} <-
           Request.post_as(
             metadata.token_endpoint,
             provider,
             form,
             Keyword.fetch!(opts, :req_options)
           ),
         do: Token.from_response(status, body, metadata.token_endpoint)
  end

  defp challenge(verifier),
    do: :sha256 |> :crypto.hash(verifier) |> Base.url_encode64(padding: false)

  defp random, do: 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
end
