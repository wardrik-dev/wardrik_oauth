defmodule WardrikOAuth.Test.Fixed do
  @moduledoc "Resolves the same providers for every principal, each keyed `fixed/name`."
  @behaviour WardrikOAuth.Resolver

  @impl true
  def provider(%{name: name}, providers) do
    case Enum.find(providers, fn {given, _opts} -> to_string(given) == name end) do
      {_given, opts} ->
        {:ok, WardrikOAuth.Provider.new(name, [key: "fixed/" <> name] ++ opts)}

      nil ->
        {:error, :not_found}
    end
  end
end

defmodule WardrikOAuth.Test.Apps do
  @moduledoc "Resolves each principal's providers as the test set them, in an `Agent`."
  @behaviour WardrikOAuth.Resolver

  @impl true
  def provider(%{name: name, principal: principal}, apps) do
    Agent.get(apps, fn set ->
      send(set.test, {:resolved, name, principal.id})
      Map.get(set, {principal.id, name}, {:error, :not_found})
    end)
  end
end
