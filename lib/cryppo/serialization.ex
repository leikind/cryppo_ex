defprotocol Cryppo.Serialization do
  @moduledoc false

  # Cryppo serialization protocol

  @spec serialize(t, Keyword.t()) :: String.t() | {:error, atom}
  def serialize(value, opts \\ [])
end
