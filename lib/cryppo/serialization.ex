defprotocol Cryppo.Serialization do
  @moduledoc false

  # Cryppo serialization protocol

  @spec serialize(t) :: String.t() | {:error, atom}
  def serialize(value)
end
