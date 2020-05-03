defprotocol Cryppo.Serialization do
  @moduledoc false

  # Cryppo serialization protocol

  @spec serialize(t) :: String.t()
  def serialize(value)
end
