defprotocol Cryppo.Serialization do
  @moduledoc """
  Cryppo serialization protocol
  """

  @spec serialize(t) :: String.t()
  def serialize(value)
end
