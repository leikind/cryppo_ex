defmodule Cryppo.Base64 do
  @moduledoc false

  @spec decode_base64(binary) :: {:error, :invalid_base64} | {:ok, binary}
  def decode_base64(base64) do
    case Base.url_decode64(base64) do
      :error -> {:error, :invalid_base64}
      {:ok, decoded} -> {:ok, decoded}
    end
  end
end
