defmodule Cryppo.Base64 do
  @moduledoc false

  @spec decode_base64(binary) :: {:error, :invalid_base64} | {:ok, String.t()}
  def decode_base64(base64) do
    case Base.url_decode64(base64) do
      :error ->
        case Base.decode64(base64) do
          {:ok, _bin} -> {:error, "only URL-safe base64 is supported"}
          _ -> {:error, :invalid_base64}
        end

      {:ok, decoded} ->
        {:ok, decoded}
    end
  end
end
