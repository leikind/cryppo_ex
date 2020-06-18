defmodule Cryppo.Aes do
  @moduledoc false

  alias Cryppo.EncryptionKey

  @spec build_encryption_key(binary, atom) ::
          {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}
  def build_encryption_key(raw_key, mod) when is_binary(raw_key) and is_atom(mod) do
    key = EncryptionKey.new(raw_key, mod)
    {:ok, key}
  end

  def build_encryption_key(_, _), do: {:error, :invalid_encryption_key}

  @spec generate_key(non_neg_integer, atom) :: EncryptionKey.t()
  def generate_key(key_length, mod) do
    key_length |> :crypto.strong_rand_bytes() |> EncryptionKey.new(mod)
  end
end
