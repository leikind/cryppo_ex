defmodule Cryppo do
  @moduledoc """
  to do
  """

  alias Cryppo.{Aes256gcm, Rsa4096, EncryptionKey, EncryptedData}

  @type encryption_strategy_name() :: atom()
  @type strategy_not_found() :: tuple()

  @spec generate_encryption_key(encryption_strategy_name) ::
          EncryptionKey.t() | strategy_not_found
  def generate_encryption_key(encryption_strategy) when is_atom(encryption_strategy) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      %EncryptionKey{} = apply(mod, :generate_key, [])
    end
  end

  @spec encrypt(encryption_strategy_name, EncryptionKey.t(), binary) ::
          :ok | {:strategy_not_found, atom}
  def encrypt(encryption_strategy, %EncryptionKey{} = key, data)
      when is_atom(encryption_strategy) and is_binary(data) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      apply(mod, :encrypt, [data, key])
    end
  end

  def decrypt(
        %EncryptedData{encryption_strategy: encryption_strategy} = encrypted_data,
        %EncryptionKey{} = key
      ) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      apply(mod, :decrypt, [encrypted_data, key])
    end
  end

  # code it with a macro
  # Aes256Gcm
  # Rsa4096

  @spec find_strategy(encryption_strategy_name) :: {:ok, atom} | strategy_not_found
  defp find_strategy(strategy) do
    case strategy do
      :aes_256_gcm -> {:ok, Aes256gcm}
      :rsa4096 -> {:ok, Rsa4096}
      _ -> {:strategy_not_found, strategy}
    end
  end
end
