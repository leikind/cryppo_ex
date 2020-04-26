defmodule Cryppo.Strategies do
  @moduledoc false

  alias Cryppo.{Aes256gcm, Pbkdf2hmac, Rsa4096}

  # probably code it with a macro
  @spec find_strategy(Cryppo.encryption_strategy()) ::
          {:ok, Cryppo.encryption_strategy_module()} | {:unsupported_encryption_strategy, any}
  def find_strategy(encryption_strategy) do
    case encryption_strategy do
      "Aes256Gcm" -> {:ok, Aes256gcm}
      "Rsa4096" -> {:ok, Rsa4096}
      _ -> {:unsupported_encryption_strategy, encryption_strategy}
    end
  end

  @spec find_key_derivation_strategy(Cryppo.encryption_strategy()) ::
          {:ok, atom} | {:unsupported_key_derivation_strategy, Cryppo.encryption_strategy()}
  def find_key_derivation_strategy(key_derivation_strategy) do
    case key_derivation_strategy do
      "Pbkdf2Hmac" -> {:ok, Pbkdf2hmac}
      _ -> {:unsupported_key_derivation_strategy, key_derivation_strategy}
    end
  end
end
