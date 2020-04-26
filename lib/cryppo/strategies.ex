defmodule Cryppo.Strategies do
  @moduledoc false

  alias Cryppo.{Aes256gcm, Pbkdf2hmac, Rsa4096}

  @encryption_strategies %{"Aes256Gcm" => Aes256gcm, "Rsa4096" => Rsa4096}
  @derivation_strategies %{"Pbkdf2Hmac" => Pbkdf2hmac}

  @enc_strats_with_ok Enum.into(@encryption_strategies, %{}, fn {k, v} -> {k, {:ok, v}} end)
  @der_strats_with_ok Enum.into(@derivation_strategies, %{}, fn {k, v} -> {k, {:ok, v}} end)

  # TODO Find a way to register and use external strategies

  @spec encryption_strategies :: [Cryppo.encryption_strategy()]
  def encryption_strategies, do: Map.keys(@encryption_strategies)

  @spec derivation_strategies :: [Cryppo.encryption_strategy()]
  def derivation_strategies, do: Map.keys(@derivation_strategies)

  @spec find_strategy(Cryppo.encryption_strategy()) ::
          {:ok, Cryppo.encryption_strategy_module()} | {:unsupported_encryption_strategy, any}
  def find_strategy(encryption_strategy) do
    @enc_strats_with_ok
    |> Map.get(encryption_strategy, {:unsupported_encryption_strategy, encryption_strategy})
  end

  @spec find_key_derivation_strategy(Cryppo.encryption_strategy()) ::
          {:ok, atom} | {:unsupported_key_derivation_strategy, Cryppo.encryption_strategy()}
  def find_key_derivation_strategy(key_derivation_strategy) do
    @der_strats_with_ok
    |> Map.get(
      key_derivation_strategy,
      {:unsupported_key_derivation_strategy, key_derivation_strategy}
    )
  end
end
