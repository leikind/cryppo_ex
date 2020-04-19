defmodule Cryppo.Pbkdf2hmac do
  @moduledoc """
    PBKDF2 key derivation
    https://en.wikipedia.org/wiki/PBKDF2

    hash function: SHA256
    Key length: 32 bytes
    Minimal number of iterations: 20000
  """

  alias Cryppo.{DerivedKey, EncryptionKey}

  @min_iterations 20_000
  @iteration_variance 10
  @variance (@min_iterations * (@iteration_variance / 100.0)) |> trunc

  @salt_length 20
  @key_length 32

  @on_load :init_random_number_generation

  @spec init_random_number_generation :: :ok
  def init_random_number_generation do
    # https://erlang.org/doc/man/crypto.html#rand_seed-0
    :crypto.rand_seed()
    :ok
  end

  def generate_derived_key(passphrase) do
    salt = make_salt()
    iterations = make_iterations()

    {:ok, pdk} =
      :pbkdf2.pbkdf2(
        {:hmac, :sha256},
        passphrase,
        salt,
        iterations,
        @key_length
      )

    %DerivedKey{
      encryption_key: EncryptionKey.new(pdk),
      key_derivation_strategy: __MODULE__,
      salt: salt,
      iter: iterations,
      length: @key_length,
      hash: "SHA256"
    }
  end

  # another clause to reuse an existing key in DerivedKey
  def build_derived_key(passphrase, %DerivedKey{
        salt: salt,
        iter: iterations,
        length: key_length
      }) do
    # TODO DRY
    {:ok, pdk} =
      :pbkdf2.pbkdf2(
        {:hmac, :sha256},
        passphrase,
        salt,
        iterations,
        key_length
      )

    %DerivedKey{
      encryption_key: EncryptionKey.new(pdk),
      key_derivation_strategy: __MODULE__,
      salt: salt,
      iter: iterations,
      length: key_length,
      hash: "SHA256"
    }
  end

  # provide some randomisation to the number of iterations
  defp make_iterations do
    @min_iterations + :rand.uniform(@variance)
  end

  defp make_salt, do: :crypto.strong_rand_bytes(@salt_length)
end
