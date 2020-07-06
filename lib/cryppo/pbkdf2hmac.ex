defmodule Cryppo.Pbkdf2hmac do
  @moduledoc false

  # PBKDF2 key derivation
  # https://en.wikipedia.org/wiki/PBKDF2

  # hash function: SHA256
  # Key length: 32 bytes
  # Minimal number of iterations: 20000

  use Cryppo.DerivationStrategy, strategy_name: "Pbkdf2Hmac"

  @min_iterations 20_000
  @iteration_variance 10
  @variance (@min_iterations * (@iteration_variance / 100.0)) |> trunc

  @salt_length 20

  @spec hash_function :: binary
  def hash_function, do: "SHA256"

  @spec generate_derived_key(String.t(), integer()) :: DerivedKey.t()
  @impl DerivationStrategy
  def generate_derived_key(passphrase, key_length) do
    salt = make_salt()
    iterations = make_iterations()
    passphrase |> derive_and_build_derived_key(salt, iterations, key_length)
  end

  @spec build_derived_key(String.t(), DerivedKey.t()) :: DerivedKey.t()
  @impl DerivationStrategy
  def build_derived_key(
        _passphrase,
        %DerivedKey{
          encryption_key: %EncryptionKey{key: key}
        } = derived_key
      )
      when is_binary(key) do
    # derived_key already has the encryption key, we do nothing
    derived_key
  end

  def build_derived_key(passphrase, %DerivedKey{
        salt: salt,
        iter: iterations,
        length: key_length
      }) do
    passphrase |> derive_and_build_derived_key(salt, iterations, key_length)
  end

  @spec derive_and_build_derived_key(String.t(), binary, integer, integer) :: DerivedKey.t()
  defp derive_and_build_derived_key(passphrase, salt, iterations, key_length) do
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
      hash: hash_function()
    }
  end

  # provide some randomisation to the number of iterations
  @spec make_iterations :: pos_integer
  defp make_iterations do
    @min_iterations + :rand.uniform(@variance)
  end

  @spec make_salt :: binary
  defp make_salt, do: :crypto.strong_rand_bytes(@salt_length)
end
