defmodule Cryppo do
  @moduledoc """
    Main public API of Cryppo
  """

  alias Cryppo.{
    DerivedKey,
    EncryptedData,
    EncryptedDataWithDerivedKey,
    EncryptionKey,
    Loader,
    RsaSignature,
    Serialization,
    Strategies
  }

  import Strategies, only: [find_strategy: 1, find_key_derivation_strategy: 1]

  @typedoc """
  Name of an encryption or derivation strategy

  Use `Cryppo.encryption_strategies/0` to get a list of encryption strategies.
  Use `Cryppo.derivation_strategies/0` to get a list of derivation strategies.
  """

  @type encryption_strategy() :: String.t()

  @typedoc """
  Module of an encryption or derivation strategy
  """
  @type encryption_strategy_module() :: atom

  @doc "List available encryption strategies"
  @spec encryption_strategies :: [encryption_strategy()]
  def encryption_strategies, do: Strategies.encryption_strategies()

  @doc "List available  derivation strategies"
  @spec derivation_strategies :: [encryption_strategy()]
  def derivation_strategies, do: Strategies.derivation_strategies()

  @doc """
  Generate an encryption key for an encryption strategy

  The generated encrypted key is marked as belonging to the encryption strategy.

  ## Example

      iex> _encryption_key = Cryppo.generate_encryption_key("Aes256Gcm")
  """
  @spec generate_encryption_key(encryption_strategy) ::
          EncryptionKey.t() | {:unsupported_encryption_strategy, binary}
  def generate_encryption_key(encryption_strategy) when is_binary(encryption_strategy) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      %EncryptionKey{} = apply(mod, :generate_key, [])
    end
  end

  @doc """
  Encrypt data with an encryption key

  ## Example

      iex> encryption_key = Cryppo.generate_encryption_key("Aes256Gcm")
      iex> _encrypted_data = Cryppo.encrypt("data to encrypt", "Aes256Gcm", encryption_key)

  The encryption key must match the encryption strategy:

      iex> encryption_key = Cryppo.generate_encryption_key("Aes256Gcm")
      iex> Cryppo.encrypt("data to encrypt", "Rsa4096", encryption_key)
      {:incompatible_key, [submitted_key_strategy: Cryppo.Aes256gcm, encryption_strategy: Cryppo.Rsa4096]}
  """
  @spec encrypt(binary, encryption_strategy, EncryptionKey.t() | any) ::
          EncryptedData.t()
          | {:unsupported_encryption_strategy, atom}
          | {:error, :invalid_encryption_key}
          | :encryption_error
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def encrypt(data, encryption_strategy, encryption_key_or_raw_key)
      when is_binary(encryption_strategy) and is_binary(data) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      encryption_key_or_raw_key =
        encryption_key_or_raw_key
        |> add_encryption_strategy_module(mod)

      apply(mod, :run_encryption, [data, encryption_key_or_raw_key])
    end
  end

  @doc """
  Generate an encryption key for an encryption strategy and encrypt data with this encryption key

  ## Example

      iex> {_encrypted_data, _encryption_key} = Cryppo.encrypt("data to encrypt", "Aes256Gcm")
  """
  @spec encrypt(binary, encryption_strategy) ::
          EncryptedData.t()
          | {:unsupported_encryption_strategy, atom}
          | :encryption_error
  def encrypt(data, encryption_strategy)
      when is_binary(encryption_strategy) and is_binary(data) do
    with {:ok, mod} <- find_strategy(encryption_strategy) do
      encryption_key = apply(mod, :generate_key, [])
      encrypted = apply(mod, :run_encryption, [data, encryption_key])
      {encrypted, encryption_key}
    end
  end

  defp add_encryption_strategy_module(key, mod) do
    case key do
      %EncryptionKey{encryption_strategy_module: nil} = key ->
        %{key | encryption_strategy_module: mod}

      k ->
        k
    end
  end

  @doc """
  Decrypt encrypted data with an encryption key

  ## Example

      iex> {encrypted_data, encryption_key} = Cryppo.encrypt("data to encrypt", "Aes256Gcm")
      iex> Cryppo.decrypt(encrypted_data, encryption_key)
      {:ok, "data to encrypt"}
  """
  @spec decrypt(EncryptedData.t(), EncryptionKey.t() | any) ::
          {:ok, binary}
          | {:error, :invalid_encryption_key}
          | :decryption_error
          | {:decryption_error, {any, any}}
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def decrypt(
        %EncryptedData{encryption_strategy_module: mod} = encrypted_data,
        encryption_key_or_raw_key
      ) do
    encryption_key_or_raw_key = encryption_key_or_raw_key |> add_encryption_strategy_module(mod)

    apply(mod, :run_decryption, [encrypted_data, encryption_key_or_raw_key])
  end

  @doc """
  Encrypt data with a derived key

  ## Example

      iex> _encrypted = Cryppo.encrypt_with_derived_key("data to encrypt", "Aes256Gcm", "Pbkdf2Hmac", "passphrase")

  """
  @spec encrypt_with_derived_key(binary, encryption_strategy(), encryption_strategy(), String.t()) ::
          EncryptedDataWithDerivedKey.t()
          | {:unsupported_encryption_strategy, encryption_strategy}
          | {:unsupported_key_derivation_strategy, encryption_strategy}
  def encrypt_with_derived_key(
        data,
        encryption_strategy,
        key_derivation_strategy,
        passphrase
      )
      when is_binary(encryption_strategy) and is_binary(key_derivation_strategy) and
             is_binary(passphrase) and is_binary(data) do
    with {:ok, key_derivation_mod} <- find_key_derivation_strategy(key_derivation_strategy),
         {:ok, encryption_strategy_mod} <- find_strategy(encryption_strategy) do
      %DerivedKey{encryption_key: key} =
        derived_key = apply(key_derivation_mod, :generate_derived_key, [passphrase])

      key_with_encryption_strategy = %{key | encryption_strategy_module: encryption_strategy_mod}

      %EncryptedData{} =
        encrypted_data =
        apply(encryption_strategy_mod, :run_encryption, [data, key_with_encryption_strategy])

      %EncryptedDataWithDerivedKey{encrypted_data: encrypted_data, derived_key: derived_key}
    end
  end

  @doc """
  Decrypt data with a derived key

  ## Example

      iex> encrypted = Cryppo.encrypt_with_derived_key("data to encrypt", "Aes256Gcm", "Pbkdf2Hmac", "passphrase")
      iex> {:ok, decrypted, _key} = Cryppo.decrypt_with_derived_key(encrypted, "passphrase")
      iex> decrypted
      "data to encrypt"
  """
  @spec decrypt_with_derived_key(EncryptedDataWithDerivedKey.t(), String.t()) ::
          {:ok, binary, DerivedKey.t()}
          | :decryption_error
          | {:decryption_error, {any, any}}
          | {:incompatible_key, submitted_key_strategy: atom, encryption_strategy: atom}
  def decrypt_with_derived_key(
        %EncryptedDataWithDerivedKey{
          derived_key:
            %DerivedKey{
              key_derivation_strategy: key_derivation_mod
            } = derived_key,
          encrypted_data:
            %EncryptedData{
              encryption_strategy_module: encryption_strategy_mod
            } = encrypted_data
        },
        passphrase
      )
      when is_binary(passphrase) do
    derived_key =
      %DerivedKey{encryption_key: key} =
      apply(key_derivation_mod, :build_derived_key, [passphrase, derived_key])

    key_with_encryption_strategy = %{key | encryption_strategy_module: encryption_strategy_mod}

    with {:ok, decrypted} <-
           apply(encryption_strategy_mod, :run_decryption, [
             encrypted_data,
             key_with_encryption_strategy
           ]) do
      {:ok, decrypted, derived_key}
    end
  end

  @doc """
  Serialize various Cryppo data structures as a string

  3 Cryppo data structures have their own serialization formats:

  * `Cryppo.EncryptedData`
  * `Cryppo.EncryptedDataWithDerivedKey`
  * `Cryppo.RsaSignature`

  ## Examples

  `Cryppo.EncryptedData`:

      iex> {encrypted_data, _key} = Cryppo.encrypt("data to encrypt", "Aes256Gcm")
      iex> Cryppo.serialize(encrypted_data)

  `Cryppo.EncryptedDataWithDerivedKey`:

      iex> "data to encrypt"
      ...> |> Cryppo.encrypt_with_derived_key("Aes256Gcm", "Pbkdf2Hmac", "passphrase")
      ...> |> Cryppo.serialize()

  `Cryppo.RsaSignature`:

      iex> private_key = Cryppo.generate_encryption_key("Rsa4096")
      iex> "data to encrypt"
      ...> |> Cryppo.Rsa4096.sign(private_key)
      ...> |> Cryppo.serialize()
  """
  @spec serialize(EncryptedData.t() | EncryptedDataWithDerivedKey.t() | RsaSignature.t()) ::
          binary
  def serialize(%EncryptedData{} = s), do: Serialization.serialize(s)
  def serialize(%EncryptedDataWithDerivedKey{} = s), do: Serialization.serialize(s)
  def serialize(%RsaSignature{} = s), do: Serialization.serialize(s)

  @doc """
  Load various Cryppo data structures from theur serialized forms

  3 Cryppo data structures have their own serialization formats:

  * `Cryppo.EncryptedData`
  * `Cryppo.EncryptedDataWithDerivedKey`
  * `Cryppo.RsaSignature`

  ## Examples

      iex> s = "Aes256Gcm.vDY5WSQjdYkBIAcbIfTgk4e-TXHp.LS0tCmFkOiBub25lCmF0OiAhIWJpbmFyeSB8LQogIGkyTWliWVlvdTh6b2FvM3ZOR0FiV1E9PQppdjogISFiaW5hcnkgfC0KICBUT0o4TUwyN1pId01tVmVwCg=="
      iex> %Cryppo.EncryptedData{} = Cryppo.load(s)

      iex> s = "Aes256Gcm.fkPSVHHuUeRbRMGzLqno_7qh74OGfdl5dg==.LS0tCmFkOiBub25lCmF0OiAhIWJpbmFyeSB8LQogIEZSME5UNUx2Zmpsd3lEY3NKUm9VcEE9PQppdjogISFiaW5hcnkgfC0KICBtRWdzdDMvdjg0Q0V2aEZHCg==.Pbkdf2Hmac.LS0tCidpJzogMjE5MjgKJ2l2JzogISFiaW5hcnkgfC0KICBEZVNHRTlBVS9BVG1QM3JaeEYzUGt5V1ZHSU09CidsJzogMzIK"
      iex> %Cryppo.EncryptedDataWithDerivedKey{} = Cryppo.load(s)

      iex> s = "Sign.Rsa4096.V4JbRzpkud-3cHCGqDwGjS3TmRto5Te0iSAtD7oIzsDa83McBDYpU_eeswVZF9AGEvoAEQOCwpqJ_PgbjHKT2nHgLysK-btG6Nxk_K2J7A6Uq15X5QrOgIKTzC00dj1tzAN73u9lsRPKIfwPyp_Mlb6FNs1LoB7OvAusit6QPm8iAwHo4nOWBBUf3hO9b3gsWJ92FxnBsCLYFQj_zv4mnLHj7pDNVtq9Kp4hK6bgcIH4FZtyDKDr6bXEtlCGLDIY10UqNLylkagI36Gyafm-HnD57vRxjgHIGEsd2XcwDJ8PqqrzSYNxl-RyWD3wq0nXE_1rYJ7k1AKLM5G1Hg8B2whqcXpQ52x3zVFCAjlU9GNhT6pdUBxQYw09va7fe2w517PrwwMe90MW87fj3G7dGEKT95cDLTx1d84ybIUFUJOGKY0FF4LL0E3UqWQ92kU4bh-DSTkNmgItX34fiBIOpQDbF238IkRYyFA8LfMPfL-0_dnto9sH0E3Umi41qFvpA2Nq8r57FF4vCOSkXYWVfyitOkY_URqMLxS57azwZRBehJYDtvbqmzaYEDceeLjkxDi--Y10LT4Cz2SGiU--YDJM66PZ3Cp74gvDpsWlohcwYmMib5LrjdtvLOAtOZhoLZyGeeX0lDnwOum7lFRpJd8UIrOlTvpBo48ep2bpmgA=.VmVyaMO8dHVuZyB2ZXJib3Rlbg=="
      iex> %Cryppo.RsaSignature{} = Cryppo.load(s)
  """
  @spec load(binary) ::
          EncryptedDataWithDerivedKey.t()
          | EncryptedData.t()
          | RsaSignature.t()
          | {:error, :invalid_base64}
          | {:error, :invalid_yaml}
          | {:error, :invalid_derivation_artefacts}
          | {:unsupported_encryption_strategy, binary}
          | {:unsupported_key_derivation_strategy, binary}
  def load(serialized), do: Loader.load(serialized)
end
