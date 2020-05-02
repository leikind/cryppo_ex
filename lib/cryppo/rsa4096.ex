defmodule Cryppo.Rsa4096 do
  @moduledoc """
    Encryption Strategy RSA 4096.
    Key length 4096
    Exponents: 65537
    Padding: rsa_pkcs1_oaep_padding
  """

  @type rsa_private_key() ::
          {:RSAPrivateKey, integer, integer, integer, integer, integer, integer, integer, integer,
           integer, any}
  @type rsa_public_key() :: {:RSAPublicKey, integer, integer}
  @type pem() :: String.t()

  use Cryppo.EncryptionStrategy, strategy_name: "Rsa4096"
  alias Cryppo.RsaSignature

  # 4096 is the key size in ruby Cryppo
  @size 4_096
  # 65537 is the default in OpenSSL, and hence in ruby Cryppo
  @exponent 65_537

  # rsa_pkcs1_oaep_padding is the padding in ruby Cryppo
  @padding :rsa_pkcs1_oaep_padding

  @spec generate_key :: EncryptionKey.t()
  @impl true
  def generate_key do
    {:rsa, @size, @exponent}
    |> :public_key.generate_key()
    |> EncryptionKey.new(__MODULE__)
  end

  @spec encrypt(binary, EncryptionKey.t()) ::
          {:ok, binary, EncryptedData.encryption_artefacts()} | :encryption_error
  @impl EncryptionStrategy
  def encrypt(data, %EncryptionKey{key: private_key})
      when is_binary(data) and elem(private_key, 0) == :RSAPrivateKey and
             tuple_size(private_key) == 11 do
    public_key = private_key_to_public_key(private_key)
    encrypted = data |> :public_key.encrypt_public(public_key, rsa_padding: @padding)

    {:ok, encrypted, []}
  end

  def encrypt(_, _), do: :encryption_error

  @spec private_key_to_public_key(rsa_private_key() | EncryptionKey.t()) :: rsa_public_key()
  def private_key_to_public_key(%EncryptionKey{
        encryption_strategy_module: __MODULE__,
        key: private_key
      }),
      do: private_key_to_public_key(private_key)

  def private_key_to_public_key(private_key)
      when is_tuple(private_key) and elem(private_key, 0) == :RSAPrivateKey and
             tuple_size(private_key) == 11 do
    public_modulus = private_key |> elem(2)
    public_exponent = private_key |> elem(3)
    {:RSAPublicKey, public_modulus, public_exponent}
  end

  @spec to_pem(EncryptionKey.t() | rsa_private_key() | rsa_public_key()) :: {:ok, pem()}
  def to_pem(%EncryptionKey{key: key}),
    do: to_pem(key)

  def to_pem(key)
      when is_tuple(key) and (elem(key, 0) == :RSAPrivateKey or elem(key, 0) == :RSAPublicKey) do
    pem_entry = key |> elem(0) |> :public_key.pem_entry_encode(key)
    {:ok, :public_key.pem_encode([pem_entry])}
  end

  @spec from_pem(pem) :: {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}
  def from_pem(pem) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [pem_entry] ->
        encryption_key = %EncryptionKey{
          encryption_strategy_module: __MODULE__,
          key: :public_key.pem_entry_decode(pem_entry)
        }

        {:ok, encryption_key}

      _ ->
        {:error, :invalid_encryption_key}
    end
  end

  @spec decrypt(EncryptedData.t(), EncryptionKey.t()) :: {:ok, binary} | :decryption_error
  @impl EncryptionStrategy
  def decrypt(%EncryptedData{encrypted_data: encrypted_data}, %EncryptionKey{key: private_key})
      when is_binary(encrypted_data) do
    decrypted = :public_key.decrypt_private(encrypted_data, private_key, rsa_padding: @padding)
    {:ok, decrypted}
  rescue
    ErlangError -> :decryption_error
  end

  def decrypt(_, _), do: :decryption_error

  @spec sign(binary, rsa_private_key() | EncryptionKey.t() | pem()) ::
          RsaSignature.t() | {:error, :invalid_encryption_key}
  def sign(data, maybe_pem) when is_binary(data) and is_binary(maybe_pem) do
    with {:ok, encryption_key} <- from_pem(maybe_pem) do
      sign(data, encryption_key)
    end
  end

  def sign(data, %EncryptionKey{encryption_strategy_module: __MODULE__, key: private_key}),
    do: sign(data, private_key)

  def sign(data, private_key_erlang_tuple)
      when is_binary(data) and is_tuple(private_key_erlang_tuple) and
             elem(private_key_erlang_tuple, 0) == :RSAPrivateKey and
             tuple_size(private_key_erlang_tuple) == 11 do
    signature = :public_key.sign(data, :sha256, private_key_erlang_tuple)
    %RsaSignature{signature: signature, data: data}
  end

  @spec verify(RsaSignature.t(), rsa_public_key | rsa_private_key | EncryptionKey.t() | pem) ::
          boolean() | {:error, :invalid_encryption_key}
  def verify(%RsaSignature{data: data, signature: signature}, public_key),
    do: verify(data, signature, public_key)

  @spec verify(binary, binary, rsa_public_key | rsa_private_key | EncryptionKey.t() | pem) ::
          boolean() | {:error, :invalid_encryption_key}

  defp verify(data, signature, maybe_pem) when is_binary(maybe_pem) do
    with {:ok, encryption_key} <- from_pem(maybe_pem),
         do: verify(data, signature, encryption_key)
  end

  defp verify(data, signature, %EncryptionKey{
         encryption_strategy_module: __MODULE__,
         key: private_key
       }),
       do: verify(data, signature, private_key)

  defp verify(data, signature, private_key)
       when is_tuple(private_key) and elem(private_key, 0) == :RSAPrivateKey do
    public_key = private_key_to_public_key(private_key)
    verify(data, signature, public_key)
  end

  defp verify(data, signature, public_key)
       when is_binary(data) and is_binary(signature) and is_tuple(public_key) and
              elem(public_key, 0) == :RSAPublicKey do
    :public_key.verify(data, :sha256, signature, public_key)
  end

  @spec build_encryption_key(any) :: {:ok, EncryptionKey.t()} | {:error, :invalid_encryption_key}
  @impl EncryptionStrategy
  def build_encryption_key(private_key_in_erlang_format)
      when is_tuple(private_key_in_erlang_format) and
             elem(private_key_in_erlang_format, 0) == :RSAPrivateKey and
             tuple_size(private_key_in_erlang_format) == 11 do
    {:ok, EncryptionKey.new(private_key_in_erlang_format, __MODULE__)}
  end

  def build_encryption_key(maybe_pem) when is_binary(maybe_pem),
    do: from_pem(maybe_pem)

  def build_encryption_key(_), do: {:error, :invalid_encryption_key}
end
