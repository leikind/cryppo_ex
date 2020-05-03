defmodule Cryppo.Rsa4096 do
  @moduledoc """
  Encryption strategy RSA with 4096-bit keys and some RSA-specific functions

  For encryption and decryption please use functions in module `Cryppo`.
  This module also contains logic for PEMs, singing and verification.

  """

  # Key length 4096
  # Exponents: 65537
  # Padding: rsa_pkcs1_oaep_padding

  @typedoc """
  Erlang type for RSA private keys

  The native Erlang type for RSA private keys in module [`public_key`](https://erlang.org/doc/man/public_key.html)
  are Erlang records visible from Elixir as tuples with 11 terms the first term being atom `:RSAPrivateKey`
  """
  @type rsa_private_key() ::
          {:RSAPrivateKey, integer, integer, integer, integer, integer, integer, integer, integer,
           integer, any}

  @typedoc """
  Erlang type for RSA public keys

  The native Erlang type for RSA public keys in module [`public_key`](https://erlang.org/doc/man/public_key.html)
  are Erlang records visible from Elixir as tuples with 3 terms the first term being atom `:RSAPublicKey`
  """
  @type rsa_public_key() :: {:RSAPublicKey, integer, integer}

  @typedoc """
  RSA keys in PEM format
  """
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

  @doc """
  Extracts a public key from a private key

  Extracts a public key from a `Cryppo.EncryptionKey` struct with an RSA private key or from an
  RSA private key in the native Erlang type `t:rsa_private_key/0`

  ## Examples

  With a `Cryppo.EncryptionKey` struct:

      iex> public_key = "Rsa4096"
      ...> |> Cryppo.generate_encryption_key()
      ...> |> Cryppo.Rsa4096.private_key_to_public_key()
      ...> elem(public_key, 0)
      :RSAPublicKey

  With a native Erlang key:

      iex> public_key = {:rsa, 4_096, 65_537}
      ...> |> :public_key.generate_key()
      ...> |> Cryppo.Rsa4096.private_key_to_public_key()
      ...> elem(public_key, 0)
      :RSAPublicKey

  """

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

  @doc """
  Converts an RSA key to PEM format.

  Can convert

  * a `Cryppo.EncryptionKey` struct
  * a public key as native Erlang type `t:rsa_public_key/0`
  * a private key as native Erlang type `t:rsa_private_key/0`


  ## Examples

  With a `Cryppo.EncryptionKey` struct

      iex> "Rsa4096" |> Cryppo.generate_encryption_key() |> Cryppo.Rsa4096.to_pem()


  With a public key as native Erlang type `t:rsa_public_key/0`

      iex> "Rsa4096"
      ...> |> Cryppo.generate_encryption_key()
      ...> |> Cryppo.Rsa4096.private_key_to_public_key()
      ...> |> Cryppo.Rsa4096.to_pem()

  With a private key as native Erlang type `t:rsa_private_key/0`

      iex> encryption_key = Cryppo.generate_encryption_key("Rsa4096")
      iex> Cryppo.Rsa4096.to_pem(encryption_key.key)

  """

  @spec to_pem(EncryptionKey.t() | rsa_private_key() | rsa_public_key()) :: {:ok, pem()}
  def to_pem(%EncryptionKey{key: key}),
    do: to_pem(key)

  def to_pem(key)
      when is_tuple(key) and (elem(key, 0) == :RSAPrivateKey or elem(key, 0) == :RSAPublicKey) do
    pem_entry = key |> elem(0) |> :public_key.pem_entry_encode(key)
    {:ok, :public_key.pem_encode([pem_entry])}
  end

  @doc """
  Loads and initializes a `Cryppo.EncryptionKey` struct from a string with a PEM.

  ## Examples

      iex> pem = "-----BEGIN RSA PRIVATE KEY-----\\n" <>
      ...>       "MIICWwIBAAKBgQDKCUh7F4p5btzcSLBaToHvD3rCZX4fMaDtjkN5TwmC3/6iQzD5\\n" <>
      ...>       "tn396BzDTdQ16HuuZ+eN+KQSa1QWr2h1DB13nVP+moeyLVC8BShiM3NBRn77r7Lr\\n" <>
      ...>       "sWooM3mwnSvMPWWnBj1c+0tbO7zfur5wQdzBl66HrHgHt+Bz6f+dDj+aVwIDAQAB\\n" <>
      ...>       "AoGAMHh3rihgrW9+h07dGF1baOoyzm6hCoTSkguefn0K0B5DLdSm7FHu+jp0pBqI\\n" <>
      ...>       "/gHvolEFSZdMbarYOrUMf4BPlRSarCjjxf/beV4Pj/UQrCkDmNBBVJp33Sy8HEdb\\n" <>
      ...>       "Wrzk+k8NcAS1UR4R6EW9JrUz0mMwX6CsvG2zZMbpS/Q9KXkCQQDwmCXjOTPQ+bxW\\n" <>
      ...>       "K4gndHnXD5QkKNcTdFq64ef23R6AY0XEGkiRLDXZZA09hDIACgSSfk1Qbo0SJSvU\\n" <>
      ...>       "TAR8A6clAkEA1vkWJ5qUo+xuIZB+2604LRco1GYAj5/fZ2kvUMjbOdCFgFaDVzJY\\n" <>
      ...>       "X2pzLkk7RZNgPvXcRAgX7FlWmm4jwZzQywJARrHeSCMRx7DqF0PZUQaXmorYU7uw\\n" <>
      ...>       "XuYMluc0WsRkZwNEh7fVZNrhw8vzXAUREBPhfg4gt6aUSyWi+FGR68LDBQJAC55O\\n" <>
      ...>       "ujk6i1l94kaC9LB59sXnqQMSSLDlTBt9OSqB3rAMZxFF6/KGoDGKpBfFIk+CxiRX\\n" <>
      ...>       "kT22vUleyt3lBNPK3QJAEr56asvREcIDFkbs7Ebjev4U1PL58w78ipp49Ti5FiwH\\n" <>
      ...>       "vR9vuGcUcIDcWKOl05t4D35F5A/DskP6dGYA1cuWNg==\\n" <>
      ...>       "-----END RSA PRIVATE KEY-----\\n\\n"
      ...> {:ok, encryption_key} = Cryppo.Rsa4096.from_pem(pem)
  """

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

  @doc """
  Signs data with a private key

  """
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

  @doc """
  Verifies an RSA signature with a public key

  """

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
