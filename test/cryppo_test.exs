defmodule CryppoTest do
  use ExUnit.Case

  alias Cryppo.{EncryptionKey, EncryptedData}

  @aes_encryption_strategies [:aes_256_gcm]
  @all_encryption_strategies [:rsa_4096 | @aes_encryption_strategies]

  test "generation of encryption keys" do
    for encryption_strategy <- @all_encryption_strategies do
      key = Cryppo.generate_encryption_key(encryption_strategy)
      assert key, "key exists"
      assert %EncryptionKey{} = key, "a key is an EncryptionKey struct"

      assert inspect(key) == "%Cryppo.EncryptionKey{ HIDDEN }",
             "the contents of the struct is invisible"
    end
  end

  # TODO write failure tests
  test "encryption/decryption aes_256_gcm" do
    strategy = :aes_256_gcm
    key = Cryppo.generate_encryption_key(strategy)
    plain_data = "some plain data"

    encrypted_data = Cryppo.encrypt(strategy, key, plain_data)
    assert %EncryptedData{} = encrypted_data

    {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

    assert decrypted_data == plain_data
  end

  # TODO write failure tests
  test "encryption/decryption rsa4096" do
    strategy = :rsa_4096
    key = Cryppo.generate_encryption_key(strategy)
    plain_data = "some plain data"

    encrypted_data = Cryppo.encrypt(strategy, key, plain_data)

    assert %EncryptedData{} = encrypted_data

    {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

    assert decrypted_data == plain_data
  end
end
