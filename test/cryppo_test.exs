defmodule CryppoTest do
  use ExUnit.Case

  alias Cryppo.{EncryptionKey, EncryptedData}

  @aes_encryption_strategies ["Aes256Gcm"]
  @all_encryption_strategies ["Rsa4096" | @aes_encryption_strategies]

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
    strategy = "Aes256Gcm"
    key = Cryppo.generate_encryption_key(strategy)
    plain_data = "some plain data"

    encrypted_data = Cryppo.encrypt(strategy, key, plain_data)
    assert %EncryptedData{} = encrypted_data

    {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

    assert decrypted_data == plain_data
  end

  # TODO write failure tests
  test "encryption/decryption rsa4096" do
    strategy = "Rsa4096"
    key = Cryppo.generate_encryption_key(strategy)
    plain_data = "some plain data"

    encrypted_data = Cryppo.encrypt(strategy, key, plain_data)

    assert %EncryptedData{} = encrypted_data

    {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

    assert decrypted_data == plain_data
  end

  # TODO compare with ruby cryppo
  test "encrypt serialize, de-serialize, decrypt with aes_256_gcm" do
    strategy = "Aes256Gcm"
    key = Cryppo.generate_encryption_key(strategy)
    plain_data = "some plain data"

    encrypted_data = Cryppo.encrypt(strategy, key, plain_data)

    encrypted_data |> Cryppo.serialize() |> IO.inspect()

    # {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

    # assert decrypted_data == plain_data
  end
end
