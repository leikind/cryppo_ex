defmodule SerializationTest do
  use ExUnit.Case

  alias Cryppo.EncryptedDataWithDerivedKey

  @plain_data "Hello world!"

  # add all the tests from Ruby Cryppo here

  test "encrypt serialize, de-serialize, decrypt with aes_256_gcm" do
    strategy = "Aes256Gcm"
    key = Cryppo.generate_encryption_key(strategy)

    encrypted_data = Cryppo.encrypt(strategy, key, @plain_data)

    serialized = encrypted_data |> Cryppo.serialize()

    restored_encrypted_data = Cryppo.load(serialized)

    assert encrypted_data == restored_encrypted_data

    {:ok, decrypted_data} = Cryppo.decrypt(restored_encrypted_data, key)

    assert decrypted_data == @plain_data
  end

  test "encrypt with a derived key, serialize, load, encrypt with the derived key" do
    encrypted_data =
      Cryppo.encrypt_with_derived_key(
        "Aes256Gcm",
        "Pbkdf2Hmac",
        "my passphrase",
        @plain_data
      )

    assert %EncryptedDataWithDerivedKey{} = encrypted_data,
           "encrypted_data is a EncryptedDataWithDerivedKey struct"

    serialized = encrypted_data |> Cryppo.serialize()

    loaded_encrypted_data = Cryppo.load(serialized)

    {:ok, decrypted, _derived_key} =
      Cryppo.decrypt_with_derived_key("my passphrase", loaded_encrypted_data)

    assert decrypted == @plain_data
  end
end
