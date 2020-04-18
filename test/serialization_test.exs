defmodule SerializationTest do
  use ExUnit.Case

  test "encrypt serialize, de-serialize, decrypt with aes_256_gcm" do
    strategy = "Aes256Gcm"
    key = Cryppo.generate_encryption_key(strategy)
    plain_data = "Hello world!"

    encrypted_data = Cryppo.encrypt(strategy, key, plain_data)

    serialized = encrypted_data |> Cryppo.serialize()

    restored_encrypted_data = Cryppo.load(serialized)

    assert encrypted_data == restored_encrypted_data

    {:ok, decrypted_data} = Cryppo.decrypt(restored_encrypted_data, key)

    assert decrypted_data == plain_data
  end
end
