defmodule SerializationTest do
  use ExUnit.Case

  alias Cryppo.{EncryptedData, EncryptedDataWithDerivedKey, Rsa4096}

  @plain_data "Hello world!"

  describe "with a generated key" do
    test "serializes the data" do
      strategy = "Aes256Gcm"
      key = Cryppo.generate_encryption_key(strategy)

      encrypted_data = @plain_data |> Cryppo.encrypt(strategy, key)

      serialized = Cryppo.serialize(encrypted_data)
      assert is_binary(serialized)

      assert [p1, p2, p3] = String.split(serialized, ".")

      assert p1 == strategy

      {:ok, encrypted_data2} = Base.url_decode64(p2)
      assert encrypted_data2 == encrypted_data.encrypted_data

      assert p3
    end

    test "encrypt serialize, de-serialize, decrypt with aes_256_gcm" do
      strategy = "Aes256Gcm"
      key = Cryppo.generate_encryption_key(strategy)

      encrypted_data = @plain_data |> Cryppo.encrypt(strategy, key)
      assert %EncryptedData{} = encrypted_data

      serialized = Cryppo.serialize(encrypted_data)

      restored_encrypted_data = Cryppo.load(serialized)
      assert %EncryptedData{} = restored_encrypted_data

      assert encrypted_data == restored_encrypted_data

      {:ok, decrypted_data} = Cryppo.decrypt(restored_encrypted_data, key)

      assert decrypted_data == @plain_data
    end
  end

  describe "with a derived key" do
    test "serializes the data" do
      encryption_strategy = "Aes256Gcm"
      derivation_strategy_name = "Pbkdf2Hmac"

      encrypted_data_with_derived_key =
        @plain_data
        |> Cryppo.encrypt_with_derived_key(
          encryption_strategy,
          derivation_strategy_name,
          "my passphrase"
        )

      serialized = Cryppo.serialize(encrypted_data_with_derived_key)

      assert is_binary(serialized)

      assert [p1, p2, p3, p4, p5] = String.split(serialized, ".")

      assert p1 == encryption_strategy

      {:ok, encrypted_data2} = Base.url_decode64(p2)
      assert encrypted_data2 == encrypted_data_with_derived_key.encrypted_data.encrypted_data

      assert p3

      assert p4 == derivation_strategy_name

      assert p5
    end

    test "loads the data" do
      encrypted_data =
        @plain_data
        |> Cryppo.encrypt_with_derived_key(
          "Aes256Gcm",
          "Pbkdf2Hmac",
          "my passphrase"
        )

      assert %EncryptedDataWithDerivedKey{} = encrypted_data,
             "encrypted_data is a EncryptedDataWithDerivedKey struct"

      serialized = Cryppo.serialize(encrypted_data)

      loaded_encrypted_data = Cryppo.load(serialized)

      assert %EncryptedDataWithDerivedKey{} = loaded_encrypted_data,
             "loaded_encrypted_data is a EncryptedDataWithDerivedKey struct"

      assert loaded_encrypted_data.derived_key.key_derivation_strategy ==
               encrypted_data.derived_key.key_derivation_strategy

      assert loaded_encrypted_data.derived_key.salt ==
               encrypted_data.derived_key.salt

      assert loaded_encrypted_data.derived_key.iter ==
               encrypted_data.derived_key.iter

      assert loaded_encrypted_data.derived_key.length ==
               encrypted_data.derived_key.length

      assert loaded_encrypted_data.derived_key.hash ==
               encrypted_data.derived_key.hash

      assert loaded_encrypted_data.derived_key.encryption_key !=
               encrypted_data.derived_key.encryption_key,
             "the encryption key is of course not serialized"

      assert loaded_encrypted_data.derived_key.encryption_key == nil,
             "once loded, the encryption key is nil"

      assert loaded_encrypted_data.encrypted_data.encrypted_data ==
               encrypted_data.encrypted_data.encrypted_data

      assert loaded_encrypted_data.encrypted_data.encryption_artefacts ==
               encrypted_data.encrypted_data.encryption_artefacts

      assert loaded_encrypted_data.encrypted_data.encryption_strategy_module ==
               encrypted_data.encrypted_data.encryption_strategy_module
    end

    test "encrypt with a derived key, serialize, load, encrypt with the derived key" do
      encrypted_data =
        @plain_data
        |> Cryppo.encrypt_with_derived_key(
          "Aes256Gcm",
          "Pbkdf2Hmac",
          "my passphrase"
        )

      assert %EncryptedDataWithDerivedKey{} = encrypted_data,
             "encrypted_data is a EncryptedDataWithDerivedKey struct"

      {:ok, decrypted, _derived_key} =
        encrypted_data
        |> Cryppo.serialize()
        |> Cryppo.load()
        |> Cryppo.decrypt_with_derived_key("my passphrase")

      assert decrypted == @plain_data
    end
  end

  describe "signing and verification" do
    test "serializes the data" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      serialized = Cryppo.serialize(rsa_signature)

      assert [p1, p2, p3, p4] = String.split(serialized, ".")

      assert p1 == "Sign"
      assert p2 == "Rsa4096"

      {:ok, p3} = Base.url_decode64(p3)
      {:ok, p4} = Base.url_decode64(p4)

      assert p3 == rsa_signature.signature
      assert p4 == rsa_signature.data
    end

    test "sign, serialize, de-serialize, and verify" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      serialized = Cryppo.serialize(rsa_signature)

      restored_rsa_signature = Cryppo.load(serialized)
      assert restored_rsa_signature == rsa_signature

      public_key = Rsa4096.private_key_to_public_key(private_key)
      assert Rsa4096.verify(restored_rsa_signature, public_key) == true
    end
  end
end
