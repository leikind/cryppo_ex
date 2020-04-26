defmodule CryppoTest do
  use ExUnit.Case

  alias Cryppo.{EncryptedData, EncryptedDataWithDerivedKey, EncryptionKey, Rsa4096, RsaSignature}

  @all_encryption_strategies ["Rsa4096", "Aes256Gcm"]

  @plain_data "Hello world!"

  test "Cryppo.encryption_strategies" do
    assert Cryppo.encryption_strategies() == ["Aes256Gcm", "Rsa4096"]
  end

  test "Cryppo.derivation_strategies" do
    assert Cryppo.derivation_strategies() == ["Pbkdf2Hmac"]
  end

  test "Cryppo.generate_encryption_key" do
    for encryption_strategy <- @all_encryption_strategies do
      key = Cryppo.generate_encryption_key(encryption_strategy)
      assert key, "key exists"
      assert %EncryptionKey{} = key, "a key is an EncryptionKey struct"

      assert inspect(key) == "%Cryppo.EncryptionKey{ HIDDEN }",
             "the contents of the struct is invisible"
    end
  end

  test "try to generate a key for an invalid key generation strategy" do
    assert Cryppo.generate_encryption_key("i-dont-exist") ==
             {:unsupported_encryption_strategy, "i-dont-exist"}
  end

  describe "Encryption / decryption with a generated key" do
    test "Encryption / decryption using all available strategies" do
      for encryption_strategy <- @all_encryption_strategies do
        key = Cryppo.generate_encryption_key(encryption_strategy)

        encrypted_data = @plain_data |> Cryppo.encrypt(encryption_strategy, key)

        assert %EncryptedData{} = encrypted_data,
               "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

        {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

        assert decrypted_data == @plain_data,
               "decryption with #{encryption_strategy} is successful"
      end
    end

    test "generate an encryption key and encrypt in one go" do
      for encryption_strategy <- @all_encryption_strategies do
        {encrypted_data, key} = @plain_data |> Cryppo.encrypt(encryption_strategy)

        assert %EncryptedData{} = encrypted_data,
               "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

        {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

        assert decrypted_data == @plain_data,
               "decryption with #{encryption_strategy} is successful"
      end
    end

    test "Encryption / decryption using raw keys, not EncryptionKey structs" do
      for encryption_strategy <- ["Rsa4096", "Aes256Gcm"] do
        key = Cryppo.generate_encryption_key(encryption_strategy)
        raw_key = key.key

        encrypted_data = @plain_data |> Cryppo.encrypt(encryption_strategy, raw_key)

        assert %EncryptedData{} = encrypted_data,
               "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

        {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, raw_key)

        assert decrypted_data == @plain_data,
               "decryption with #{encryption_strategy} is successful"
      end
    end

    test "Encryption / decryption with Rsa4096 using a PEM" do
      encryption_strategy = "Rsa4096"
      key = Cryppo.generate_encryption_key(encryption_strategy)
      {:ok, pem} = Rsa4096.to_pem(key)

      encrypted_data = @plain_data |> Cryppo.encrypt(encryption_strategy, pem)

      assert %EncryptedData{} = encrypted_data,
             "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

      {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, pem)

      assert decrypted_data == @plain_data,
             "decryption with #{encryption_strategy} is successful"
    end

    test "decryption with Rsa4096 using an invalid PEM" do
      encryption_strategy = "Rsa4096"
      key = Cryppo.generate_encryption_key(encryption_strategy)
      {:ok, pem} = Rsa4096.to_pem(key)

      encrypted_data = @plain_data |> Cryppo.encrypt(encryption_strategy, pem)

      assert %EncryptedData{} = encrypted_data,
             "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

      assert Cryppo.decrypt(encrypted_data, "foobar") == {:error, :invalid_encryption_key}
    end

    test "encrypting with Rsa4096 using an invalid PEM" do
      assert Cryppo.encrypt(@plain_data, "Rsa4096", "foobar") == {:error, :invalid_encryption_key}
    end

    test "Decrypting using the wrong key of the same strategy" do
      for encryption_strategy <- @all_encryption_strategies do
        key = Cryppo.generate_encryption_key(encryption_strategy)
        wrong_key = Cryppo.generate_encryption_key(encryption_strategy)

        encrypted_data = @plain_data |> Cryppo.encrypt(encryption_strategy, key)

        assert %EncryptedData{} = encrypted_data,
               "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

        assert Cryppo.decrypt(encrypted_data, wrong_key) == :decryption_error,
               "decryption with (#{encryption_strategy}) with an incorrect key fails"
      end
    end

    test "trying to feed a Aes256Gcm key to a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = @plain_data |> Cryppo.encrypt("Rsa4096", key)

      wrong_key = Cryppo.generate_encryption_key("Aes256Gcm")

      assert Cryppo.decrypt(encrypted_data, wrong_key) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Aes256gcm, encryption_strategy: Cryppo.Rsa4096]}
    end

    test "trying to feed an Rsa4096 key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = @plain_data |> Cryppo.encrypt("Aes256Gcm", key)

      wrong_key = Cryppo.generate_encryption_key("Rsa4096")

      assert Cryppo.decrypt(encrypted_data, wrong_key) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Rsa4096, encryption_strategy: Cryppo.Aes256gcm]}
    end

    test "trying to feed a random string as a key to a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = @plain_data |> Cryppo.encrypt("Rsa4096", key)

      wrong_key = "foobar"

      assert Cryppo.decrypt(encrypted_data, wrong_key) == {:error, :invalid_encryption_key}
    end

    test "trying to feed a random string as a key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = @plain_data |> Cryppo.encrypt("Aes256Gcm", key)

      wrong_key = "foobar"

      assert Cryppo.decrypt(encrypted_data, wrong_key) == :decryption_error
    end

    test "trying to encrypt with Aes256Gcm using a Rsa4096 key" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")

      assert Cryppo.encrypt(@plain_data, "Rsa4096", key) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Aes256gcm, encryption_strategy: Cryppo.Rsa4096]}
    end

    test "trying to encrypt with Rsa4096 using a Aes256Gcm key" do
      key = Cryppo.generate_encryption_key("Rsa4096")

      assert Cryppo.encrypt(@plain_data, "Aes256Gcm", key) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Rsa4096, encryption_strategy: Cryppo.Aes256gcm]}
    end
  end

  test "Encryption / decryption with a derived key" do
    encrypted_data =
      @plain_data
      |> Cryppo.encrypt_with_derived_key(
        "Aes256Gcm",
        "Pbkdf2Hmac",
        "my passphrase"
      )

    assert(encrypted_data)

    assert %EncryptedDataWithDerivedKey{} = encrypted_data,
           "encrypted_data is a EncryptedDataWithDerivedKey struct"

    encrypted_data_without_key = %{
      encrypted_data
      | derived_key: %{encrypted_data.derived_key | encryption_key: nil}
    }

    assert encrypted_data_without_key.derived_key.encryption_key == nil,
           "encrypted_data struct contains no key"

    {:ok, decrypted, derived_key2} =
      Cryppo.decrypt_with_derived_key("my passphrase", encrypted_data)

    assert @plain_data == decrypted

    assert derived_key2.encryption_key, "key has been derived again"
  end

  test "Reusing a key already present in EncryptedDataWithDerivedKey" do
    encrypted_data =
      @plain_data
      |> Cryppo.encrypt_with_derived_key(
        "Aes256Gcm",
        "Pbkdf2Hmac",
        "my passphrase"
      )

    assert(encrypted_data)

    assert %EncryptedDataWithDerivedKey{} = encrypted_data,
           "encrypted_data is a EncryptedDataWithDerivedKey struct"

    {:ok, decrypted, derived_key2} =
      Cryppo.decrypt_with_derived_key("my passphrase", encrypted_data)

    assert @plain_data == decrypted

    assert derived_key2.encryption_key,
           "key has not been derived again, it is the same key used for encryption"
  end

  describe "RSA signatures" do
    test "sign data with a private key and then verify with the public key" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Cryppo.sign_with_private_key(@plain_data, private_key)

      assert %RsaSignature{} = rsa_signature
      assert rsa_signature.data == @plain_data
      assert is_binary(rsa_signature.signature)

      public_key = Cryppo.private_key_to_public_key(private_key)

      assert Cryppo.verify_rsa_signature(rsa_signature, public_key) == true
    end

    test "a different public key" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Cryppo.sign_with_private_key(@plain_data, private_key)

      wrong_public_key =
        "Rsa4096"
        |> Cryppo.generate_encryption_key()
        |> Cryppo.private_key_to_public_key()

      assert Cryppo.verify_rsa_signature(rsa_signature, wrong_public_key) == false
    end

    test "verify wrong data" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Cryppo.sign_with_private_key(@plain_data, private_key)

      public_key = Cryppo.private_key_to_public_key(private_key)

      rsa_signature_with_wrong_data = %{rsa_signature | data: "something else"}

      assert Cryppo.verify_rsa_signature(rsa_signature_with_wrong_data, public_key) == false
    end

    test "verify wrong signature" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Cryppo.sign_with_private_key(@plain_data, private_key)

      public_key = Cryppo.private_key_to_public_key(private_key)

      rsa_signature_with_wrong_signature = %{rsa_signature | signature: "notasignature"}

      assert Cryppo.verify_rsa_signature(rsa_signature_with_wrong_signature, public_key) == false
    end
  end
end
