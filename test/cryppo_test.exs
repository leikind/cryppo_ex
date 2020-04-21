defmodule CryppoTest do
  use ExUnit.Case

  alias Cryppo.{EncryptedData, EncryptedDataWithDerivedKey, EncryptionKey}

  @all_encryption_strategies ["Rsa4096", "Aes256Gcm"]

  @plain_data "Hello world!"

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
      @plain_data = "Hello world!"

      for encryption_strategy <- @all_encryption_strategies do
        key = Cryppo.generate_encryption_key(encryption_strategy)

        encrypted_data = Cryppo.encrypt(encryption_strategy, key, @plain_data)

        assert %EncryptedData{} = encrypted_data,
               "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

        {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

        assert decrypted_data == @plain_data,
               "decryption with #{encryption_strategy} is successful"
      end
    end

    test "Decrypting using the wrong key of the same strategy" do
      @plain_data = "Hello world!"

      for encryption_strategy <- @all_encryption_strategies do
        key = Cryppo.generate_encryption_key(encryption_strategy)
        wrong_key = Cryppo.generate_encryption_key(encryption_strategy)

        encrypted_data = Cryppo.encrypt(encryption_strategy, key, @plain_data)

        assert %EncryptedData{} = encrypted_data,
               "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

        assert Cryppo.decrypt(encrypted_data, wrong_key) == :decryption_error,
               "decryption with (#{encryption_strategy}) with an incorrect key fails"
      end
    end

    test "trying to feed a Aes256Gcm key to a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = Cryppo.encrypt("Rsa4096", key, @plain_data)

      wrong_key = Cryppo.generate_encryption_key("Aes256Gcm")

      assert Cryppo.decrypt(encrypted_data, wrong_key) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Aes256gcm, encryption_strategy: Cryppo.Rsa4096]}
    end

    test "trying to feed an Rsa4096 key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = Cryppo.encrypt("Aes256Gcm", key, @plain_data)

      wrong_key = Cryppo.generate_encryption_key("Rsa4096")

      assert Cryppo.decrypt(encrypted_data, wrong_key) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Rsa4096, encryption_strategy: Cryppo.Aes256gcm]}
    end

    test "trying to feed a random string as a key to a Rsa4096 decryption" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      encrypted_data = Cryppo.encrypt("Rsa4096", key, @plain_data)

      wrong_key = "foobar"

      assert_raise FunctionClauseError, fn ->
        assert Cryppo.decrypt(encrypted_data, wrong_key)
      end
    end

    test "trying to feed a random string as a key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = Cryppo.encrypt("Aes256Gcm", key, @plain_data)

      wrong_key = "foobar"

      assert_raise FunctionClauseError, fn ->
        assert Cryppo.decrypt(encrypted_data, wrong_key)
      end
    end

    test "trying to encrypt with Aes256Gcm using a Rsa4096 key" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")

      assert Cryppo.encrypt("Rsa4096", key, @plain_data) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Aes256gcm, encryption_strategy: Cryppo.Rsa4096]}
    end

    test "trying to encrypt with Rsa4096 using a Aes256Gcm key" do
      key = Cryppo.generate_encryption_key("Rsa4096")

      assert Cryppo.encrypt("Aes256Gcm", key, @plain_data) ==
               {:incompatible_key,
                [submitted_key_strategy: Cryppo.Rsa4096, encryption_strategy: Cryppo.Aes256gcm]}
    end
  end

  test "Encryption / decryption with a derived key" do
    encrypted_data =
      Cryppo.encrypt_with_derived_key(
        "Aes256Gcm",
        "Pbkdf2Hmac",
        "my passphrase",
        @plain_data
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
      Cryppo.encrypt_with_derived_key(
        "Aes256Gcm",
        "Pbkdf2Hmac",
        "my passphrase",
        @plain_data
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
    # TODO
  end
end
