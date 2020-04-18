defmodule CryppoTest do
  use ExUnit.Case

  alias Cryppo.{EncryptionKey, EncryptedData}

  @aes_encryption_strategies ["Aes256Gcm"]
  @all_encryption_strategies ["Rsa4096" | @aes_encryption_strategies]

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

  test "try to generate a key for a an invalid key generation strategy" do
    assert Cryppo.generate_encryption_key("i-dont-exist") ==
             {:unsupported_encryption_strategy, "i-dont-exist"}
  end

  test "Encryption / decryption using all available strategies" do
    @plain_data = "Hello world!"

    for encryption_strategy <- @all_encryption_strategies do
      key = Cryppo.generate_encryption_key(encryption_strategy)

      encrypted_data = Cryppo.encrypt(encryption_strategy, key, @plain_data)

      assert %EncryptedData{} = encrypted_data,
             "the result of Cryppo.encrypt(#{encryption_strategy}) is an EncryptedData struct"

      {:ok, decrypted_data} = Cryppo.decrypt(encrypted_data, key)

      assert decrypted_data == @plain_data, "decryption with #{encryption_strategy} is successful"
    end
  end

  describe "breaking stuff" do
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

      assert Cryppo.decrypt(encrypted_data, wrong_key) == :decryption_error
    end

    test "trying to feed an Rsa4096 key to a Aes256Gcm decryption" do
      key = Cryppo.generate_encryption_key("Aes256Gcm")
      encrypted_data = Cryppo.encrypt("Aes256Gcm", key, @plain_data)

      wrong_key = Cryppo.generate_encryption_key("Rsa4096")

      assert Cryppo.decrypt(encrypted_data, wrong_key) == :decryption_error
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

      assert Cryppo.encrypt("Rsa4096", key, @plain_data) == :encryption_error
    end

    test "trying to encrypt with Rsa4096 using a Aes256Gcm key" do
      key = Cryppo.generate_encryption_key("Rsa4096")
      assert Cryppo.encrypt("Aes256Gcm", key, @plain_data) == :encryption_error
    end
  end
end
