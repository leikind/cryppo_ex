defmodule Rsa4096Test do
  use ExUnit.Case

  alias Cryppo.{Rsa4096, RsaSignature}

  doctest Rsa4096

  @plain_data "Hello world!"

  test "to_pem and back from_pem" do
    key = Cryppo.generate_encryption_key("Rsa4096")

    {:ok, pem} = Rsa4096.to_pem(key)
    {:ok, restored_key} = Rsa4096.from_pem(pem)

    assert restored_key.encryption_strategy_module == key.encryption_strategy_module
    assert restored_key.key == key.key
  end

  test "to_pem using the erlang tuple and back from_pem" do
    key = Cryppo.generate_encryption_key("Rsa4096")
    erlang_private_key_tuple = key.key

    {:ok, pem} = Rsa4096.to_pem(erlang_private_key_tuple)
    {:ok, restored_key} = Rsa4096.from_pem(pem)

    assert restored_key.encryption_strategy_module == key.encryption_strategy_module
    assert restored_key.key == key.key
  end

  test "different ways to decrypt" do
    original_key = Cryppo.generate_encryption_key("Rsa4096")

    encrypted_data = "this is love!" |> Cryppo.encrypt("Rsa4096", original_key)

    {:ok, pem} = Rsa4096.to_pem(original_key)
    {:ok, key_restored_from_pem} = Rsa4096.from_pem(pem)

    assert Cryppo.decrypt(encrypted_data, original_key) == {:ok, "this is love!"}
    assert Cryppo.decrypt(encrypted_data, key_restored_from_pem) == {:ok, "this is love!"}
    assert Cryppo.decrypt(encrypted_data, pem) == {:ok, "this is love!"}
  end

  describe "RSA signatures" do
    test "signing is restricted to 512 bytes" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      to_sign = 1..512 |> Enum.reduce("", fn _, acc -> "a" <> acc end)

      assert %Cryppo.RsaSignature{} = Rsa4096.sign(to_sign, private_key)

      to_sign = to_sign <> "b"

      assert Rsa4096.sign(to_sign, private_key) == {:error, "cannot sign more than 512 bytes"}
    end

    test "sign data with a private key (a EncryptionKey struct) and then verify with the public key" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      assert %RsaSignature{} = rsa_signature
      assert rsa_signature.data == @plain_data
      assert is_binary(rsa_signature.signature)

      public_key = Rsa4096.private_key_to_public_key(private_key)

      assert Rsa4096.verify(rsa_signature, public_key) == true
    end

    test "sign data with a private key (an erlang tuple) and then verify with the public key" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      private_key_as_erlang_tuple = private_key.key

      rsa_signature = Rsa4096.sign(@plain_data, private_key_as_erlang_tuple)

      assert %RsaSignature{} = rsa_signature
      assert rsa_signature.data == @plain_data
      assert is_binary(rsa_signature.signature)

      public_key = Rsa4096.private_key_to_public_key(private_key)

      assert Rsa4096.verify(rsa_signature, public_key) == true
    end

    test "sign data with a private key (as a PEM) and then verify with the public key" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      {:ok, pem} = Rsa4096.to_pem(private_key)

      rsa_signature = Rsa4096.sign(@plain_data, pem)

      assert %RsaSignature{} = rsa_signature
      assert rsa_signature.data == @plain_data
      assert is_binary(rsa_signature.signature)

      public_key = Rsa4096.private_key_to_public_key(private_key)

      assert Rsa4096.verify(rsa_signature, public_key) == true
    end

    test "sign data with a private key and then verify with the private key in the Erlang format" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      private_key_tuple = private_key.key

      assert Rsa4096.verify(rsa_signature, private_key_tuple) == true
    end

    test "sign data with a private key and then verify with the private key as an EncryptionKey" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      assert Rsa4096.verify(rsa_signature, private_key) == true
    end

    test "sign data with a private key and then verify with the private key as a PEM" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      {:ok, pem} = Rsa4096.to_pem(private_key)

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      assert Rsa4096.verify(rsa_signature, pem) == true
    end

    test "sign data with a private key and then verify with the public key as a PEM" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      {:ok, pem} = private_key |> Rsa4096.private_key_to_public_key() |> Rsa4096.to_pem()

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      assert Rsa4096.verify(rsa_signature, pem) == true
    end

    test "verify with a different public key" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      wrong_public_key =
        "Rsa4096"
        |> Cryppo.generate_encryption_key()
        |> Rsa4096.private_key_to_public_key()

      assert Rsa4096.verify(rsa_signature, wrong_public_key) == false
    end

    test "verify wrong data" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      public_key = Rsa4096.private_key_to_public_key(private_key)

      rsa_signature_with_wrong_data = %{rsa_signature | data: "something else"}

      assert Rsa4096.verify(rsa_signature_with_wrong_data, public_key) == false
    end

    test "verify wrong signature" do
      private_key = Cryppo.generate_encryption_key("Rsa4096")

      rsa_signature = Rsa4096.sign(@plain_data, private_key)

      public_key = Rsa4096.private_key_to_public_key(private_key)

      rsa_signature_with_wrong_signature = %{rsa_signature | signature: "notasignature"}

      assert Rsa4096.verify(rsa_signature_with_wrong_signature, public_key) == false
    end
  end

  test "trying to encrypt more than Rsa4096 + rsa_pkcs1_oaep_padding can handle" do
    key = Cryppo.generate_encryption_key("Rsa4096")

    data = 1..1000 |> Enum.map_join("", fn _ -> "a" end)

    assert Cryppo.encrypt(data, "Rsa4096", key) ==
             {:encryption_error,
              "the input data to encrypt is likely bigger than Rsa4096 + rsa_pkcs1_oaep_padding can handle"}
  end
end
