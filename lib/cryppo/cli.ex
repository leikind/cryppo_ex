defmodule Cryppo.Cli do
  @moduledoc false

  use ExCLI.DSL, escript: true

  alias Cryppo.{
    EncryptedData,
    EncryptedDataWithDerivedKey,
    EncryptionKey,
    EncryptionKey,
    Rsa4096,
    RsaSignature
  }

  name("cryppo")
  description("cryppo CLI")

  command :help do
    description("Display help for a cryppo command")

    argument(:cmd)

    run context do
      case context[:cmd] do
        "genkey" -> genkey_help()
        "genkeypair" -> genkeypair_help()
        "sign" -> sign_help()
        "verify" -> verify_help()
        "encrypt" -> encrypt_help()
        "decrypt" -> decrypt_help()
        "encrypt-der" -> encrypt_der_help()
        "decrypt-der" -> decrypt_der_help()
        unknown_cmd -> IO.puts("Unknown command: #{unknown_cmd}")
      end
    end
  end

  command :genkey do
    description("Generate an encryption key for a symmetric encryption strategy")

    option(:help, type: :boolean, aliases: [:h])
    option(:strategy, default: "Aes256Gcm", aliases: [:s])

    run context do
      if context[:help],
        do: genkey_help(),
        else: genkey(context[:strategy])
    end
  end

  defp genkey_help do
    IO.puts("""
    Generate an encryption key for a symmetric encryption strategy - printed as base64 encoded

    USAGE
      cryppo genkey -s [ENCRYPTION_STRATEGY]

    OPTIONS
      -s, --strategy=strategy  encryption strategy (defaults to Aes256Gcm)

    EXAMPLES
      cryppo genkey
      cryppo genkey --strategy=Aes256Gcm
    """)
  end

  command :genkeypair do
    description("Generate a new RSA key pair, writing the private and public keys to files")

    option(:privateKeyOut, aliases: [:p])
    option(:publicKeyOut, aliases: [:P])

    run context do
      if context[:privateKeyOut] && context[:publicKeyOut] do
        genkeypair(context[:privateKeyOut], context[:publicKeyOut])
      else
        genkeypair_help()
      end
    end
  end

  defp genkeypair_help do
    IO.puts("""
    Generate a new RSA key pair, writing the private and public keys to files.

    USAGE
      cryppo genkeypair -p [PRIVATE_KEY_FILE] -P [PUBLIC_KEY_FILE]

    OPTIONS
      -p, --privateKeyOut=privateKeyOut  (required) Private key output path
      -P, --publicKeyOut=publicKeyOut    (required) Public key output path

    EXAMPLE
      cryppo genkeypair -p private.pem -P public.pem
    """)
  end

  command :sign do
    description("Sign a file with an RSA private key and write the signed contents to a new file")

    option(:privateKeyFile, aliases: [:p])

    argument(:file_to_sign)
    argument(:destination)

    run context do
      if context[:privateKeyFile] && context[:file_to_sign] && context[:destination] do
        sign(context[:privateKeyFile], context[:file_to_sign], context[:destination])
      else
        sign_help()
      end
    end
  end

  defp sign_help do
    IO.puts("""
    USAGE
    cryppo sign -p [PRIVATE_KEY_FILE] FILE DESTINATION

    ARGUMENTS
      FILE         File to sign
      DESTINATION  file to write the resulting signed content to

    OPTIONS
      -p, --privateKeyFile=privateKeyFile  (required) path to the private key file

    EXAMPLE
      cryppo sign -p private.pem my_file.txt my_file.signed.txt
    """)
  end

  command :verify do
    description("Verify an RSA signed file and write the contents to another file")

    option(:publicKeyFile, aliases: [:P])

    argument(:file_to_verify)
    argument(:destination)

    run context do
      if context[:publicKeyFile] && context[:file_to_verify] && context[:destination] do
        verify(context[:publicKeyFile], context[:file_to_verify], context[:destination])
      else
        verify_help()
      end
    end
  end

  defp verify_help do
    IO.puts("""
    USAGE
    cryppo verify -P [PUBLIC_KEY_FILE] FILE DESTINATION

    ARGUMENTS
      FILE         Signed file contents to verify
      DESTINATION  File to write the resulting verified content to

    OPTIONS
      -P, --publicKeyFile=publicKeyFile  (required) path to the public key file

    EXAMPLE
      cryppo verify -P public.pem my_file.signed.txt my_file.txt
    """)
  end

  command :encrypt do
    description("Encrypt a serialized encrypted value")

    option(:publicKeyFile, aliases: [:P])
    option(:key, aliases: [:k])
    option(:strategy, aliases: [:s])
    option(:value, aliases: [:v])

    run context do
      public_key_file = context[:publicKeyFile]
      key = context[:key]
      strategy = context[:strategy]
      data = context[:value]

      cond do
        data == nil ->
          encrypt_help()

        public_key_file && key ->
          IO.puts(:stderr, "Either `key` or `publicKeyFile` must be present!\n")
          encrypt_help()

        strategy && public_key_file ->
          IO.puts(:stderr, "Option `strategy` must only be used with `key`!\n")
          encrypt_help()

        key == nil && public_key_file == nil ->
          encrypt_help()

        true ->
          if key do
            strategy = if strategy, do: strategy, else: "Aes256Gcm"

            encrypt(data, key, strategy)
          else
            if File.exists?(public_key_file),
              do: encrypt(data, public_key_file),
              else: IO.puts(:stderr, "File #{public_key_file} does not exist")
          end
      end
    end
  end

  defp encrypt_help do
    IO.puts("""
    USAGE
    cryppo encrypt -v [DATA] -k [KEY] -s [ENCRYPTION_STRATEGY]
    cryppo encrypt -v [DATA] -P [PUBLIC_KEY_FILE]

    OPTIONS
      -v, --value=value                  (required) value to encrypt
      -s, --strategy=strategy            encryption strategy (defaults to Aes256Gcm)
      -k, --key=key                      base64 encoded data encryption key
      -P, --publicKeyFile=publicKeyFile  public key file (if encrypting with RSA)

    EXAMPLES
      encrypt -v "hello world" -k vm8CjugMda2zdjsI9W25nH-CY-84DDYoBxTFLwfKLDk= -s Aes256Gcm
      encrypt -v "hello world" -P public.pem
    """)
  end

  command :decrypt do
    description("Decrypt a serialized encrypted value")

    option(:strategy, aliases: [:s])
    option(:key, aliases: [:k])
    option(:privateKeyFile, aliases: [:p])
    option(:encrypted, aliases: [:e])

    run context do
      private_key_file = context[:privateKeyFile]
      key = context[:key]
      strategy = context[:strategy]
      data = context[:encrypted]

      cond do
        data == nil ->
          decrypt_help()

        private_key_file && key ->
          IO.puts(:stderr, "Either `key` or `privateKeyFile` must be present!\n")
          encrypt_help()

        strategy && private_key_file ->
          IO.puts(:stderr, "Option `strategy` must only be used with `key`!\n")
          encrypt_help()

        key == nil && private_key_file == nil ->
          encrypt_help()

        true ->
          if key do
            strategy = if strategy, do: strategy, else: "Aes256Gcm"
            decrypt(data, key, strategy)
          else
            if File.exists?(private_key_file),
              do: decrypt(data, private_key_file),
              else: IO.puts(:stderr, "File #{private_key_file} does not exist")
          end
      end
    end
  end

  defp decrypt_help do
    IO.puts("""
    USAGE
      cryppo decrypt -s [ENCRYPTED_DATA] -k [KEY] -s [ENCRYPTION_STRATEGY]
      cryppo decrypt -s [ENCRYPTED_DATA] -p [PRIVATE_KEY_FILE]

    OPTIONS
      -s, --strategy=strategy              encryption strategy (defaults to Aes256Gcm)
      -k, --key=key                        base64 encoded data encryption key
      -p, --privateKeyFile=privateKeyFile  private key file (if encrypting with RSA)
      -e, --encrypted=encrypted            (required) serialized encrypted value

    EXAMPLES
      cryppo decrypt -e
      "Aes256Gcm.gSAByGMq4edzM0U=.LS0tCml2OiAhYmluYXJ5IHwtCiAgaW1QL09qMWZ6eWw0cmwwSgphdDogIWJpbmFyeSB8LQogIE5SbjZUQXJ2bitNS1
      Z5M0FpZEpmWlE9PQphZDogbm9uZQo=" -k vm8CjugMda2zdjsI9W25nH-CY-84DDYoBxTFLwfKLDk=

      cryppo decrypt -e "Rsa4096.bJjV2g_RBZKeyqBr-dSjPAc3qtkTgd0=.LS0tCnt9Cg==" -p private.pem
    """)
  end

  command :"encrypt-der" do
    description("Encrypt data with a derived key")

    option(:value, aliases: [:v])
    option(:password, aliases: [:w])
    option(:strategy, aliases: [:s])
    option(:"derivation-strategy", aliases: [:d])

    run context do
      data = context[:value]
      passphrase = context[:password]
      strategy = context[:strategy]
      derivation_strategy = context[:"derivation-strategy"]

      cond do
        data == nil ->
          encrypt_der_help()

        passphrase == nil ->
          encrypt_der_help()

        true ->
          strategy = if strategy, do: strategy, else: "Aes256Gcm"

          derivation_strategy =
            if derivation_strategy, do: derivation_strategy, else: "Pbkdf2Hmac"

          encrypt_with_derived_key(data, strategy, derivation_strategy, passphrase)
      end
    end
  end

  defp encrypt_der_help do
    IO.puts("""
    USAGE
    cryppo encrypt-der -v [DATA] -w [PASSWORD] -s [ENCRYPTION_STRATEGY] -d [DERIVATION_STRATEGY]

    OPTIONS
      -v, --value=value                  (required) value to encrypt
      -w, --password=password            (required) password for key derivation
      -s, --strategy=strategy            encryption strategy (defaults to Aes256Gcm)
      -d, --derivation-strategy=strategy derivation strategy (defaults to Pbkdf2Hmac)

    EXAMPLES
      cryppo encrypt-der -v "hello world" -w "secret phrase" -s Aes256Gcm -d Pbkdf2Hmac

      cryppo encrypt-der -v "hello world" -w "secret phrase"
    """)
  end

  command :"decrypt-der" do
    description("Encrypt data with a derived key")

    option(:encrypted, aliases: [:e])
    option(:password, aliases: [:w])

    run context do
      data = context[:encrypted]
      passphrase = context[:password]

      cond do
        data == nil ->
          decrypt_der_help()

        passphrase == nil ->
          decrypt_der_help()

        true ->
          decrypt_with_derived_key(data, passphrase)
      end
    end
  end

  defp decrypt_der_help do
    IO.puts("""
    USAGE
    cryppo decrypt-der -e [ENCRYPTED_DATA] -w [PASSWORD]

    OPTIONS
      -e, --encrypted=encrypted      (required) serialized encrypted value
      -w, --password=password        (required) passphrase for key derivation

    EXAMPLES
      cryppo decrypt-der -w "secret phrase"  \\
      -e "Aes256Gcm.e-IJT9E8ew3wlz8=.LS0tCmFkOiBub25lCmF0OiAhIWJpbmFyeSB8LQogIHpTRzQzbVhlSFBsR3ZQQVZoNTVJQUE9PQppdjogISFiaW5hcnkgfC0KICBMU2NDNmVCZ2wrUCtuUkpaCg==.Pbkdf2Hmac.LS0tCidpJzogMjEzMjIKJ2l2JzogISFiaW5hcnkgfC0KICBzTmlGT21xWEg5b1piNzRNVElCcGxvNHlHV2M9CidsJzogMzIK"
    """)
  end

  defp decrypt(data, private_key_file) do
    with {:ok, pem} <- File.read(private_key_file),
         {:ok, key} <- Rsa4096.from_pem(pem),
         %EncryptionKey{key: rsa_key}
         when elem(rsa_key, 0) == :RSAPrivateKey and tuple_size(rsa_key) == 11 <-
           key do
      decrypt(data, key, "Rsa4096")
    else
      %EncryptionKey{key: rsa_key}
      when elem(rsa_key, 0) == :RSAPublicKey and tuple_size(rsa_key) == 3 ->
        IO.puts(:stderr, "A private RSA key is required for decryption, not a public key")

      err ->
        IO.puts(:stderr, inspect(err))
    end
  end

  defp decrypt(data, %EncryptionKey{} = key, strategy) do
    IO.puts("Encryption strategy: #{strategy}")

    with encrypted = %EncryptedData{} <- Cryppo.load(data),
         {:ok, decrypted} <- Cryppo.decrypt(encrypted, key) do
      IO.puts(decrypted)
    else
      err -> IO.puts(:stderr, inspect(err))
    end
  end

  defp decrypt(data, key_base64, strategy) do
    case Base.url_decode64(key_base64) do
      {:ok, key} -> decrypt(data, EncryptionKey.new(key), strategy)
      _ -> IO.puts(:stderr, "The key is invalid base64!")
    end
  end

  defp genkey(strategy) do
    case Cryppo.generate_encryption_key(strategy) do
      %EncryptionKey{key: key} ->
        IO.puts("Encryption strategy: #{strategy}")
        key |> Base.url_encode64(padding: true) |> IO.puts()

      err ->
        IO.puts(:stderr, inspect(err))
    end
  end

  defp genkeypair(private_key_out, public_key_out) do
    cond do
      private_key_out == public_key_out ->
        IO.puts(:stderr, "publicKeyOut and privateKeyOut are the same file!")

      File.exists?(private_key_out) ->
        IO.puts(:stderr, "File #{private_key_out} already exists, exiting...")

      File.exists?(public_key_out) ->
        IO.puts(:stderr, "File #{public_key_out} already exists, exiting...")

      true ->
        with private_key = %EncryptionKey{} <- Cryppo.generate_encryption_key("Rsa4096"),
             public_key = {:RSAPublicKey, _, _} <- Rsa4096.private_key_to_public_key(private_key),
             {:ok, private_key_pem} <- Rsa4096.to_pem(private_key),
             {:ok, public_key_pem} <- Rsa4096.to_pem(public_key),
             {:ok, private_key_file} <- File.open(private_key_out, [:write]),
             {:ok, public_key_file} <- File.open(public_key_out, [:write]),
             :ok <- IO.write(private_key_file, private_key_pem),
             :ok <- IO.write(public_key_file, public_key_pem),
             :ok <- File.close(private_key_file),
             :ok <- File.close(public_key_file) do
          "Private key written to #{private_key_out}, public key written to #{public_key_out}."
          |> IO.puts()
        else
          err -> IO.puts(:stderr, inspect(err))
        end
    end
  end

  defp sign(private_key_pem_file, file_to_sign, destination) do
    cond do
      !File.exists?(private_key_pem_file) ->
        IO.puts(:stderr, "File #{private_key_pem_file} not found...")

      !File.exists?(file_to_sign) ->
        IO.puts(:stderr, "File #{file_to_sign} not found...")

      File.exists?(destination) ->
        IO.puts(:stderr, "File #{destination} already exists, exiting...")

      true ->
        with {:ok, pem} <- File.read(private_key_pem_file),
             {:ok, data_to_sign} <- File.read(file_to_sign),
             {:ok, key} <- Rsa4096.from_pem(pem),
             signature = %RsaSignature{} <- Rsa4096.sign(data_to_sign, key),
             serialized_signature <- Cryppo.serialize(signature),
             {:ok, destination_file} <- File.open(destination, [:write]),
             :ok <- IO.write(destination_file, serialized_signature),
             :ok <- File.close(destination_file) do
          IO.puts("Signature written to file #{destination}")
        else
          err -> IO.puts(:stderr, inspect(err))
        end
    end
  end

  defp verify(public_key_pem_file, file_to_verify, destination) do
    cond do
      !File.exists?(public_key_pem_file) ->
        IO.puts(:stderr, "File #{public_key_pem_file} not found...")

      !File.exists?(file_to_verify) ->
        IO.puts(:stderr, "File #{file_to_verify} not found...")

      File.exists?(destination) ->
        IO.puts(:stderr, "File #{destination} already exists, exiting...")

      true ->
        with {:ok, pem} <- File.read(public_key_pem_file),
             {:ok, data_to_verify_serialized} <- File.read(file_to_verify),
             {:ok, key} <- Rsa4096.from_pem(pem),
             rsa_signature = %RsaSignature{} <- Cryppo.load(data_to_verify_serialized) do
          if Rsa4096.verify(rsa_signature, key) do
            IO.puts("Data signature verified")

            with {:ok, destination_file} <- File.open(destination, [:write]),
                 :ok <- IO.write(destination_file, rsa_signature.data),
                 :ok <- File.close(destination_file) do
              IO.puts("Data written to file #{destination}")
            else
              err -> IO.puts(:stderr, inspect(err))
            end
          else
            IO.puts("Data could not be verified")
          end
        else
          err -> IO.puts(:stderr, inspect(err))
        end
    end
  end

  defp encrypt(data, %EncryptionKey{} = key, strategy) do
    IO.puts("Encryption strategy: #{strategy}")
    data |> Cryppo.encrypt(strategy, key) |> Cryppo.serialize() |> IO.puts()
  end

  defp encrypt(data, key_base64, strategy) do
    case Base.url_decode64(key_base64) do
      {:ok, key} -> encrypt(data, EncryptionKey.new(key), strategy)
      _ -> IO.puts(:stderr, "The key is invalid base64!")
    end
  end

  defp encrypt(data, public_key_file) do
    with {:ok, pem} <- File.read(public_key_file),
         {:ok, key} <- Rsa4096.from_pem(pem) do
      encrypt(data, key, "Rsa4096")
    else
      err -> IO.puts(:stderr, inspect(err))
    end
  end

  defp encrypt_with_derived_key(data, strategy, derivation_strategy, passphrase) do
    case Cryppo.encrypt_with_derived_key(data, strategy, derivation_strategy, passphrase) do
      encrypted = %EncryptedDataWithDerivedKey{} ->
        encrypted |> Cryppo.serialize() |> IO.puts()

      err ->
        IO.puts(:stderr, inspect(err))
    end
  end

  defp decrypt_with_derived_key(data, passphrase) do
    with encrypted = %EncryptedDataWithDerivedKey{} <- Cryppo.load(data),
         {:ok, decrypted, _key} <- Cryppo.decrypt_with_derived_key(encrypted, passphrase) do
      IO.puts(decrypted)
    else
      err -> IO.puts(:stderr, inspect(err))
    end
  end
end
