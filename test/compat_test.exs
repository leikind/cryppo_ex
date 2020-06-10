defmodule CompatTest do
  use ExUnit.Case

  alias Cryppo.{DerivedKey, EncryptionKey, Rsa4096}

  @corpus_of_tests "./test/compat.json"

  test "can decrypt a serialized encrypted value encrypted with Aes256Gcm by Ruby Cryppo" do
    {:ok, key} = Base.url_decode64("S5-0MiMs1jkg52bB9nzl1IoNYzxfSyxuoIx6Tvj2vCk=")

    serialized_and_encrypted =
      "Aes256Gcm.29dTcNFcPs-0SOnA.LS0tCml2OiAhYmluYXJ5IHwtCiAgUU1oRnpWZWU3bzE5Qy9XcwphdDogIWJpbmFyeSB8LQogIGFKQjVhYU0wWGZnTjZCYm42U0FzUnc9PQphZDogbm9uZQo="

    {:ok, restored_encrypted_data} = Cryppo.load(serialized_and_encrypted)

    assert Cryppo.decrypt(restored_encrypted_data, key) == {:ok, "this is love"}
  end

  test "can decrypt a serialized encrypted value encrypted with Rsa4096 by Ruby Cryppo" do
    pem =
      "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"

    serialized =
      "Rsa4096.mxqaQRwtp0SBmno6syisN4orlH-Q4-60I_CmMYXD0e3QliXrK4VUn0dRBHJNQNHoJNRAtd5-Y4OniM8W5cFUMkVhseaQsBR3AXIFUvcQYID8_m5SRp6rhcOxih_6Httk6UBqSUg4s8LvBO1MXCjikBHSwjvrth_EowC9epOR7YeBEKDShOdbBf7riP5aXby037CS-ofI7wVv2dGoc-rY1Z4Khdufofu9VhdejmXQG3vvzPyIkEv-zy_fgtr31qY0VSQ0r2W3VRsRE94KOF88cSl2LmDv0tD96VMfudqFQsAtieTCo7Be-BpDcnSBhiVJGN9Sc07DRHSJ88EnmqTGwaRuK-6fSdyPEhRWH0rAz0CLg42gks3bpfYp68dEhWxi5zL_dZke1k-R82ak3fGtGTbjZxH0V5s6WczGRCQwAl86fE95LI_9JEWpeiqhbRlu3aRTKcs4EZC4SRROf0-5Qa-l4atrVp2gTRX6H8tPCdqNko5vUfub4RIehOJDq6Y--rw53ZFXD5h89ifXQgVn_uz1SAo78DR8TDGMRNps2JypcgMHjsYG3SyGw-LXp61ADZGx_5mm6tJK3Ubib30D7j5R_QV_bVSSaRCv16tXn9kgbg6k-BLseNvC7f9kuS2aabiqGROwzHuBL4lbJOscoCNUAGmLz_ShYlhuysUP_D0=.LS0tIHt9Cg=="

    {:ok, restored_encrypted_data} = Cryppo.load(serialized)

    assert Cryppo.decrypt(restored_encrypted_data, pem) == {:ok, "this is love"}
  end

  test "encrypt with pem from ruby, decrypt, serialize, de-serialize, decrypt" do
    pem =
      "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"

    encrypted = Cryppo.encrypt("this is love", "Rsa4096", pem)
    assert Cryppo.decrypt(encrypted, pem) == {:ok, "this is love"}

    ser = Cryppo.Serialization.serialize(encrypted)
    {:ok, restored_encrypted} = Cryppo.load(ser)
    assert Cryppo.decrypt(restored_encrypted, pem) == {:ok, "this is love"}
  end

  test "decrypt a value encrypted with a derived key and serialized with ruby Cryppo" do
    {:ok, encrypted} =
      "Aes256Gcm.8nGHS3XRrIdmSqju.LS0tCml2OiAhYmluYXJ5IHwtCiAgcWFFR0tZeklzMEVQdTFoYgphdDogIWJpbmFyeSB8LQogIGUxeVBxMGVJM2F1S3BVZ0pUYitXR1E9PQphZDogbm9uZQo=.Pbkdf2Hmac.LS0tCml2OiAhYmluYXJ5IHwtCiAgMzdzZTd0N25jMUZWT1NkNldjUUQ1UkpNWVZzPQppOiAyMDg2NwpsOiAzMgo="
      |> Cryppo.load()

    {:ok, decrypted, derived_key} =
      encrypted |> Cryppo.decrypt_with_derived_key("this is a passphrase")

    assert decrypted == "this is love"
    assert %DerivedKey{} = derived_key
  end

  test "verify a signature signed with Ruby Cryppo" do
    pem =
      "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"

    serialized_signature =
      "Sign.Rsa4096.mtCOwALUET6JYR_K9AfSYapAmde7xKUPaeEzZqbdqkwiGGmmwDPKbrZFv_mMA61lA1ojHokUod38zB8HPYffPd7GBZZMCpa02iO076_Ue-HCJBVNf1Y-VcVGcNq5DJXs4l0hUl8pPkZ_MUN6om_BDZLtGnTndqookdM6NLQ3qa7pHZKoBgkfEeBbC4XDgU0YCWBk9QL_VLZYHbyVwM-YFlyFzsMMa9QH6HQp6pAnvRarQjAXAnhGK6cespifx6xvRa7xuTQAAxtruh-QOgh0IXiFGaHScdE6fEj1OlJVDE2TtCJAe9eTffnAgzp2FyIU1ASi87xjVWVO0ckxyH7GqR8-_Ol7U-nW_cn2grDY6EOKQdIV-ViSL5buw53nEBtwR3S4rHXsx6qhywnZS5nDFk-k6NSFiyPUcn_aZV-jOTsFM5I9smy0N2PyTaoAe5-x2-53cZ7yaFr6MKE_cWrYEdVss1YepIFtd60VFmqyWqUN_AdZk6Ixg7FEKAx5F1nyHfbKsZAGUk5zH4r84Xqxh0avduZk3ZaOca9Ax6oEKg7zHJYBiygputqr_NUH1Mv_NGeZndcoOOO4rm0MnH6JeiD92WpxCCgRxSnYUhh-7ZOHeco_oo7N5IHX_D_6PlBm5zLy48UKDdfZmApZmWOMY_cjnFGrLII4ftYISDzTYy0=.dGhpcyBpcyBsb3Zl"

    {:ok, private_key} = Rsa4096.from_pem(pem)
    public_key_erlang_tuple = Rsa4096.private_key_to_public_key(private_key)

    {:ok, signature} = Cryppo.load(serialized_signature)

    assert Rsa4096.verify(signature, public_key_erlang_tuple) == true
  end

  test "the corpus of serialized values" do
    {:ok, json} = File.read(@corpus_of_tests)

    {:ok,
     %{
       "encryption_with_key" => encryption_with_key,
       "encryption_with_derived_key" => encryption_with_derived_key,
       "signatures" => signatures
     }} = Jason.decode(json)

    encryption_with_key
    |> Enum.map(fn %{
                     "encryption_strategy" => encryption_strategy,
                     "expected_decryption_result" => expected_decryption_result,
                     "format" => _format,
                     "key" => key,
                     "serialized" => serialized
                   } ->
      encryption_key =
        case encryption_strategy do
          "Rsa4096" ->
            {:ok, encryption_key} = Rsa4096.from_pem(key)
            encryption_key

          "Aes256Gcm" ->
            {:ok, k} = Base.url_decode64(key)
            EncryptionKey.new(k)
        end

      {:ok, encrypted_data} = serialized |> Cryppo.load()

      {:ok, decrypted} = Cryppo.decrypt(encrypted_data, encryption_key)
      assert decrypted == expected_decryption_result
    end)

    encryption_with_derived_key
    |> Enum.map(fn %{
                     "derivation_strategy" => _derivation_strategy,
                     "encryption_strategy" => _encryption_strategy,
                     "expected_decryption_result" => expected_decryption_result,
                     "format" => _format,
                     "passphrase" => passphrase,
                     "serialized" => serialized
                   } ->
      {:ok, encrypted_data} = serialized |> Cryppo.load()

      {:ok, decrypted, _key} = Cryppo.decrypt_with_derived_key(encrypted_data, passphrase)

      assert decrypted == expected_decryption_result
    end)

    signatures
    |> Enum.map(fn %{
                     "public_pem" => public_pem,
                     "serialized_signature" => serialized_signature
                   } ->
      {:ok, signature} = serialized_signature |> Cryppo.load()

      assert Rsa4096.verify(signature, public_pem)
    end)
  end

  # Use this to regenerate the corpus of tests ("./test/compat.json")
  # test "generate a corpus of tests", do: generate_a_corpus_of_tests()

  def generate_a_corpus_of_tests do
    aes = "Aes256Gcm"
    rsa = "Rsa4096"
    pbkdf2hmac = "Pbkdf2Hmac"

    cases = 30

    sentences_to_encrypt = 0..cases |> Enum.map(fn _ -> Faker.Food.description() end)

    encryption_with_key =
      sentences_to_encrypt
      |> Enum.flat_map(fn sentence ->
        {encrypted_aes, key_aes} = Cryppo.encrypt(sentence, aes)
        {encrypted_rsa, key_rsa} = Cryppo.encrypt(sentence, rsa)

        {:ok, pem} = Cryppo.Rsa4096.to_pem(key_rsa)

        key_aes_base64 = Base.url_encode64(key_aes.key, padding: true)

        [
          # AES
          %{
            serialized: Cryppo.serialize(encrypted_aes),
            expected_decryption_result: sentence,
            encryption_strategy: aes,
            key: key_aes_base64,
            format: "latest_version"
          },
          %{
            serialized: Cryppo.serialize(encrypted_aes, version: :legacy),
            expected_decryption_result: sentence,
            encryption_strategy: aes,
            key: key_aes_base64,
            format: "legacy"
          },
          # RSA
          %{
            serialized: Cryppo.serialize(encrypted_rsa),
            expected_decryption_result: sentence,
            encryption_strategy: rsa,
            key: pem,
            format: "latest_version"
          },
          %{
            serialized: Cryppo.serialize(encrypted_rsa, version: :legacy),
            expected_decryption_result: sentence,
            encryption_strategy: rsa,
            key: pem,
            format: "legacy"
          }
        ]
      end)

    encryption_with_derived_key =
      sentences_to_encrypt
      |> Enum.flat_map(fn sentence ->
        passphrase =
          Faker.Food.dish() <> " " <> Faker.Name.first_name() <> " " <> Faker.Name.last_name()

        encrypted = Cryppo.encrypt_with_derived_key(sentence, aes, pbkdf2hmac, passphrase)

        [
          %{
            serialized: Cryppo.serialize(encrypted),
            expected_decryption_result: sentence,
            encryption_strategy: aes,
            derivation_strategy: pbkdf2hmac,
            passphrase: passphrase,
            format: "latest_version"
          },
          %{
            serialized: Cryppo.serialize(encrypted, version: :legacy),
            expected_decryption_result: sentence,
            encryption_strategy: aes,
            derivation_strategy: pbkdf2hmac,
            passphrase: passphrase,
            format: "legacy"
          }
        ]
      end)

    sentences_to_sign = sentences_to_encrypt

    signatures =
      sentences_to_sign
      |> Enum.map(fn sentence ->
        rsa_key = Cryppo.generate_encryption_key(rsa)

        {:ok, public_pem} = rsa_key |> Rsa4096.private_key_to_public_key() |> Rsa4096.to_pem()

        serialized_signature = sentence |> Rsa4096.sign(rsa_key) |> Cryppo.serialize()

        %{
          serialized_signature: serialized_signature,
          public_pem: public_pem
        }
      end)

    json =
      %{
        encryption_with_key: encryption_with_key,
        encryption_with_derived_key: encryption_with_derived_key,
        signatures: signatures
      }
      |> Jason.encode!(pretty: true)

    {:ok, file} = File.open(@corpus_of_tests, [:write, :utf8])
    IO.write(file, json)
    :ok = File.close(file)
  end
end
