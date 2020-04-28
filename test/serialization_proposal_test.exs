defmodule ProposalTest do
  use ExUnit.Case

  alias Cryppo.{Loader, Serialization, Yaml}

  test "what's inside" do
    data_encrypted_with_derived_key =
      Cryppo.encrypt_with_derived_key("this is love", "Aes256Gcm", "Pbkdf2Hmac", "my passphrase")

    serialized = Serialization.serialize(data_encrypted_with_derived_key)

    [_, _, encryption_artefacts, _, derivation_artefacts] = String.split(serialized, ".")

    restored = Loader.load(serialized)

    assert data_encrypted_with_derived_key.encrypted_data.encryption_artefacts ==
             restored.encrypted_data.encryption_artefacts

    assert restored.derived_key.salt == data_encrypted_with_derived_key.derived_key.salt
    assert restored.derived_key.iter == data_encrypted_with_derived_key.derived_key.iter
    assert restored.derived_key.length == data_encrypted_with_derived_key.derived_key.length
  end

  test "serialization and then loading the values are correct" do
    data_encrypted_with_derived_key =
      Cryppo.encrypt_with_derived_key("this is love", "Aes256Gcm", "Pbkdf2Hmac", "my passphrase")

    serialized = Serialization.serialize(data_encrypted_with_derived_key)

    restored = Loader.load(serialized)

    assert data_encrypted_with_derived_key.encrypted_data.encryption_artefacts ==
             restored.encrypted_data.encryption_artefacts

    assert restored.derived_key.salt == data_encrypted_with_derived_key.derived_key.salt
    assert restored.derived_key.iter == data_encrypted_with_derived_key.derived_key.iter
    assert restored.derived_key.length == data_encrypted_with_derived_key.derived_key.length
    assert restored.derived_key.hash == data_encrypted_with_derived_key.derived_key.hash
  end

  def pack_derivation_artefacts(l, i, iv) do
    # l is a integer which will fit in 1 byte (32)
    # i is a integer which will fit in 2 bytes (ex. 20511)
    # iv is a binary
    <<l::8-integer-unsigned, i::16-integer-unsigned, iv::binary>>
  end

  def unpack_derivation_artefacts(packed) do
    <<l::8-integer-unsigned, i::16-integer-unsigned, iv::binary>> = packed
    {l, i, iv}
  end

  test "pack derivation artefacts" do
    data_encrypted_with_derived_key =
      Cryppo.encrypt_with_derived_key("this is love", "Aes256Gcm", "Pbkdf2Hmac", "my passphrase")

    # IO.puts("")
    # i = iterations, iv = salt, l - length
    l = data_encrypted_with_derived_key.derived_key.length
    i = data_encrypted_with_derived_key.derived_key.iter
    iv = data_encrypted_with_derived_key.derived_key.salt

    packed = pack_derivation_artefacts(l, i, iv)

    {restored_l, restored_i, restored_iv} = unpack_derivation_artefacts(packed)

    assert restored_l == l
    assert restored_i == i
    assert restored_iv == iv
  end

  def pack_encryption_artefacts(at, iv, ad) do
    #  at is 16 bytes, iv is 12 bytes, ad is variable size
    <<at::binary, iv::binary, ad::binary>>
  end

  def unpack_encryption_artefacts(encryption_artefacts_bin) do
    #  at is 16 bytes, iv is 12 bytes, ad is variable size
    <<at::binary-size(16), rest::binary>> = encryption_artefacts_bin
    <<iv::binary-size(12), ad::binary>> = rest

    {at, iv, ad}
  end

  test "pack encryption artefacts" do
    data_encrypted_with_derived_key =
      Cryppo.encrypt_with_derived_key("this is love", "Aes256Gcm", "Pbkdf2Hmac", "my passphrase")

    %{ad: ad, at: at, iv: iv} =
      data_encrypted_with_derived_key.encrypted_data.encryption_artefacts

    packed = pack_encryption_artefacts(at, iv, ad)

    {restored_at, restored_iv, restored_ad} = unpack_encryption_artefacts(packed)

    assert restored_at == at
    assert restored_iv == iv
    assert restored_ad == ad
  end

  test "pack both and encode as base64" do
    data_encrypted_with_derived_key =
      Cryppo.encrypt_with_derived_key("this is love", "Aes256Gcm", "Pbkdf2Hmac", "my passphrase")

    l = data_encrypted_with_derived_key.derived_key.length
    i = data_encrypted_with_derived_key.derived_key.iter
    iv = data_encrypted_with_derived_key.derived_key.salt

    packed_derivation_artefacts = pack_derivation_artefacts(l, i, iv)

    %{ad: ad, at: at, iv: iv} =
      data_encrypted_with_derived_key.encrypted_data.encryption_artefacts

    packed_encryption_artefacts = pack_encryption_artefacts(at, iv, ad)

    # IO.puts("bytes for all artefacts:")

    # in the current version: 220

    total_bytes_for_encryption_and_derivation_artefacts =
      (Base.url_encode64(packed_derivation_artefacts, padding: true) <>
         Base.url_encode64(packed_encryption_artefacts, padding: true))
      |> byte_size()

    # |> IO.inspect()

    _percent = (total_bytes_for_encryption_and_derivation_artefacts / 220 * 100) |> Float.ceil(2)

    # IO.puts("#{percent}%")
  end
end
