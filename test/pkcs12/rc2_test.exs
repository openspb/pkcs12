defmodule PKCS12.RC2Test do
  use ExUnit.Case, async: true

  alias PKCS12.RC2

  # RFC 2268, section 5: {key bytes, effective bits, key, plaintext, ciphertext}
  @vectors [
    {8, 63, "0000000000000000", "0000000000000000", "ebb773f993278eff"},
    {8, 64, "ffffffffffffffff", "ffffffffffffffff", "278b27e42e2f0d49"},
    {8, 64, "3000000000000000", "1000000000000001", "30649edf9be7d2c2"},
    {1, 64, "88", "0000000000000000", "61a8a244adacccf0"},
    {7, 64, "88bca90e90875a", "0000000000000000", "6ccf4308974c267f"},
    {16, 64, "88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "1a807d272bbe5db1"},
    {16, 128, "88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6"},
    {33, 129, "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
     "0000000000000000", "5b78d3a43dfff1f1"}
  ]

  test "RFC 2268 vectors" do
    for {size, bits, key, plain, cipher} <- @vectors do
      key = Base.decode16!(key, case: :lower)
      assert byte_size(key) == size
      expanded = RC2.expand(key, bits)
      plain = Base.decode16!(plain, case: :lower)
      cipher = Base.decode16!(cipher, case: :lower)
      assert RC2.encrypt_block(expanded, plain) == cipher
      assert RC2.decrypt_block(expanded, cipher) == plain
    end
  end

  test "CBC round trip" do
    key = :crypto.strong_rand_bytes(5)
    iv = :crypto.strong_rand_bytes(8)
    data = :crypto.strong_rand_bytes(4096)
    encrypted = RC2.encrypt_cbc(key, 40, iv, data)
    assert byte_size(encrypted) == byte_size(data)
    assert RC2.decrypt_cbc(key, 40, iv, encrypted) == data
  end

  @tag :rc2
  test "CBC matches :crypto, when its OpenSSL has RC2" do
    if :rc2_cbc in :crypto.supports(:ciphers) do
      for size <- [5, 16], bytes <- [8, 64, 1024] do
        key = :crypto.strong_rand_bytes(size)
        iv = :crypto.strong_rand_bytes(8)
        data = :crypto.strong_rand_bytes(bytes)
        theirs = :crypto.crypto_one_time(:rc2_cbc, key, iv, data, true)
        assert RC2.encrypt_cbc(key, size * 8, iv, data) == theirs
        assert RC2.decrypt_cbc(key, size * 8, iv, theirs) == data
      end
    end
  end
end
