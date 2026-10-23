defmodule PKCS12.KDFTest do
  use ExUnit.Case, async: true

  alias PKCS12.KDF

  # Computed with `openssl kdf -kdfopt digest:... -kdfopt hexpass:...
  # -kdfopt hexsalt:... -kdfopt iter:... -kdfopt id:... -keylen ... PKCS12KDF`
  # (OpenSSL 3.6). The passwords are already BMPStrings.
  #
  # {hash, password, salt, iterations, purpose, bytes, expected}
  @vectors [
    {:sha, "0074006500730074002d00700061007300730077006f007200640000", "0102030405060708", 2048,
     :key, 24, "13a7c6beb4d45b522e38b07ddf63dfe2c7fd45474ab99b69"},
    {:sha, "0074006500730074002d00700061007300730077006f007200640000", "0102030405060708", 2048,
     :iv, 8, "358f6e5db0c3eaa1"},
    {:sha, "0074006500730074002d00700061007300730077006f007200640000", "0102030405060708", 2048,
     :mac, 20, "b0d27fc2b077400c1e490929e558d1182b9a6726"},
    {:sha224, "0074006500730074002d00700061007300730077006f007200640000",
     "00112233445566778899aabbccddeeff", 1000, :key, 32,
     "ace1fcb0205012d09221e86797bda93336d9dda1ac65c269ea3d495200d049c7"},
    {:sha256, "0074006500730074002d00700061007300730077006f007200640000", "0102030405060708",
     2048, :mac, 32, "b5735bc5a8a86926ee5b74d9dda4096080528d3ed619318a45984e96e28f1153"},
    {:sha384, "00530065006e00680061002d00e700e3006f0000", "0a0b0c", 7, :key, 100,
     "733688c498cec9926e5fb7341a945d0d0aaa12d79f0165baa459a88942dedc17a3dedc58d182b83358c89367d998a9a3ddee1ead8d8fec29bcf1be08a5bfe7af7495c5ab09f762107dca88119c3bb9b9621f0b8769b629974941517e1ee8a58b68939e0c"},
    {:sha512, "00530065006e00680061002d00e700e3006f0000", "00", 1, :mac, 64,
     "1276b6b584bc3b199c127d5c6d0d1f298cf88f246cc3047eb5d2fe4a6b87fba617e9bc33624ceb8840d573ca147e93116a07ba27e7eff6c58f56259df0c7b227"},
    # the empty password, as a terminator only and as no bytes at all
    {:sha, "0000", "0a0b", 3, :mac, 20, "3fab250bf4a6f508d20b80dcd2618d8b067c714a"},
    {:sha, "", "0a0b", 3, :mac, 20, "7882f17dbf411aaac252a08dee16839e429d45bc"},
    # password and salt longer than one block, output of more than two blocks
    {:sha256, String.duplicate("0078", 70) <> "0000", String.duplicate("ff", 70), 5, :iv, 65,
     "e43410972feab813faae5fc209d2d398f8416e8f78709f01140288a8e216ac70b936125964c2467fdf23ba36ae479878ca614b254c9670d6453acc06b514d81fa4"}
  ]

  test "vectors" do
    for {hash, password, salt, iterations, purpose, n, expected} <- @vectors do
      password = Base.decode16!(password, case: :lower)
      salt = Base.decode16!(salt, case: :lower)
      out = KDF.derive(hash, password, salt, iterations, purpose, n)
      assert Base.encode16(out, case: :lower) == expected, inspect({hash, iterations, purpose, n})
    end
  end

  test "a shorter output is a prefix of a longer one" do
    long = KDF.derive(:sha, <<0, 0>>, "salt", 10, :key, 50)
    assert KDF.derive(:sha, <<0, 0>>, "salt", 10, :key, 7) == binary_part(long, 0, 7)
  end

  test "hash_size/1" do
    sizes = for hash <- ~w(sha sha224 sha256 sha384 sha512)a, do: KDF.hash_size(hash)
    assert sizes == [20, 28, 32, 48, 64]
  end
end
