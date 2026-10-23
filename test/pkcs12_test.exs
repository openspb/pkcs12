defmodule PKCS12Test do
  use ExUnit.Case, async: true

  import PKCS12.Fixtures

  alias PKCS12.{Bag, Error}

  @pw "test-password"
  @pwu "Senha-ção"

  # {file, password, key material, expected password encoding}
  @files [
    {"o3_default.p12", @pw, "rsa", :unicode},
    {"o3_legacy.p12", @pw, "rsa", :unicode},
    {"o3_3des.p12", @pw, "rsa", :unicode},
    {"o3_pbmac1.p12", @pw, "rsa", :unicode},
    {"o3_pbmac1_sha512.p12", @pw, "rsa", :unicode},
    {"o3_nomac.p12", @pw, "rsa", :unicode},
    {"o3_noenc.p12", @pw, "rsa", :unicode},
    {"o3_aes128_sha512.p12", @pw, "rsa", :unicode},
    {"o3_aes192_sha384.p12", @pw, "rsa", :unicode},
    {"o3_pbes2_3des.p12", @pw, "rsa", :unicode},
    {"o3_rc2_128.p12", @pw, "rsa", :unicode},
    {"o3_iter100k.p12", @pw, "rsa", :unicode},
    {"o3_legacy_100k.p12", @pw, "rsa", :unicode},
    {"o3_noiter.p12", @pw, "rsa", :unicode},
    {"o3_utf8.p12", @pwu, "rsa", :unicode},
    {"o3_utf8_legacy.p12", @pwu, "rsa", :unicode},
    {"o3_empty.p12", "", "rsa", :unicode},
    {"o3_empty_legacy.p12", "", "rsa", :unicode},
    {"o3_names.p12", @pw, "rsa", :unicode},
    {"o3_ec.p12", @pw, "ec", :unicode},
    {"o3_ec_legacy.p12", @pw, "ec", :unicode},
    {"o11_default.p12", @pw, "rsa", :unicode},
    {"o11_utf8.p12", @pwu, "rsa", :unicode},
    {"o11_empty.p12", "", "rsa", :unicode},
    {"o11_aes.p12", @pw, "rsa", :unicode},
    {"lre_default.p12", @pw, "rsa", :unicode},
    {"lre_utf8.p12", @pwu, "rsa", :latin1},
    {"lre_empty.p12", "", "rsa", :unicode},
    {"py_best.p12", @pw, "rsa", :unicode},
    {"py_3des_sha1.p12", @pw, "rsa", :unicode},
    {"py_aes_sha256.p12", @pw, "rsa", :unicode},
    {"py_noenc.p12", "", "rsa", :unicode},
    {"py_utf8.p12", @pwu, "rsa", :unicode},
    {"java_default.p12", @pw, "rsa", :unicode},
    {"java_legacy.p12", @pw, "rsa", :unicode}
  ]

  describe "files of each generator" do
    for {file, password, material, encoding} <- @files do
      test file do
        assert {:ok, p12} = PKCS12.decode(read!(unquote(file)), unquote(password))
        assert :public_key.der_decode(:PrivateKeyInfo, p12.private_key) == key(unquote(material))
        assert p12.certificate == cert_der(unquote(material))
        assert p12.ca_certificates == [cert_der("ca")]
        assert p12.info.password_encoding == unquote(encoding)
      end
    end

    test "a wrong password" do
      for {file, password, _, _} <- @files do
        assert {:error, %Error{reason: :invalid_password}} =
                 PKCS12.decode(read!(file), password <> "x"),
               file
      end
    end

    test "the password is not needed without encryption and MAC" do
      for password <- ["any", "", nil] do
        assert {:ok, p12} = PKCS12.decode(read!("o3_noenc_nomac.p12"), password)
        assert p12.certificate == cert_der("rsa")
        assert p12.info == %{mac: nil, encryption: [], password_encoding: nil}
      end
    end

    test "nil is the empty password" do
      assert {:ok, %PKCS12{}} = PKCS12.decode(read!("o3_empty.p12"), nil)
    end

    test "RC4 depends on :crypto" do
      result = PKCS12.decode(read!("o3_rc4.p12"), @pw)

      if :rc4 in :crypto.supports(:ciphers) do
        assert {:ok, %{certificate: cert}} = result
        assert cert == cert_der("rsa")
      else
        assert {:error, %Error{reason: {:not_available, cipher}}} = result
        assert cipher in [:rc4_40, :rc4_128]
      end
    end

    # Set by the CI job without the OpenSSL legacy provider, so that the files
    # above prove the library reads RC2 on its own.
    if System.get_env("PKCS12_EXPECT_NO_LEGACY") == "1" do
      test "this system has no OpenSSL legacy provider" do
        refute :rc2_cbc in :crypto.supports(:ciphers)
      end
    end
  end

  describe "info" do
    test "the default of OpenSSL 3" do
      assert {:ok, %{info: info}} = PKCS12.decode(read!("o3_default.p12"), @pw)

      assert info == %{
               mac: %{scheme: :hmac, digest: :sha256, prf: nil, iterations: 2048, verified: true},
               encryption: [
                 %{scheme: :pbes2, cipher: :aes_256_cbc, digest: :sha256, iterations: 2048}
               ],
               password_encoding: :unicode
             }
    end

    test "the legacy algorithms: encrypted parts first, then keys" do
      assert {:ok, %{info: info}} = PKCS12.decode(read!("java_legacy.p12"), @pw)
      assert %{scheme: :hmac, digest: :sha, iterations: 100_000} = info.mac

      assert info.encryption == [
               %{scheme: :pkcs12_pbe, cipher: :rc2_40_cbc, digest: :sha, iterations: 50_000},
               %{scheme: :pkcs12_pbe, cipher: :des_ede3_cbc, digest: :sha, iterations: 50_000}
             ]
    end

    test "PBMAC1" do
      assert {:ok, %{info: %{mac: mac}}} = PKCS12.decode(read!("o3_pbmac1_sha512.p12"), @pw)

      assert mac == %{
               scheme: :pbmac1,
               digest: :sha512,
               prf: :sha512,
               iterations: 2048,
               verified: true
             }
    end

    test "no MAC" do
      assert {:ok, %{info: %{mac: nil}}} = PKCS12.decode(read!("o3_nomac.p12"), @pw)
    end
  end

  describe "contents" do
    test "a file with certificates only" do
      assert {:ok, p12} = PKCS12.decode(read!("o3_certs_only.p12"), @pw)
      assert p12.private_key == nil
      assert p12.certificate == nil
      assert Enum.sort(p12.ca_certificates) == Enum.sort([cert_der("rsa"), cert_der("ca")])
    end

    test "a trust store without password, with attributes the library does not interpret" do
      assert {:ok, p12} = PKCS12.decode(read!("java_truststore.p12"), nil)
      assert p12.ca_certificates == [cert_der("ca")]
      assert [%Bag{type: :certificate, friendly_name: "ca", attributes: attributes}] = p12.bags
      # Java's trustedKeyUsage
      assert [{"2.16.840.1.113894.746875.1.1", [_value]}] = attributes
    end

    test "two keys: the first is the main one, both are in the bags" do
      assert {:ok, p12} = PKCS12.decode(read!("java_two_keys.p12"), @pw)
      assert [first, second] = for(%Bag{type: :private_key} = bag <- p12.bags, do: bag)
      assert Enum.sort([first.friendly_name, second.friendly_name]) == ["ec", "rsa"]

      # keytool does not keep the order of the aliases; the names tell which is which.
      material = first.friendly_name
      assert p12.private_key == first.value
      assert :public_key.der_decode(:PrivateKeyInfo, first.value) == key(material)
      assert p12.certificate == cert_der(material)
      # The other leaf, and the CA once for each key.
      assert length(p12.ca_certificates) == 3
    end

    test "bags of other types are passed on" do
      assert {:ok, p12} = PKCS12.decode(read!("java_secret.p12"), @pw)
      assert p12.private_key == nil
      # secretBag
      assert [%Bag{type: :other, oid: "1.2.840.113549.1.12.10.1.5", friendly_name: "aes"}] =
               p12.bags
    end

    test "friendlyName with non-ASCII characters" do
      assert {:ok, p12} = PKCS12.decode(read!("o3_names.p12"), @pw)
      names = for bag <- p12.bags, do: bag.friendly_name
      assert "Chave de teste ção" in names
      assert "AC de teste" in names
    end

    test "localKeyId ties the key to its certificate" do
      assert {:ok, p12} = PKCS12.decode(read!("o3_default.p12"), @pw)
      [key] = for %Bag{type: :private_key} = bag <- p12.bags, do: bag

      [leaf] =
        for %Bag{type: :certificate, value: value} = bag <- p12.bags,
            value == p12.certificate,
            do: bag

      assert is_binary(key.local_key_id)
      assert key.local_key_id == leaf.local_key_id
      assert key.oid == "1.2.840.113549.1.12.10.1.2"
    end

    test "without localKeyId, the certificate is found by its public key" do
      for {file, material} <- [{"o3_noenc_nomac.p12", "rsa"}, {"o3_ec.p12", "ec"}] do
        der =
          if file == "o3_ec.p12" do
            # Make an unencrypted copy, the only kind map_bags can change.
            {:ok, p12} = PKCS12.decode(read!(file), @pw)
            plain_file(p12)
          else
            read!(file)
          end

        stripped = map_bags(der, &drop_local_key_id/1)
        assert {:ok, p12} = PKCS12.decode(stripped, nil)
        assert Enum.all?(p12.bags, &(&1.local_key_id == nil))
        assert p12.certificate == cert_der(material), file
        assert p12.ca_certificates == [cert_der("ca")]
      end
    end

    test "keys and certificates do not keep the input binary alive" do
      assert {:ok, p12} = PKCS12.decode(read!("o3_noenc_nomac.p12"), nil)
      assert :binary.referenced_byte_size(p12.private_key) == byte_size(p12.private_key)
      assert :binary.referenced_byte_size(p12.certificate) == byte_size(p12.certificate)
    end
  end

  describe "limits" do
    test "iterations of one derivation" do
      bin = read!("o3_bigiter.p12")

      assert {:error, %Error{reason: {:too_many_iterations, 3_000_000}}} = PKCS12.decode(bin, @pw)
      assert {:ok, _} = PKCS12.decode(bin, @pw, max_iterations: 3_000_000)
    end

    test "iterations of all derivations together" do
      # MAC, certificates and key: 100,000 each.
      bin = read!("o3_iter100k.p12")

      assert {:error, %Error{reason: {:too_many_total_iterations, 300_000}}} =
               PKCS12.decode(bin, @pw, max_total_iterations: 250_000)

      assert {:ok, _} = PKCS12.decode(bin, @pw, max_total_iterations: 300_000)
    end

    test "the budget counts the hash blocks of each derivation" do
      # MAC with SHA-1: 100,000 x 1. RC2-40: 50,000 x (1 for the key + 1 for
      # the IV). 3DES: 50,000 x (2 for the key + 1 for the IV).
      bin = read!("java_legacy.p12")

      assert {:error, %Error{reason: {:too_many_total_iterations, 350_000}}} =
               PKCS12.decode(bin, @pw, max_total_iterations: 349_999)

      assert {:ok, _} = PKCS12.decode(bin, @pw, max_total_iterations: 350_000)
    end

    test "a wrong password also spends the budget" do
      # Two candidates for the empty password: two MAC checks of 2,048.
      assert {:error, %Error{reason: {:too_many_total_iterations, 4096}}} =
               PKCS12.decode(read!("o3_default.p12"), "", max_total_iterations: 4095)
    end

    test "verify_mac: false still decrypts" do
      assert {:ok, p12} = PKCS12.decode(read!("o3_default.p12"), @pw, verify_mac: false)
      assert p12.certificate == cert_der("rsa")
      assert p12.info.mac.verified == false
    end
  end

  describe "RFC 9879 vectors (PBMAC1, password 1234)" do
    for file <- ~w(rfc9879_a1.p12 rfc9879_a2.p12 rfc9879_a3.p12) do
      test "#{file} is valid" do
        assert {:ok, %{private_key: key, info: %{mac: %{scheme: :pbmac1}}}} =
                 PKCS12.decode(read!(unquote(file)), "1234")

        assert is_tuple(:public_key.der_decode(:PrivateKeyInfo, key))
      end
    end

    test "A.4 and A.5 (wrong iteration count, wrong salt) fail" do
      for file <- ~w(rfc9879_a4.p12 rfc9879_a5.p12) do
        assert {:error, %Error{reason: :invalid_password}} = PKCS12.decode(read!(file), "1234")
      end
    end

    test "A.6 (no keyLength) fails" do
      assert {:error, %Error{reason: :malformed}} = PKCS12.decode(read!("rfc9879_a6.p12"), "1234")
    end
  end

  describe "BER" do
    test "indefinite lengths in the outer layers, MAC intact" do
      for file <- ["o3_default.p12", "o3_legacy.p12", "lre_default.p12"] do
        der = read!(file)
        ber = to_ber(der)
        assert ber != der
        assert {:ok, p12} = PKCS12.decode(ber, @pw)
        assert p12.certificate == cert_der("rsa"), file
      end
    end

    test "BER in every layer (files without MAC)" do
      for file <- ["o3_nomac.p12", "o3_noenc_nomac.p12"] do
        assert {:ok, p12} = PKCS12.decode(to_ber(read!(file), deep: true), @pw)
        assert :public_key.der_decode(:PrivateKeyInfo, p12.private_key) == key("rsa")
        assert p12.certificate == cert_der("rsa"), file
      end
    end
  end

  describe "malformed input" do
    test "arbitrary binaries" do
      for bin <- [
            <<>>,
            <<0>>,
            <<0x30>>,
            <<0x30, 0x80>>,
            <<0x30, 0x84, 255, 255, 255, 255>>,
            "text"
          ] do
        assert {:error, %Error{reason: :malformed}} = PKCS12.decode(bin, @pw)
      end
    end

    test "deep nesting does not blow up" do
      deep = Enum.reduce(1..10_000, <<5, 0>>, fn _, acc -> <<0x30, 0x80>> <> acc <> <<0, 0>> end)
      assert {:error, %Error{reason: :malformed}} = PKCS12.decode(deep, @pw)
    end

    test "PEM instead of DER" do
      assert {:error, %Error{reason: :malformed}} = PKCS12.decode(read!("rsa.crt"), @pw)
    end

    test "another PFX version" do
      <<0x30, 0x82, len::16, 0x02, 0x01, 3, rest::binary>> = read!("o3_default.p12")
      bin = <<0x30, 0x82, len::16, 0x02, 0x01, 4, rest::binary>>
      assert {:error, %Error{reason: {:unsupported_version, 4}}} = PKCS12.decode(bin, @pw)
    end
  end

  describe "decode!/3" do
    test "returns the result" do
      assert %PKCS12{} = PKCS12.decode!(read!("o3_default.p12"), @pw)
    end

    test "raises PKCS12.Error" do
      assert_raise Error, "wrong password", fn -> PKCS12.decode!(read!("o3_default.p12"), "x") end
    end
  end

  describe "arguments" do
    test "a password that is not a binary is refused without being printed" do
      for password <- [~c"test-password", 123, :pw] do
        error =
          assert_raise ArgumentError, fn -> PKCS12.decode(read!("o3_default.p12"), password) end

        refute Exception.message(error) =~ "test-password"
        refute Exception.message(error) =~ "123"
      end
    end

    test "the file must be a binary" do
      assert_raise ArgumentError, fn -> PKCS12.decode(~c"abc", @pw) end
    end

    test "unknown and invalid options" do
      bin = read!("o3_default.p12")
      assert_raise ArgumentError, fn -> PKCS12.decode(bin, @pw, max_iteration: 1) end
      assert_raise ArgumentError, fn -> PKCS12.decode(bin, @pw, max_iterations: 0) end
      assert_raise ArgumentError, fn -> PKCS12.decode(bin, @pw, max_total_iterations: -1) end
      assert_raise ArgumentError, fn -> PKCS12.decode(bin, @pw, verify_mac: "no") end
    end
  end

  describe "secrets stay out of inspect and errors" do
    test "inspect/1 shows no key" do
      {:ok, p12} = PKCS12.decode(read!("o3_noenc_nomac.p12"), nil)
      text = inspect(p12, limit: :infinity, printable_limit: :infinity)
      refute text =~ inspect(p12.private_key, limit: :infinity)
      refute text =~ "private_key:"
      refute text =~ "value:"
    end

    test "errors carry no password" do
      {:error, error} = PKCS12.decode(read!("o3_default.p12"), "secret-pw-123")
      refute inspect(error) =~ "secret-pw-123"
      refute Exception.message(error) =~ "secret-pw-123"
    end
  end

  test "every reason has a message" do
    for reason <- [
          :malformed,
          :invalid_password,
          {:unsupported_version, 4},
          {:unsupported_algorithm, "1.2.3"},
          {:unsupported, :public_key_integrity},
          {:unsupported, :public_key_privacy},
          {:not_available, :rc4},
          {:too_many_iterations, 5},
          {:too_many_total_iterations, 5},
          {:unsupported_mac_key_size, 8}
        ] do
      message = Exception.message(%Error{reason: reason})
      refute message =~ "PKCS#12 error:", inspect(reason)
    end
  end

  # An unencrypted file, without MAC, with the bags of `p12`.
  defp plain_file(p12) do
    alias PKCS12.{DER, OID}

    data = {0x06, OID.encode("1.2.840.113549.1.7.1")}

    bags =
      for bag <- p12.bags do
        {type, value} =
          case bag.type do
            :private_key ->
              {:ok, key} = DER.decode(bag.value)
              {"1.2.840.113549.1.12.10.1.1", key}

            :certificate ->
              x509 = {0x06, OID.encode("1.2.840.113549.1.9.22.1")}
              {"1.2.840.113549.1.12.10.1.3", {0x30, [x509, {0xA0, [{0x04, bag.value}]}]}}
          end

        local_key_id =
          {0x30, [{0x06, OID.encode("1.2.840.113549.1.9.21")}, {0x31, [{0x04, "id"}]}]}

        {0x30, [{0x06, OID.encode(type)}, {0xA0, [value]}, {0x31, [local_key_id]}]}
      end

    safe_contents = DER.encode({0x30, bags})
    auth_safe = DER.encode({0x30, [{0x30, [data, {0xA0, [{0x04, safe_contents}]}]}]})
    DER.encode({0x30, [{0x02, <<3>>}, {0x30, [data, {0xA0, [{0x04, auth_safe}]}]}]})
  end
end
