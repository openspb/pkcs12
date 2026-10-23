defmodule PKCS12.EncodeTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import PKCS12.Fixtures

  alias PKCS12.{Bag, DER, Error}

  @pw "test-password"

  # Few iterations where the count does not matter, to keep the suite fast.
  @fast [iterations: 1]

  setup_all do
    %{p12: PKCS12.decode!(read!("o3_legacy.p12"), @pw)}
  end

  defp round_trip(p12, password, opts) do
    {:ok, pfx} = PKCS12.encode(p12, password, opts)
    PKCS12.decode!(pfx, password)
  end

  defp same_content?(a, b) do
    a.private_key == b.private_key and a.certificate == b.certificate and
      a.ca_certificates == b.ca_certificates
  end

  describe "profiles" do
    test "modern by default", %{p12: p12} do
      back = round_trip(p12, @pw, [])
      assert same_content?(back, p12)

      assert back.info.mac == %{
               scheme: :hmac,
               digest: :sha256,
               prf: nil,
               iterations: 100_000,
               verified: true
             }

      assert back.info.encryption == [
               %{scheme: :pbes2, cipher: :aes_256_cbc, digest: :sha256, iterations: 100_000}
             ]

      assert back.info.password_encoding == :unicode
      assert [%Bag{type: :certificate}, %Bag{type: :certificate}, key] = back.bags
      assert key.type == :private_key
      assert key.oid == "1.2.840.113549.1.12.10.1.2"
    end

    test "legacy", %{p12: p12} do
      back = round_trip(p12, @pw, profile: :legacy)
      assert same_content?(back, p12)
      assert %{scheme: :hmac, digest: :sha, iterations: 2048} = back.info.mac

      assert back.info.encryption == [
               %{scheme: :pkcs12_pbe, cipher: :rc2_40_cbc, digest: :sha, iterations: 2048},
               %{scheme: :pkcs12_pbe, cipher: :des_ede3_cbc, digest: :sha, iterations: 2048}
             ]
    end

    test "options given win over the profile", %{p12: p12} do
      back = round_trip(p12, @pw, profile: :legacy, mac: :sha512, iterations: 10)
      assert %{digest: :sha512, iterations: 10} = back.info.mac
      assert Enum.all?(back.info.encryption, &(&1.iterations == 10))
      assert Enum.map(back.info.encryption, & &1.cipher) == [:rc2_40_cbc, :des_ede3_cbc]
    end

    test "nil takes the value of the profile", %{p12: p12} do
      back = round_trip(p12, @pw, profile: :legacy, key_encryption: nil, mac: nil, iterations: 3)
      assert %{digest: :sha} = back.info.mac
      assert Enum.map(back.info.encryption, & &1.cipher) == [:rc2_40_cbc, :des_ede3_cbc]
    end
  end

  describe "algorithms" do
    test "every cipher, for the key and for the certificates", %{p12: p12} do
      for key <- [:aes_256_cbc, :aes_192_cbc, :aes_128_cbc, :des_ede3_cbc, :none],
          certs <- [:aes_256_cbc, :aes_192_cbc, :aes_128_cbc, :des_ede3_cbc, :rc2_40_cbc, :none] do
        opts = [key_encryption: key, certificate_encryption: certs] ++ @fast
        back = round_trip(p12, @pw, opts)
        assert same_content?(back, p12), inspect(opts)

        expected = for c <- [certs, key], c != :none, uniq: true, do: c
        assert Enum.map(back.info.encryption, & &1.cipher) == expected, inspect(opts)
      end
    end

    test "every MAC", %{p12: p12} do
      for mac <- [:sha, :sha224, :sha256, :sha384, :sha512] do
        back = round_trip(p12, @pw, [mac: mac] ++ @fast)
        assert %{scheme: :hmac, digest: ^mac, verified: true} = back.info.mac
      end
    end

    test "PBMAC1 as RFC 9879 asks", %{p12: p12} do
      {:ok, pfx} = PKCS12.encode(p12, @pw, mac: :pbmac1, iterations: 2000)

      assert %{scheme: :pbmac1, digest: :sha256, prf: :sha256, iterations: 2000} =
               PKCS12.decode!(pfx, @pw).info.mac

      {:ok, {0x30, [_version, _auth_safe, mac_data]}} = DER.decode(pfx)
      {0x30, [{0x30, [{0x30, [_pbmac1, params]}, _digest]}, mac_salt, iterations]} = mac_data
      {0x30, [{0x30, [_pbkdf2, {0x30, [salt, _iter, key_length, _prf]}]}, _hmac]} = params

      # keyLength present and equal to the HMAC size; macSalt and iterations,
      # which PBMAC1 ignores, not empty and not zero.
      assert key_length == {0x02, <<32>>}
      assert mac_salt == salt and byte_size(elem(salt, 1)) == 16
      assert {:ok, 2000} = DER.uint(iterations)
    end

    test "no MAC and no encryption", %{p12: p12} do
      opts = [key_encryption: :none, certificate_encryption: :none, mac: :none]
      {:ok, pfx} = PKCS12.encode(p12, @pw, opts)

      # The password then protects nothing.
      back = PKCS12.decode!(pfx, "anything")
      assert same_content?(back, p12)
      assert back.info == %{mac: nil, encryption: [], password_encoding: nil}
      assert Enum.map(back.bags, & &1.oid) |> List.last() == "1.2.840.113549.1.12.10.1.1"
    end

    test "random salts and IVs", %{p12: p12} do
      refute PKCS12.encode!(p12, @pw, @fast) == PKCS12.encode!(p12, @pw, @fast)
    end
  end

  describe "content" do
    test "the key and its certificate share a localKeyId, the SHA-1 of the certificate",
         %{p12: p12} do
      back = round_trip(p12, @pw, @fast)
      [leaf, ca, key] = back.bags
      assert key.local_key_id == :crypto.hash(:sha, p12.certificate)
      assert leaf.local_key_id == key.local_key_id
      assert ca.local_key_id == nil
      assert Enum.all?(back.bags, &(&1.friendly_name == nil and &1.attributes == []))
    end

    test ":friendly_name and :local_key_id", %{p12: p12} do
      back = round_trip(p12, @pw, [friendly_name: "Chave de ação ✓", local_key_id: "id"] ++ @fast)
      [leaf, ca, key] = back.bags

      for bag <- [leaf, key] do
        assert bag.friendly_name == "Chave de ação ✓"
        assert bag.local_key_id == "id"
      end

      assert ca.friendly_name == nil
    end

    test "key records of :public_key" do
      records = [
        key("rsa"),
        key("ec"),
        :public_key.generate_key({:rsa, 1024, 65_537}),
        :public_key.generate_key({:namedCurve, :secp384r1}),
        :public_key.generate_key({:namedCurve, :ed25519})
      ]

      for record <- records do
        back = round_trip(%{private_key: record}, @pw, @fast)
        assert back.private_key == :public_key.der_encode(:PrivateKeyInfo, record)
      end
    end

    test "a key alone" do
      der = :public_key.der_encode(:PrivateKeyInfo, key("ec"))
      back = round_trip(%{private_key: der}, @pw, @fast)
      assert back.private_key == der
      assert back.certificate == nil
      assert [%Bag{local_key_id: nil}] = back.bags
    end

    test "certificates alone" do
      certs = [cert_der("rsa"), cert_der("ca")]
      back = round_trip(%{ca_certificates: certs}, @pw, @fast)
      assert back.private_key == nil
      assert back.ca_certificates == certs
      assert back.info.encryption != []
    end

    test "a certificate without its key reads back as any other" do
      back = round_trip(%{certificate: cert_der("rsa")}, @pw, friendly_name: "x", iterations: 1)
      assert back.ca_certificates == [cert_der("rsa")]
      assert [%Bag{friendly_name: "x", local_key_id: nil}] = back.bags
    end

    test "nothing at all" do
      back = round_trip(%{}, @pw, @fast)
      assert back.private_key == nil and back.ca_certificates == [] and back.bags == []
    end

    test "a file in an old format, written again in the modern one" do
      for file <- ["o3_legacy.p12", "java_legacy.p12", "lre_default.p12", "o3_rc2_128.p12"] do
        old = PKCS12.decode!(read!(file), @pw)
        back = round_trip(old, @pw, [])
        assert same_content?(back, old), file
        assert [%{cipher: :aes_256_cbc}] = back.info.encryption
      end
    end

    test "the output is DER, down to the contents of the data parts", %{p12: p12} do
      opts = [key_encryption: :none, certificate_encryption: :none, friendly_name: "n"]
      pfx = PKCS12.encode!(p12, @pw, opts)
      assert_der(pfx)

      {:ok, {0x30, [_, {0x30, [_, {0xA0, [{0x04, auth_safe}]}]}, _]}} = DER.decode(pfx)
      assert_der(auth_safe)
      {:ok, {0x30, parts}} = DER.decode(auth_safe)

      for {0x30, [_data, {0xA0, [{0x04, safe_contents}]}]} <- parts do
        assert_der(safe_contents)
        {:ok, {0x30, bags}} = DER.decode(safe_contents)

        # SET OF sorted by encoding.
        for {0x30, [_, _, {0x31, attributes}]} <- bags do
          encoded = Enum.map(attributes, &DER.encode/1)
          assert encoded == Enum.sort(encoded)
        end
      end

      assert_der(PKCS12.encode!(p12, @pw, @fast))
    end
  end

  describe "passwords" do
    test "nil is the empty password", %{p12: p12} do
      {:ok, pfx} = PKCS12.encode(p12, nil, @fast)
      assert same_content?(PKCS12.decode!(pfx, ""), p12)
      assert same_content?(PKCS12.decode!(pfx, nil), p12)
      assert PKCS12.decode!(pfx, "").info.password_encoding == :unicode
    end

    test "non-ASCII passwords, in the standard forms", %{p12: p12} do
      for opts <- [[], [profile: :legacy], [mac: :pbmac1]] do
        back = round_trip(p12, "Senha-ção ✓", opts ++ @fast)
        assert same_content?(back, p12)
        assert back.info.password_encoding == :unicode
      end
    end

    test "a wrong password does not read", %{p12: p12} do
      {:ok, pfx} = PKCS12.encode(p12, @pw, @fast)
      assert {:error, %Error{reason: :invalid_password}} = PKCS12.decode(pfx, "wrong")
    end

    test "a password that is not UTF-8 is refused without showing it", %{p12: p12} do
      error = assert_raise ArgumentError, fn -> PKCS12.encode(p12, <<"s3cr3t", 0xFF>>) end
      refute Exception.message(error) =~ "s3cr3t"
    end
  end

  describe "invalid input" do
    test "keys" do
      pkcs1 = :public_key.der_encode(:RSAPrivateKey, key("rsa"))

      for bad <- ["", "not DER", pkcs1, cert_der("rsa"), {:RSAPrivateKey, :bad}, {}, 42, [1]] do
        assert {:error, %Error{reason: {:invalid_input, :private_key}}} =
                 PKCS12.encode(%{private_key: bad}, @pw, @fast),
               inspect(bad)
      end
    end

    test "certificates" do
      key_der = :public_key.der_encode(:PrivateKeyInfo, key("rsa"))

      for bad <- ["", "not DER", key_der, 42] do
        assert {:error, %Error{reason: {:invalid_input, :certificate}}} =
                 PKCS12.encode(%{certificate: bad}, @pw, @fast)
      end

      for bad <- [[cert_der("ca"), "x"], [nil], cert_der("ca"), :all] do
        assert {:error, %Error{reason: {:invalid_input, :ca_certificates}}} =
                 PKCS12.encode(%{ca_certificates: bad}, @pw, @fast)
      end
    end

    test "messages" do
      for field <- [:private_key, :certificate, :ca_certificates] do
        message = Exception.message(%Error{reason: {:invalid_input, field}})
        refute message =~ "PKCS#12 error"
      end
    end

    test "encode! raises" do
      assert_raise Error, ~r/private key/, fn -> PKCS12.encode!(%{private_key: "x"}, @pw) end
      assert is_binary(PKCS12.encode!(%{}, @pw, @fast))
    end

    test "not a map" do
      assert_raise ArgumentError, ~r/map/, fn -> PKCS12.encode("pfx", @pw) end
      assert_raise ArgumentError, ~r/password/, fn -> PKCS12.encode(%{}, ~c"pw") end
    end
  end

  describe "options" do
    test "invalid values" do
      bad = [
        [profile: :fast],
        [key_encryption: :rc2_40_cbc],
        [key_encryption: :aes_256_gcm],
        [key_encryption: false],
        [certificate_encryption: :rc4_128],
        [mac: :md5],
        [mac: :sha1],
        [iterations: 0],
        [iterations: 1.5],
        [friendly_name: <<0xFF>>],
        [friendly_name: :name],
        [local_key_id: ""],
        [unknown: 1]
      ]

      for opts <- bad do
        assert_raise ArgumentError, fn -> PKCS12.encode(%{}, @pw, opts) end
      end
    end
  end

  property "what is written reads back the same" do
    material = %{
      "rsa" => {:public_key.der_encode(:PrivateKeyInfo, key("rsa")), cert_der("rsa")},
      "ec" => {:public_key.der_encode(:PrivateKeyInfo, key("ec")), cert_der("ec")}
    }

    check all name <- member_of(Map.keys(material)),
              with_key <- boolean(),
              with_cert <- boolean(),
              # Without a localKeyId, the decoder pairs a key with a certificate
              # by its public key; the CA certificate matches neither key.
              cas <- list_of(constant(cert_der("ca")), max_length: 3),
              password <- one_of([constant(nil), string(:printable, max_length: 20)]),
              profile <- member_of([:modern, :legacy]),
              key_encryption <- member_of([nil, :aes_128_cbc, :des_ede3_cbc, :none]),
              certificate_encryption <- member_of([nil, :aes_192_cbc, :rc2_40_cbc, :none]),
              mac <- member_of([nil, :sha, :sha384, :pbmac1, :none]),
              iterations <- integer(1..20),
              friendly_name <- one_of([constant(nil), string(:printable, max_length: 10)]),
              max_runs: 100 do
      {key, cert} = Map.fetch!(material, name)

      input = %{
        private_key: if(with_key, do: key),
        certificate: if(with_cert, do: cert),
        ca_certificates: cas
      }

      opts = [
        profile: profile,
        key_encryption: key_encryption,
        certificate_encryption: certificate_encryption,
        mac: mac,
        iterations: iterations,
        friendly_name: friendly_name
      ]

      back = round_trip(input, password, opts)
      assert back.private_key == input.private_key

      if with_key do
        assert back.certificate == input.certificate
        assert back.ca_certificates == cas
      else
        assert back.ca_certificates == List.wrap(input.certificate) ++ cas
      end
    end
  end

  defp assert_der(bin) do
    {:ok, element} = DER.decode(bin)
    assert DER.encode(element) == bin
  end
end
