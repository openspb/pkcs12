defmodule PKCS12.Encoder do
  @moduledoc false
  # Writes a PFX laid out as most tools do it, so that every reader finds
  # what it expects:
  #
  #   * the certificates, the key's first, in one part, encrypted unless
  #     asked otherwise (encryptedData);
  #   * the key in a plain data part, encrypted on its own
  #     (pkcs8ShroudedKeyBag), or not at all (keyBag);
  #   * the MAC over both.
  #
  # The key and its certificate share the same attributes: friendlyName and
  # localKeyId. The output is DER.

  alias PKCS12.{Decoder, DER, KDF, MAC, OID, Password, PBE}

  @data OID.encode("1.2.840.113549.1.7.1")
  @encrypted_data OID.encode("1.2.840.113549.1.7.6")

  @key_bag OID.encode("1.2.840.113549.1.12.10.1.1")
  @shrouded_key_bag OID.encode("1.2.840.113549.1.12.10.1.2")
  @cert_bag OID.encode("1.2.840.113549.1.12.10.1.3")

  @x509_certificate OID.encode("1.2.840.113549.1.9.22.1")
  @friendly_name OID.encode("1.2.840.113549.1.9.20")
  @local_key_id OID.encode("1.2.840.113549.1.9.21")

  @type opts :: %{
          key_encryption: PBE.writable() | :none,
          certificate_encryption: PBE.writable() | :none,
          mac: KDF.hash() | :pbmac1 | :none,
          iterations: pos_integer(),
          friendly_name: String.t() | nil,
          local_key_id: binary() | nil
        }

  @spec encode(map(), Password.t(), opts()) :: {:ok, binary()} | {:error, PKCS12.Error.reason()}
  def encode(input, password, opts) do
    with {:ok, key} <- private_key(Map.get(input, :private_key)),
         {:ok, certificate} <- certificate(Map.get(input, :certificate)),
         {:ok, ca_certificates} <- ca_certificates(Map.get(input, :ca_certificates) || []),
         attributes = attributes(opts.friendly_name, local_key_id(key, certificate, opts)),
         {:ok, certs} <-
           certificates_part(certificate, ca_certificates, attributes, password, opts),
         {:ok, keys} <- key_part(key, attributes, password, opts),
         auth_safe = DER.encode({0x30, certs ++ keys}),
         {:ok, mac_data} <- mac_data(opts.mac, password, opts.iterations, auth_safe) do
      {:ok, DER.encode({0x30, [DER.integer(3), data(auth_safe) | mac_data]})}
    end
  end

  ## Input

  # A PrivateKeyInfo in DER, or a key record of `:public_key`, which can
  # raise and also exit on what it cannot encode.
  defp private_key(nil), do: {:ok, nil}
  defp private_key(der) when is_binary(der), do: pkcs8(der)

  defp private_key(record) when is_tuple(record) do
    pkcs8(:public_key.der_encode(:PrivateKeyInfo, record))
  rescue
    _ -> invalid(:private_key)
  catch
    :exit, _ -> invalid(:private_key)
  end

  defp private_key(_other), do: invalid(:private_key)

  defp pkcs8(der) do
    case Decoder.private_key_info(der) do
      {:ok, der} -> {:ok, der}
      :error -> invalid(:private_key)
    end
  end

  defp certificate(nil), do: {:ok, nil}
  defp certificate(der), do: if(certificate?(der), do: {:ok, der}, else: invalid(:certificate))

  defp ca_certificates(certs) do
    if is_list(certs) and Enum.all?(certs, &certificate?/1),
      do: {:ok, certs},
      else: invalid(:ca_certificates)
  end

  # Only the shape of a Certificate:
  #   SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
  # The bytes are written as given.
  defp certificate?(der) when is_binary(der),
    do: match?({:ok, {0x30, [{0x30, _}, {0x30, _}, {0x03, _}]}}, DER.decode(der))

  defp certificate?(_other), do: false

  defp invalid(field), do: {:error, {:invalid_input, field}}

  ## Attributes

  # By default, the SHA-1 of the certificate, as OpenSSL writes it: any
  # value the key and the certificate share will do.
  defp local_key_id(_key, _certificate, %{local_key_id: id}) when is_binary(id), do: id

  defp local_key_id(key, certificate, _opts) when is_binary(key) and is_binary(certificate),
    do: :crypto.hash(:sha, certificate)

  defp local_key_id(_key, _certificate, _opts), do: nil

  # A SET OF in DER is sorted by the encoding of its elements.
  defp attributes(friendly_name, local_key_id) do
    [
      friendly_name && attribute(@friendly_name, {0x1E, bmp_string(friendly_name)}),
      local_key_id && attribute(@local_key_id, {0x04, local_key_id})
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.sort_by(&DER.encode/1)
  end

  defp attribute(oid, value), do: {0x30, [{0x06, oid}, {0x31, [value]}]}

  defp bmp_string(text), do: :unicode.characters_to_binary(text, :utf8, {:utf16, :big})

  ## Parts

  defp certificates_part(nil, [], _attributes, _password, _opts), do: {:ok, []}

  defp certificates_part(certificate, ca_certificates, attributes, password, opts) do
    leaf = if certificate, do: [cert_bag(certificate, attributes)], else: []
    bags = DER.encode({0x30, leaf ++ Enum.map(ca_certificates, &cert_bag(&1, []))})

    case opts.certificate_encryption do
      :none -> {:ok, [data(bags)]}
      cipher -> encrypted_data(cipher, password, opts.iterations, bags)
    end
  end

  defp key_part(nil, _attributes, _password, _opts), do: {:ok, []}

  defp key_part(key, attributes, _password, %{key_encryption: :none}) do
    {:ok, element} = DER.decode(key)
    {:ok, [data(DER.encode({0x30, [safe_bag(@key_bag, element, attributes)]}))]}
  end

  # EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData OCTET STRING }
  defp key_part(key, attributes, password, opts) do
    with {:ok, algorithm, encrypted} <-
           PBE.encrypt(opts.key_encryption, password, opts.iterations, key) do
      bag = safe_bag(@shrouded_key_bag, {0x30, [algorithm, {0x04, encrypted}]}, attributes)
      {:ok, [data(DER.encode({0x30, [bag]}))]}
    end
  end

  defp cert_bag(der, attributes),
    do:
      safe_bag(@cert_bag, {0x30, [{0x06, @x509_certificate}, {0xA0, [{0x04, der}]}]}, attributes)

  # SafeBag ::= SEQUENCE { bagId, bagValue [0] EXPLICIT, bagAttributes SET OF OPTIONAL }
  defp safe_bag(oid, value, []), do: {0x30, [{0x06, oid}, {0xA0, [value]}]}

  defp safe_bag(oid, value, attributes),
    do: {0x30, [{0x06, oid}, {0xA0, [value]}, {0x31, attributes}]}

  defp data(content), do: {0x30, [{0x06, @data}, {0xA0, [{0x04, content}]}]}

  # EncryptedData ::= SEQUENCE { version 0, EncryptedContentInfo }, whose
  # encryptedContent is [0] IMPLICIT OCTET STRING.
  defp encrypted_data(cipher, password, iterations, content) do
    with {:ok, algorithm, encrypted} <- PBE.encrypt(cipher, password, iterations, content) do
      info = {0x30, [{0x06, @data}, algorithm, {0x80, encrypted}]}
      {:ok, [{0x30, [{0x06, @encrypted_data}, {0xA0, [{0x30, [DER.integer(0), info]}]}]}]}
    end
  end

  defp mac_data(:none, _password, _iterations, _content), do: {:ok, []}

  defp mac_data(mac, password, iterations, content) do
    with {:ok, mac_data} <- MAC.build(mac, password, iterations, content), do: {:ok, [mac_data]}
  end
end
