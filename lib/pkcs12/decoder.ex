defmodule PKCS12.Decoder do
  @moduledoc false
  # Reads a PFX in phases, so that nothing expensive happens before the
  # cheap checks pass:
  #
  #   1. the structure: version, AuthenticatedSafe and MacData, with every
  #      iteration count checked against `:max_iterations`;
  #   2. the MAC, which also tells which form of the password is right;
  #   3. the encrypted parts and the shrouded keys.
  #
  # The key derivations of phases 2 and 3 are charged to a budget,
  # `:max_total_iterations`, carried in `ctx`, by the work they do: the
  # iteration count once per output block of the hash.

  alias PKCS12.{Bag, DER, MAC, OID, Password, PBE}

  @data OID.encode("1.2.840.113549.1.7.1")
  @signed_data OID.encode("1.2.840.113549.1.7.2")
  @enveloped_data OID.encode("1.2.840.113549.1.7.3")
  @encrypted_data OID.encode("1.2.840.113549.1.7.6")

  @key_bag OID.encode("1.2.840.113549.1.12.10.1.1")
  @shrouded_key_bag OID.encode("1.2.840.113549.1.12.10.1.2")
  @cert_bag OID.encode("1.2.840.113549.1.12.10.1.3")
  @safe_contents_bag OID.encode("1.2.840.113549.1.12.10.1.6")

  @x509_certificate OID.encode("1.2.840.113549.1.9.22.1")
  @friendly_name OID.encode("1.2.840.113549.1.9.20")
  @local_key_id OID.encode("1.2.840.113549.1.9.21")

  # safeContentsBag can nest; real files use one level, if any.
  @max_bag_depth 4

  @type opts :: %{
          max_iterations: pos_integer(),
          max_total_iterations: pos_integer(),
          verify_mac: boolean()
        }

  @spec decode(binary(), binary(), opts()) :: {:ok, PKCS12.t()} | {:error, PKCS12.Error.reason()}
  def decode(pfx, password, opts) do
    max = opts.max_iterations

    with {:ok, version, auth_safe, mac_data} <- pfx(pfx),
         :ok <- version(version),
         {:ok, content} <- auth_safe(auth_safe),
         {:ok, mac} <- mac(mac_data, max),
         {:ok, parts} <- parts(content, max),
         ctx = new_ctx(opts),
         candidates = Password.candidates(password),
         {:ok, candidates, mac_info, ctx} <- check_mac(mac, content, candidates, opts, ctx),
         {:ok, bags, chosen, ctx} <- open(parts, candidates, ctx) do
      # The password matters only if the MAC was checked or something decrypted.
      encoding = if ctx.verified or ctx.encryption != [], do: chosen.encoding

      info = %{
        mac: mac_info,
        encryption: ctx.encryption |> Enum.reverse() |> Enum.uniq(),
        password_encoding: encoding
      }

      {:ok, build(bags, info)}
    end
  end

  defp new_ctx(opts) do
    %{
      max_iterations: opts.max_iterations,
      max_total: opts.max_total_iterations,
      spent: 0,
      verified: false,
      encryption: []
    }
  end

  ## Phase 1: structure

  # PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData MacData OPTIONAL }
  defp pfx(pfx) do
    case DER.decode(pfx) do
      {:ok, {0x30, [version, auth_safe]}} -> {:ok, version, auth_safe, nil}
      {:ok, {0x30, [version, auth_safe, mac_data]}} -> {:ok, version, auth_safe, mac_data}
      _ -> {:error, :malformed}
    end
  end

  defp version(element) do
    case DER.uint(element) do
      {:ok, 3} -> :ok
      {:ok, other} -> {:error, {:unsupported_version, other}}
      error -> error
    end
  end

  defp auth_safe({0x30, [{0x06, @data}, {0xA0, [octets]}]}), do: DER.octets(octets, 0x04)

  defp auth_safe({0x30, [{0x06, @signed_data} | _]}),
    do: {:error, {:unsupported, :public_key_integrity}}

  defp auth_safe(_element), do: {:error, :malformed}

  defp mac(nil, _max), do: {:ok, nil}
  defp mac(mac_data, max), do: MAC.parse(mac_data, max)

  # AuthenticatedSafe ::= SEQUENCE OF ContentInfo
  defp parts(content, max) do
    case DER.decode(content) do
      {:ok, {0x30, content_infos}} -> map_ok(content_infos, &part(&1, max))
      _ -> {:error, :malformed}
    end
  end

  defp part({0x30, [{0x06, @data}, {0xA0, [octets]}]}, _max) do
    with {:ok, bin} <- DER.octets(octets, 0x04), do: {:ok, {:data, bin}}
  end

  # EncryptedData ::= SEQUENCE { version, EncryptedContentInfo, ... }
  # EncryptedContentInfo ::= SEQUENCE {
  #   contentType, contentEncryptionAlgorithm, encryptedContent [0] IMPLICIT OPTIONAL }
  defp part({0x30, [{0x06, @encrypted_data}, {0xA0, [encrypted_data]}]}, max) do
    with {0x30, [_version, {0x30, [_type, algorithm, content]} | _]} <- encrypted_data,
         {:ok, params} <- PBE.parse(algorithm, max),
         {:ok, data} <- DER.octets(content, 0x80) do
      {:ok, {:encrypted, params, data}}
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed}
    end
  end

  defp part({0x30, [{0x06, @enveloped_data} | _]}, _max),
    do: {:error, {:unsupported, :public_key_privacy}}

  defp part(_element, _max), do: {:error, :malformed}

  ## Phase 2: MAC

  defp check_mac(nil, _content, candidates, _opts, ctx), do: {:ok, candidates, nil, ctx}

  defp check_mac(mac, _content, candidates, %{verify_mac: false}, ctx),
    do: {:ok, candidates, MAC.describe(mac, false), ctx}

  defp check_mac(mac, content, candidates, _opts, ctx) do
    # PBMAC1 takes the raw password, the same in every candidate.
    tried = if MAC.password_form(mac) == :raw, do: Enum.take(candidates, 1), else: candidates

    with {:ok, password, ctx} <- find_mac_password(tried, mac, content, ctx) do
      # A raw password says nothing about the BMPString form, which the
      # legacy ciphers may still need.
      left = if MAC.password_form(mac) == :raw, do: candidates, else: [password]
      {:ok, left, MAC.describe(mac, true), %{ctx | verified: true}}
    end
  end

  defp find_mac_password([], _mac, _content, _ctx), do: {:error, :invalid_password}

  defp find_mac_password([password | rest], mac, content, ctx) do
    with {:ok, ctx} <- charge(ctx, MAC.cost(mac)) do
      case MAC.verify(mac, password, content) do
        :ok -> {:ok, password, ctx}
        :mismatch -> find_mac_password(rest, mac, content, ctx)
        {:error, _} = error -> error
      end
    end
  end

  ## Phase 3: decryption

  # Tries the candidates in order. Without a verified MAC, a candidate fails
  # when anything it decrypts is not well-formed.
  defp open(parts, [password | rest], ctx) do
    case open_with(parts, password, %{ctx | encryption: []}) do
      {:ok, bags, ctx} -> {:ok, bags, password, ctx}
      {:bad_decrypt, ctx} when rest != [] -> open(parts, rest, ctx)
      {:bad_decrypt, _ctx} -> {:error, :invalid_password}
      {:error, _} = error -> error
    end
  end

  defp open_with(parts, password, ctx) do
    with {:ok, bags, ctx} <- map_reduce_ok(parts, ctx, &open_part(&1, password, &2)) do
      map_reduce_ok(List.flatten(bags), ctx, &open_bag(&1, password, &2))
    end
  end

  defp open_part({:data, bin}, _password, ctx) do
    with {:ok, bags} <- safe_contents(bin, ctx.max_iterations), do: {:ok, bags, ctx}
  end

  defp open_part({:encrypted, params, data}, password, ctx) do
    with {:ok, plain, ctx} <- decrypt(params, password, data, ctx) do
      case safe_contents(plain, ctx.max_iterations) do
        {:ok, bags} -> {:ok, bags, ctx}
        {:error, :malformed} when not ctx.verified -> {:bad_decrypt, ctx}
        {:error, _} = error -> error
      end
    end
  end

  defp open_bag(%Bag{value: {:shrouded, params, data}} = bag, password, ctx) do
    with {:ok, plain, ctx} <- decrypt(params, password, data, ctx) do
      case private_key_info(plain) do
        {:ok, der} -> {:ok, %{bag | value: der}, ctx}
        :error when not ctx.verified -> {:bad_decrypt, ctx}
        :error -> {:error, :malformed}
      end
    end
  end

  defp open_bag(bag, _password, ctx), do: {:ok, bag, ctx}

  defp decrypt(params, password, data, ctx) do
    with {:ok, ctx} <- charge(ctx, PBE.cost(params)) do
      ctx = %{ctx | encryption: [PBE.describe(params) | ctx.encryption]}

      case PBE.decrypt(params, password, data) do
        {:ok, plain} -> {:ok, plain, ctx}
        {:error, :bad_decrypt} -> {:bad_decrypt, ctx}
        {:error, _} = error -> error
      end
    end
  end

  defp charge(%{spent: spent, max_total: max} = ctx, iterations) do
    spent = spent + iterations

    if spent <= max,
      do: {:ok, %{ctx | spent: spent}},
      else: {:error, {:too_many_total_iterations, spent}}
  end

  ## SafeContents and SafeBags (no cryptography here)

  # Encrypted keys are left as `{:shrouded, params, data}`, for phase 3.
  defp safe_contents(bin, max) do
    case DER.decode(bin) do
      {:ok, {0x30, bags}} -> safe_bags(bags, max, 0)
      _ -> {:error, :malformed}
    end
  end

  defp safe_bags(_bags, _max, depth) when depth > @max_bag_depth, do: {:error, :malformed}

  defp safe_bags(bags, max, depth) do
    with {:ok, bags} <- map_ok(bags, &safe_bag(&1, max, depth)), do: {:ok, List.flatten(bags)}
  end

  # SafeBag ::= SEQUENCE { bagId, bagValue [0] EXPLICIT, bagAttributes SET OF OPTIONAL }
  defp safe_bag({0x30, [{0x06, oid}, {0xA0, [value]} | attributes]}, max, depth) do
    with {:ok, attributes} <- attributes(attributes) do
      bag_value(oid, value, attributes, max, depth)
    end
  end

  defp safe_bag(_element, _max, _depth), do: {:error, :malformed}

  defp bag_value(@key_bag, value, attributes, _max, _depth) do
    case private_key_info(value) do
      {:ok, der} -> bag(:private_key, der, @key_bag, attributes)
      :error -> {:error, :malformed}
    end
  end

  # EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData OCTET STRING }
  defp bag_value(@shrouded_key_bag, {0x30, [algorithm, data]}, attributes, max, _depth) do
    with {:ok, params} <- PBE.parse(algorithm, max),
         {:ok, data} <- DER.octets(data, 0x04) do
      bag(:private_key, {:shrouded, params, data}, @shrouded_key_bag, attributes)
    end
  end

  # CertBag ::= SEQUENCE { certId, certValue [0] EXPLICIT }
  defp bag_value(@cert_bag, {0x30, [{0x06, @x509_certificate}, {0xA0, [cert]}]}, attributes, _, _) do
    with {:ok, der} <- DER.octets(cert, 0x04),
         do: bag(:certificate, :binary.copy(der), @cert_bag, attributes)
  end

  defp bag_value(@safe_contents_bag, {0x30, bags}, _attributes, max, depth),
    do: safe_bags(bags, max, depth + 1)

  defp bag_value(@cert_bag, {0x30, [{0x06, @x509_certificate} | _]}, _, _, _),
    do: {:error, :malformed}

  # Certificates that are not X.509 (SDSI), CRLs, secrets and unknown bags
  # are passed on as they are.
  defp bag_value(oid, value, attributes, _max, _depth)
       when oid not in [@key_bag, @shrouded_key_bag, @safe_contents_bag] do
    bag(:other, DER.encode(value), oid, attributes)
  end

  defp bag_value(_oid, _value, _attributes, _max, _depth), do: {:error, :malformed}

  defp bag(type, value, oid, attributes) do
    case OID.decode(oid) do
      {:ok, dotted} ->
        {:ok, struct!(Bag, Map.merge(attributes, %{type: type, value: value, oid: dotted}))}

      :error ->
        {:error, :malformed}
    end
  end

  @doc """
  Checks a PrivateKeyInfo (or OneAsymmetricKey, its successor in RFC 5958):

      SEQUENCE { version INTEGER (0 or 1), privateKeyAlgorithm AlgorithmIdentifier,
                 privateKey OCTET STRING, ... }

  Checking the shape is enough to tell a decrypted key from garbage, and
  works for any key algorithm. The result is DER, in a binary of its own; a
  segmented (BER) privateKey is joined on the way. The encoder checks its
  input with it too.
  """
  @spec private_key_info(binary() | DER.element()) :: {:ok, binary()} | :error
  def private_key_info(bin) when is_binary(bin) do
    case DER.decode(bin) do
      {:ok, element} -> private_key_info(element)
      {:error, _} -> :error
    end
  end

  def private_key_info(
        {0x30, [{0x02, <<v>>} = version, {0x30, [{0x06, _} | _]} = alg, key | rest]}
      )
      when v in [0, 1] do
    case DER.octets(key, 0x04) do
      {:ok, key} -> {:ok, DER.encode({0x30, [version, alg, {0x04, key} | rest]})}
      {:error, _} -> :error
    end
  end

  def private_key_info(_element), do: :error

  # Attributes: SET OF SEQUENCE { attrId OID, attrValues SET OF ANY }
  defp attributes([]), do: {:ok, %{}}

  defp attributes([{0x31, attributes}]) do
    attributes
    |> Enum.reduce_while(%{attributes: []}, fn
      {0x30, [{0x06, @friendly_name}, {0x31, [{0x1E, name}]}]}, acc ->
        {:cont, Map.put(acc, :friendly_name, bmp_string(name))}

      {0x30, [{0x06, @local_key_id}, {0x31, [{0x04, id}]}]}, acc ->
        {:cont, Map.put(acc, :local_key_id, :binary.copy(id))}

      {0x30, [{0x06, oid}, {0x31, values}]}, acc ->
        case OID.decode(oid) do
          {:ok, dotted} ->
            attribute = {dotted, Enum.map(values, &DER.encode/1)}
            {:cont, Map.update!(acc, :attributes, &[attribute | &1])}

          :error ->
            {:halt, :error}
        end

      _other, _acc ->
        {:halt, :error}
    end)
    |> case do
      :error -> {:error, :malformed}
      acc -> {:ok, Map.update!(acc, :attributes, &Enum.reverse/1)}
    end
  end

  defp attributes(_other), do: {:error, :malformed}

  defp bmp_string(bin) do
    case :unicode.characters_to_binary(bin, {:utf16, :big}, :utf8) do
      name when is_binary(name) -> name
      _ -> nil
    end
  end

  ## Result

  defp build(bags, info) do
    keys = for %Bag{type: :private_key} = bag <- bags, do: bag
    certs = for %Bag{type: :certificate} = bag <- bags, do: bag

    case keys do
      [] ->
        %PKCS12{ca_certificates: Enum.map(certs, & &1.value), bags: bags, info: info}

      [key | _] ->
        leaf = leaf(key, certs)

        %PKCS12{
          private_key: key.value,
          certificate: leaf && leaf.value,
          ca_certificates: for(cert <- certs, cert != leaf, do: cert.value),
          bags: bags,
          info: info
        }
    end
  end

  # The certificate of the key: the one with the same localKeyId, or else the
  # one with the same public key.
  defp leaf(%Bag{local_key_id: id} = key, certs) do
    (id && Enum.find(certs, &(&1.local_key_id == id))) ||
      Enum.find(certs, &public_key_matches?(key.value, &1.value))
  end

  # `:public_key` can raise and also exit on malformed input.
  defp public_key_matches?(key_der, cert_der) do
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(cert_der, :otp)
    {:OTPSubjectPublicKeyInfo, _algorithm, cert_key} = elem(tbs, 7)

    case :public_key.der_decode(:PrivateKeyInfo, key_der) do
      {:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} -> cert_key == {:RSAPublicKey, n, e}
      {:ECPrivateKey, _, _, _, public, _} when is_binary(public) -> cert_key == {:ECPoint, public}
      _ -> false
    end
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  ## Helpers

  # Maps `fun` over `items` and stops at the first error.
  defp map_ok(items, fun) do
    items
    |> Enum.reduce_while([], fn item, acc ->
      case fun.(item) do
        {:ok, result} -> {:cont, [result | acc]}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:error, _} = error -> error
      results -> {:ok, Enum.reverse(results)}
    end
  end

  # Like `map_ok/2`, threading `ctx`. Stops at an error or at `:bad_decrypt`,
  # which carries the context so far (the budget spent must stay spent).
  defp map_reduce_ok(items, ctx, fun) do
    Enum.reduce_while(items, {:ok, [], ctx}, fn item, {:ok, acc, ctx} ->
      case fun.(item, ctx) do
        {:ok, result, ctx} -> {:cont, {:ok, [result | acc], ctx}}
        other -> {:halt, other}
      end
    end)
    |> case do
      {:ok, results, ctx} -> {:ok, Enum.reverse(results), ctx}
      other -> other
    end
  end
end
