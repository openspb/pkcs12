defmodule PKCS12.Fixtures do
  @moduledoc false
  # Access to test/fixtures (made by gen_fixtures.sh) and transformations of
  # the files that no generator produces.

  alias PKCS12.{DER, OID}

  @dir Path.expand("../fixtures", __DIR__)

  def path(name), do: Path.join(@dir, name)
  def read!(name), do: File.read!(path(name))

  @doc "A certificate of the material, in DER."
  def cert_der(name) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(read!(name <> ".crt"))
    der
  end

  @doc "A key of the material, decoded, to compare without depending on the encoding."
  def key(name) do
    [entry] = :public_key.pem_decode(read!(name <> ".key"))
    :public_key.pem_entry_decode(entry)
  end

  @data OID.encode("1.2.840.113549.1.7.1")
  @local_key_id OID.encode("1.2.840.113549.1.9.21")

  @doc """
  Re-encodes in BER: indefinite lengths in every constructed element and long
  OCTET STRINGs split in segments. With `deep: true` it also goes into the
  content of `data` ContentInfos (AuthenticatedSafe and SafeContents), which
  breaks the MAC; use it with files without one.
  """
  def to_ber(der, opts \\ []) do
    {:ok, element} = DER.decode(der)
    ber(element, Keyword.get(opts, :deep, false))
  end

  defp ber({0x30, [{0x06, @data} = oid, {0xA0, [{0x04, inner}]}]}, true = deep) do
    {:ok, element} = DER.decode(inner)
    content = ber(element, deep)
    indefinite(0x30, [DER.encode(oid), indefinite(0xA0, [segments(0x24, content)])])
  end

  defp ber({id, children}, deep) when is_list(children),
    do: indefinite(id, Enum.map(children, &ber(&1, deep)))

  defp ber({0x04, bin}, _deep) when byte_size(bin) > 32, do: segments(0x24, bin)
  defp ber({0x80, bin}, _deep) when byte_size(bin) > 32, do: segments(0xA0, bin)
  defp ber(element, _deep), do: DER.encode(element)

  defp indefinite(id, parts), do: IO.iodata_to_binary([id, 0x80, parts, 0, 0])

  defp segments(id, bin) do
    parts = for <<part::binary-size(40) <- bin>>, do: DER.encode({0x04, part})
    tail = rem(byte_size(bin), 40)

    last =
      if tail > 0,
        do: [DER.encode({0x04, binary_part(bin, byte_size(bin) - tail, tail)})],
        else: []

    indefinite(id, parts ++ last)
  end

  @doc """
  Applies `fun` to every SafeBag element of a file with neither encryption
  nor MAC, and encodes the result again. `fun` returns the new bag.
  """
  def map_bags(der, fun) do
    {:ok, {0x30, [version, {0x30, [oid, {0xA0, [{0x04, auth_safe}]}]}]}} = DER.decode(der)
    {:ok, {0x30, content_infos}} = DER.decode(auth_safe)

    content_infos =
      for {0x30, [{0x06, @data} = data, {0xA0, [{0x04, safe_contents}]}]} <- content_infos do
        {:ok, {0x30, bags}} = DER.decode(safe_contents)
        safe_contents = DER.encode({0x30, Enum.map(bags, fun)})
        {0x30, [data, {0xA0, [{0x04, safe_contents}]}]}
      end

    auth_safe = DER.encode({0x30, content_infos})
    DER.encode({0x30, [version, {0x30, [oid, {0xA0, [{0x04, auth_safe}]}]}]})
  end

  @doc "Removes the localKeyId attribute of a bag."
  def drop_local_key_id({0x30, [oid, value, {0x31, attributes}]}) do
    attributes = Enum.reject(attributes, &match?({0x30, [{0x06, @local_key_id} | _]}, &1))
    {0x30, [oid, value, {0x31, attributes}]}
  end

  def drop_local_key_id(bag), do: bag
end
