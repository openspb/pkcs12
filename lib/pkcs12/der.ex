defmodule PKCS12.DER do
  @moduledoc false
  # A small BER/DER reader for the structures of PKCS#12.
  #
  # Each element becomes `{id, value}`: `id` is the identifier octet (class,
  # constructed bit and tag number) and `value` is a binary for a primitive
  # element or a list of elements for a constructed one. Primitive values are
  # sub-binaries of the input, so reading copies nothing.
  #
  # BER is accepted where generators use it: indefinite lengths and
  # constructed (segmented) OCTET STRINGs. Tag numbers above 30 do not occur in
  # PKCS#12 and are rejected. Nesting is limited, so a hostile input cannot
  # make the reader recurse without bound.

  import Bitwise

  @max_depth 32

  @type element :: {byte(), binary() | [element()]}

  @doc """
  Reads one element that spans the whole binary.
  """
  @spec decode(binary()) :: {:ok, element()} | {:error, :malformed}
  def decode(bin) do
    case read(bin, 0) do
      {:ok, element, <<>>} -> {:ok, element}
      _ -> {:error, :malformed}
    end
  end

  defp read(_bin, depth) when depth > @max_depth, do: :error

  defp read(<<id, rest::binary>>, depth) when (id &&& 0x1F) != 0x1F do
    constructed? = (id &&& 0x20) != 0

    case read_length(rest) do
      {:definite, len, rest} when byte_size(rest) >= len ->
        content = binary_part(rest, 0, len)
        rest = binary_part(rest, len, byte_size(rest) - len)
        definite(id, constructed?, content, rest, depth)

      {:indefinite, rest} when constructed? ->
        with {:ok, children, rest} <- read_until_eoc(rest, depth + 1, []),
             do: {:ok, {id, children}, rest}

      _ ->
        :error
    end
  end

  defp read(_bin, _depth), do: :error

  defp definite(id, false, content, rest, _depth), do: {:ok, {id, content}, rest}

  defp definite(id, true, content, rest, depth) do
    with {:ok, children} <- read_all(content, depth + 1, []), do: {:ok, {id, children}, rest}
  end

  defp read_length(<<0x80, rest::binary>>), do: {:indefinite, rest}
  defp read_length(<<len, rest::binary>>) when len < 0x80, do: {:definite, len, rest}

  defp read_length(<<n, rest::binary>>) when n in 0x81..0x84 and byte_size(rest) >= n - 0x80 do
    size = n - 0x80
    len = :binary.decode_unsigned(binary_part(rest, 0, size))
    {:definite, len, binary_part(rest, size, byte_size(rest) - size)}
  end

  defp read_length(_), do: :error

  defp read_all(<<>>, _depth, acc), do: {:ok, Enum.reverse(acc)}

  defp read_all(bin, depth, acc) do
    case read(bin, depth) do
      {:ok, element, rest} -> read_all(rest, depth, [element | acc])
      :error -> :error
    end
  end

  defp read_until_eoc(<<0, 0, rest::binary>>, _depth, acc), do: {:ok, Enum.reverse(acc), rest}

  defp read_until_eoc(bin, depth, acc) when byte_size(bin) >= 2 do
    case read(bin, depth) do
      {:ok, element, rest} -> read_until_eoc(rest, depth, [element | acc])
      :error -> :error
    end
  end

  defp read_until_eoc(_bin, _depth, _acc), do: :error

  @doc """
  Content of an OCTET STRING. `id` is the identifier of the primitive form:
  `0x04` for a universal OCTET STRING, or the implicit tag that replaces it,
  such as `0x80` for `[0] IMPLICIT OCTET STRING`. The constructed form (BER)
  is accepted, and its segments are joined.
  """
  @spec octets(element(), byte()) :: {:ok, binary()} | {:error, :malformed}
  def octets({id, value}, id) when is_binary(value), do: {:ok, value}

  def octets({constructed, segments}, id)
      when constructed == (id ||| 0x20) and is_list(segments) do
    case join(segments, []) do
      {:ok, iodata} -> {:ok, IO.iodata_to_binary(iodata)}
      :error -> {:error, :malformed}
    end
  end

  def octets(_element, _id), do: {:error, :malformed}

  # Segments of a constructed string are universal OCTET STRINGs, themselves
  # primitive or constructed.
  defp join([], acc), do: {:ok, Enum.reverse(acc)}
  defp join([{0x04, part} | rest], acc) when is_binary(part), do: join(rest, [part | acc])

  defp join([{0x24, segments} | rest], acc) when is_list(segments) do
    with {:ok, parts} <- join(segments, []), do: join(rest, [parts | acc])
  end

  defp join(_segments, _acc), do: :error

  @doc """
  A non-negative INTEGER that fits in 64 bits.
  """
  @spec uint(element()) :: {:ok, non_neg_integer()} | {:error, :malformed}
  def uint({0x02, <<first, _::binary>> = bytes}) when first < 0x80 and byte_size(bytes) <= 8,
    do: {:ok, :binary.decode_unsigned(bytes)}

  def uint(_element), do: {:error, :malformed}

  @doc """
  Encodes an element in DER.
  """
  @spec encode(element()) :: binary()
  def encode(element), do: element |> to_iodata() |> IO.iodata_to_binary()

  defp to_iodata({id, value}) when is_binary(value),
    do: [id, encode_length(byte_size(value)), value]

  defp to_iodata({id, children}) when is_list(children) do
    content = Enum.map(children, &to_iodata/1)
    [id, encode_length(IO.iodata_length(content)), content]
  end

  defp encode_length(len) when len < 0x80, do: len

  defp encode_length(len) do
    bytes = :binary.encode_unsigned(len)
    [0x80 + byte_size(bytes), bytes]
  end
end
