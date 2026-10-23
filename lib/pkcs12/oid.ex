defmodule PKCS12.OID do
  @moduledoc false
  # Object identifiers are kept as the content octets of their DER encoding,
  # so the decoder can match them directly in function heads. The dotted form
  # is only built for error reasons.

  import Bitwise

  @doc """
  Content octets of a dotted OID. Meant for module attributes, at compile time.
  """
  @spec encode(String.t()) :: binary()
  def encode(dotted) do
    [a, b | rest] = dotted |> String.split(".") |> Enum.map(&String.to_integer/1)
    IO.iodata_to_binary(Enum.map([40 * a + b | rest], &base128(&1, [])))
  end

  defp base128(n, []), do: base128(n >>> 7, [n &&& 0x7F])
  defp base128(0, acc), do: acc
  defp base128(n, acc), do: base128(n >>> 7, [0x80 ||| (n &&& 0x7F) | acc])

  @doc """
  Dotted form of the content octets of an OID.
  """
  @spec decode(binary()) :: {:ok, String.t()} | :error
  def decode(octets) do
    case subidentifiers(octets, 0, []) do
      {:ok, [first | rest]} ->
        {a, b} =
          cond do
            first < 40 -> {0, first}
            first < 80 -> {1, first - 40}
            true -> {2, first - 80}
          end

        {:ok, Enum.map_join([a, b | rest], ".", &Integer.to_string/1)}

      _ ->
        :error
    end
  end

  defp subidentifiers(<<>>, 0, [_ | _] = acc), do: {:ok, Enum.reverse(acc)}

  # X.690 8.19.2: a subidentifier never starts with 0x80 (no padding).
  defp subidentifiers(<<0x80, _::binary>>, 0, _acc), do: :error

  defp subidentifiers(<<1::1, bits::7, rest::binary>>, n, acc),
    do: subidentifiers(rest, n <<< 7 ||| bits, acc)

  defp subidentifiers(<<0::1, bits::7, rest::binary>>, n, acc),
    do: subidentifiers(rest, 0, [n <<< 7 ||| bits | acc])

  defp subidentifiers(_, _, _), do: :error
end
