defmodule PKCS12.RC2 do
  @moduledoc false
  # RC2 (RFC 2268), for the files that encrypt their certificates with
  # pbeWithSHAAnd40BitRC2-CBC, as many older tools and the "legacy" mode of
  # the newer ones do. OpenSSL 3 only has RC2 in its "legacy" provider, which
  # is often missing, so `:crypto` cannot be relied on for it.
  #
  # In those files RC2 protects the certificates, which are public. Neither
  # speed nor resistance to side channels is a goal here.

  import Bitwise

  # PITABLE, from section 2 of the RFC.
  @pitable """
           D9 78 F9 C4 19 DD B5 ED 28 E9 FD 79 4A A0 D8 9D
           C6 7E 37 83 2B 76 53 8E 62 4C 64 88 44 8B FB A2
           17 9A 59 F5 87 B3 4F 13 61 45 6D 8D 09 81 7D 32
           BD 8F 40 EB 86 B7 7B 0B F0 95 21 22 5C 6B 4E 82
           54 D6 65 93 CE 60 B2 1C 73 56 C0 14 A7 8C F1 DC
           12 75 CA 1F 3B BE E4 D1 42 3D D4 30 A3 3C B6 26
           6F BF 0E DA 46 69 07 57 27 F2 1D 9B BC 94 43 03
           F8 11 C7 F6 90 EF 3E E7 06 C3 D5 2F C8 66 1E D7
           08 E8 EA DE 80 52 EE F7 84 AA 72 AC 35 4D 6A 2A
           96 1A D2 71 5A 15 49 74 4B 9F D0 5E 04 18 A4 EC
           C2 E0 41 6E 0F 51 CB CC 24 91 AF 50 A1 F4 70 39
           99 7C 3A 85 23 B8 B4 7A FC 02 36 5B 25 55 97 31
           2D 5D FA 98 E3 8A 92 AE 05 DF 29 10 67 6C BA C9
           D3 00 E6 CF E1 9E A8 2C 63 16 01 3F 58 E2 89 A9
           0D 38 34 1B AB 33 FF B0 BB 48 0C 5F B9 B1 CD 2E
           C5 F3 DB 47 E5 A5 9C 77 0A A6 20 68 FE 7F C1 AD
           """
           |> String.replace(~r/\s/, "")
           |> Base.decode16!()

  # Rotation amounts of the four words in MIX.
  @s {1, 2, 3, 5}

  @type key :: tuple()

  @doc """
  Decrypts in CBC mode, with no padding removed. `bits` is the effective key
  size (T1 in the RFC).
  """
  @spec decrypt_cbc(binary(), pos_integer(), <<_::64>>, binary()) :: binary()
  def decrypt_cbc(key, bits, <<_::binary-size(8)>> = iv, data)
      when rem(byte_size(data), 8) == 0 do
    k = expand(key, bits)

    {blocks, _} =
      Enum.map_reduce(blocks(data), iv, fn block, prev ->
        {:crypto.exor(decrypt_block(k, block), prev), block}
      end)

    IO.iodata_to_binary(blocks)
  end

  @doc """
  Encrypts in CBC mode, with no padding added. Only the tests use it.
  """
  @spec encrypt_cbc(binary(), pos_integer(), <<_::64>>, binary()) :: binary()
  def encrypt_cbc(key, bits, <<_::binary-size(8)>> = iv, data)
      when rem(byte_size(data), 8) == 0 do
    k = expand(key, bits)

    {blocks, _} =
      Enum.map_reduce(blocks(data), iv, fn block, prev ->
        out = encrypt_block(k, :crypto.exor(block, prev))
        {out, out}
      end)

    IO.iodata_to_binary(blocks)
  end

  defp blocks(data),
    do: for(i <- 0..(div(byte_size(data), 8) - 1)//1, do: binary_part(data, i * 8, 8))

  @doc """
  Key expansion (section 2 of the RFC): 64 words of 16 bits.
  """
  @spec expand(binary(), 1..1024) :: key()
  def expand(key, t1) when byte_size(key) in 1..128 and t1 in 1..1024 do
    t = byte_size(key)
    l = key |> :binary.bin_to_list() |> Enum.with_index() |> Map.new(fn {b, i} -> {i, b} end)
    l = Enum.reduce(t..127//1, l, fn i, l -> Map.put(l, i, pi(l[i - 1] + l[i - t] &&& 0xFF)) end)
    t8 = div(t1 + 7, 8)
    tm = 0xFF >>> (8 * t8 - t1)
    l = Map.put(l, 128 - t8, pi(l[128 - t8] &&& tm))

    l =
      Enum.reduce((127 - t8)..0//-1, l, fn i, l ->
        Map.put(l, i, pi(bxor(l[i + 1], l[i + t8])))
      end)

    List.to_tuple(for i <- 0..63, do: l[2 * i] + 256 * l[2 * i + 1])
  end

  defp pi(i), do: :binary.at(@pitable, i)

  @doc false
  @spec encrypt_block(key(), <<_::64>>) :: <<_::64>>
  def encrypt_block(k, <<r0::little-16, r1::little-16, r2::little-16, r3::little-16>>) do
    {r, j} = mix_rounds({r0, r1, r2, r3}, k, 0, 5)
    r = mash(r, k)
    {r, j} = mix_rounds(r, k, j, 6)
    r = mash(r, k)
    {r, _} = mix_rounds(r, k, j, 5)
    words(r)
  end

  @doc false
  @spec decrypt_block(key(), <<_::64>>) :: <<_::64>>
  def decrypt_block(k, <<r0::little-16, r1::little-16, r2::little-16, r3::little-16>>) do
    {r, j} = rmix_rounds({r0, r1, r2, r3}, k, 63, 5)
    r = rmash(r, k)
    {r, j} = rmix_rounds(r, k, j, 6)
    r = rmash(r, k)
    {r, _} = rmix_rounds(r, k, j, 5)
    words(r)
  end

  defp words({r0, r1, r2, r3}), do: <<r0::little-16, r1::little-16, r2::little-16, r3::little-16>>

  defp mix_rounds(r, _k, j, 0), do: {r, j}

  defp mix_rounds(r, k, j, n) do
    r = Enum.reduce(0..3, r, fn i, r -> mix(r, i, elem(k, j + i)) end)
    mix_rounds(r, k, j + 4, n - 1)
  end

  defp rmix_rounds(r, _k, j, 0), do: {r, j}

  defp rmix_rounds(r, k, j, n) do
    r = Enum.reduce(3..0//-1, r, fn i, r -> rmix(r, i, elem(k, j - (3 - i))) end)
    rmix_rounds(r, k, j - 4, n - 1)
  end

  # R[i-1], R[i-2] and R[i-3], with indices modulo 4.
  defp prev(r, i), do: {elem(r, rem(i + 3, 4)), elem(r, rem(i + 2, 4)), elem(r, rem(i + 1, 4))}

  defp mix(r, i, kj) do
    {a, b, c} = prev(r, i)
    x = elem(r, i) + kj + (a &&& b) + (bnot(a) &&& c) &&& 0xFFFF
    put_elem(r, i, rol(x, elem(@s, i)))
  end

  defp rmix(r, i, kj) do
    {a, b, c} = prev(r, i)
    x = ror(elem(r, i), elem(@s, i))
    put_elem(r, i, x - kj - (a &&& b) - (bnot(a) &&& c) &&& 0xFFFF)
  end

  defp mash(r, k) do
    Enum.reduce(0..3, r, fn i, r ->
      {a, _, _} = prev(r, i)
      put_elem(r, i, elem(r, i) + elem(k, a &&& 63) &&& 0xFFFF)
    end)
  end

  defp rmash(r, k) do
    Enum.reduce(3..0//-1, r, fn i, r ->
      {a, _, _} = prev(r, i)
      put_elem(r, i, elem(r, i) - elem(k, a &&& 63) &&& 0xFFFF)
    end)
  end

  defp rol(x, n), do: (x <<< n ||| x >>> (16 - n)) &&& 0xFFFF
  defp ror(x, n), do: (x >>> n ||| x <<< (16 - n)) &&& 0xFFFF
end
