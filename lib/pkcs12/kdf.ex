defmodule PKCS12.KDF do
  @moduledoc false
  # The key derivation of PKCS#12 (RFC 7292, appendix B.2), used by the
  # pbeWithSHAAnd... ciphers and by the classic MAC.
  #
  # The loop over the iterations is plain Elixir, one `:crypto.hash/2` per
  # step, so a long derivation is preempted like any other process and does
  # not hold a scheduler.

  @purposes %{key: 1, iv: 2, mac: 3}

  # {u, v}: output size and block size of the hash, in bytes.
  @sizes %{
    sha: {20, 64},
    sha224: {28, 64},
    sha256: {32, 64},
    sha384: {48, 128},
    sha512: {64, 128}
  }

  @type hash :: :sha | :sha224 | :sha256 | :sha384 | :sha512

  @doc """
  Derives `n` bytes. `password` is already in the format of appendix B.1
  (BMPString with its terminator).
  """
  @spec derive(hash(), binary(), binary(), pos_integer(), :key | :iv | :mac, pos_integer()) ::
          binary()
  def derive(hash, password, salt, iterations, purpose, n) do
    {u, v} = Map.fetch!(@sizes, hash)
    d = :binary.copy(<<Map.fetch!(@purposes, purpose)>>, v)
    i = fill(salt, v) <> fill(password, v)

    blocks(hash, d, i, iterations, v, div(n + u - 1, u), [])
    |> IO.iodata_to_binary()
    |> binary_part(0, n)
  end

  @doc """
  How many output blocks of `hash` make `n` bytes. A derivation costs its
  iteration count once per block, in PBKDF2 as in this KDF.
  """
  @spec blocks(hash(), pos_integer()) :: pos_integer()
  def blocks(hash, n), do: div(n + hash_size(hash) - 1, hash_size(hash))

  @doc """
  Output size of the hash, in bytes.
  """
  @spec hash_size(hash()) :: pos_integer()
  def hash_size(hash), do: elem(Map.fetch!(@sizes, hash), 0)

  defp blocks(_hash, _d, _i, _iterations, _v, 0, acc), do: Enum.reverse(acc)

  defp blocks(hash, d, i, iterations, v, count, acc) do
    a = iterate(hash, :crypto.hash(hash, [d, i]), iterations - 1)
    i = if count > 1, do: add_blocks(i, fill(a, v), v), else: i
    blocks(hash, d, i, iterations, v, count - 1, [a | acc])
  end

  defp iterate(_hash, digest, 0), do: digest
  defp iterate(hash, digest, n), do: iterate(hash, :crypto.hash(hash, digest), n - 1)

  # Repeats `x` up to a multiple of v bytes; empty stays empty.
  defp fill(<<>>, _v), do: <<>>

  defp fill(x, v) do
    len = v * div(byte_size(x) + v - 1, v)
    binary_part(:binary.copy(x, div(len, byte_size(x)) + 1), 0, len)
  end

  # I_j = (I_j + B + 1) mod 2^(8v), for each block of v bytes of I.
  defp add_blocks(i, b, v) do
    b = :binary.decode_unsigned(b) + 1
    bits = v * 8

    for j <- 0..(div(byte_size(i), v) - 1)//1, into: <<>> do
      block = :binary.decode_unsigned(binary_part(i, j * v, v))
      <<block + b::unsigned-size(bits)>>
    end
  end
end
