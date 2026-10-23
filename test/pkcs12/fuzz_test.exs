defmodule PKCS12.FuzzTest do
  # Damaged and random input: decode/3 must return {:ok, _} or {:error, _},
  # never raise. FUZZ_ROUNDS sets the rounds per file (default 300).
  use ExUnit.Case, async: true
  use ExUnitProperties

  import PKCS12.Fixtures

  @rounds String.to_integer(System.get_env("FUZZ_ROUNDS", "300"))
  @files ~w(o3_default.p12 o3_legacy.p12 o3_pbmac1.p12 o3_nomac.p12 o3_noenc_nomac.p12
            lre_default.p12 py_best.p12 java_legacy.p12)

  @moduletag :fuzz
  @moduletag timeout: :infinity

  for file <- @files, verify <- [true, false] do
    test "#{file}, verify_mac: #{verify}" do
      bin = read!(unquote(file))
      :rand.seed(:exsss, {1, 2, byte_size(bin)})

      raised =
        for _ <- 1..@rounds,
            mutated = mutate(bin),
            message = raised(mutated, verify_mac: unquote(verify)),
            do: message

      assert raised == [], "#{length(raised)} exceptions, the first:\n#{List.first(raised)}"
    end
  end

  property "random binaries" do
    check all bin <- binary(), max_runs: @rounds do
      assert raised(bin) == nil
      assert raised(<<0x30, 0x80>> <> bin) == nil
    end
  end

  # nil, or the formatted exception.
  defp raised(bin, opts \\ []) do
    case PKCS12.decode(bin, "test-password", [max_iterations: 100_000] ++ opts) do
      {:ok, %PKCS12{}} -> nil
      {:error, %PKCS12.Error{}} -> nil
    end
  rescue
    e -> Exception.format(:error, e, __STACKTRACE__) |> String.slice(0, 800)
  end

  defp mutate(bin) do
    size = byte_size(bin)

    case :rand.uniform(5) do
      1 ->
        set(bin, :rand.uniform(size) - 1, :rand.uniform(256) - 1)

      2 ->
        binary_part(bin, 0, :rand.uniform(size) - 1)

      3 ->
        Enum.reduce(1..:rand.uniform(8), bin, fn _, acc ->
          set(acc, :rand.uniform(size) - 1, :rand.uniform(256) - 1)
        end)

      # length octets near the start, where the structure is
      4 ->
        set(bin, :rand.uniform(min(size, 200)) - 1, Enum.random([0x00, 0x80, 0x81, 0x84, 0xFF]))

      5 ->
        insert(bin, :rand.uniform(size) - 1, :crypto.strong_rand_bytes(:rand.uniform(4)))
    end
  end

  defp set(bin, pos, byte) do
    <<head::binary-size(pos), _, tail::binary>> = bin
    <<head::binary, byte, tail::binary>>
  end

  defp insert(bin, pos, extra) do
    <<head::binary-size(pos), tail::binary>> = bin
    head <> extra <> tail
  end
end
