defmodule PKCS12.DERTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias PKCS12.DER

  describe "decode/1" do
    test "primitive and constructed elements" do
      assert DER.decode(<<0x04, 3, "abc">>) == {:ok, {0x04, "abc"}}
      assert DER.decode(<<0x30, 0>>) == {:ok, {0x30, []}}

      assert DER.decode(<<0x30, 6, 0x02, 1, 3, 0x04, 1, "x">>) ==
               {:ok, {0x30, [{0x02, <<3>>}, {0x04, "x"}]}}
    end

    test "long-form lengths" do
      content = :binary.copy("a", 300)
      assert DER.decode(<<0x04, 0x82, 300::16, content::binary>>) == {:ok, {0x04, content}}
      assert DER.decode(<<0x04, 0x81, 1, "a">>) == {:ok, {0x04, "a"}}
    end

    test "indefinite lengths (BER)" do
      assert DER.decode(<<0x30, 0x80, 0x04, 1, "a", 0x30, 0x80, 0, 0, 0, 0>>) ==
               {:ok, {0x30, [{0x04, "a"}, {0x30, []}]}}
    end

    test "rejects what PKCS#12 does not use or a reader cannot trust" do
      for bin <- [
            <<>>,
            # truncated
            <<0x04, 5, "abc">>,
            <<0x30, 0x80, 0x04, 1, "a">>,
            <<0x04, 0x82, 1>>,
            # trailing data
            <<0x04, 1, "a", 0>>,
            # indefinite length on a primitive
            <<0x04, 0x80, "a", 0, 0>>,
            # length of more than 4 bytes
            <<0x04, 0x85, 0, 0, 0, 0, 1, "a">>,
            # reserved length octet
            <<0x04, 0xFF, "a">>,
            # high tag number form
            <<0x1F, 0x81, 0x01, 0>>,
            # children that do not fill the parent
            <<0x30, 3, 0x04, 2, "a">>
          ] do
        assert DER.decode(bin) == {:error, :malformed}, inspect(bin)
      end
    end

    test "limits the nesting depth" do
      nested = fn depth ->
        Enum.reduce(1..depth, <<0x05, 0>>, fn _, acc -> <<0x30, 0x80>> <> acc <> <<0, 0>> end)
      end

      assert {:ok, _} = DER.decode(nested.(32))
      assert DER.decode(nested.(33)) == {:error, :malformed}
      assert DER.decode(nested.(100_000)) == {:error, :malformed}
    end

    test "primitive values are sub-binaries of the input" do
      # Large enough to be a reference-counted binary, not a heap binary.
      content = :binary.copy("a", 100)
      bin = <<0x30, 102, 0x04, 100, content::binary>>
      {:ok, {0x30, [{0x04, value}]}} = DER.decode(bin)
      assert value == content
      assert :binary.referenced_byte_size(value) == byte_size(bin)
    end
  end

  describe "octets/2" do
    test "the primitive form, universal or implicit" do
      assert DER.octets({0x04, "abc"}, 0x04) == {:ok, "abc"}
      assert DER.octets({0x80, "abc"}, 0x80) == {:ok, "abc"}
    end

    test "the constructed form, nested segments included" do
      segments = [{0x04, "ab"}, {0x24, [{0x04, "c"}, {0x04, ""}]}, {0x04, "d"}]
      assert DER.octets({0x24, segments}, 0x04) == {:ok, "abcd"}
      assert DER.octets({0xA0, segments}, 0x80) == {:ok, "abcd"}
    end

    test "rejects other elements and segments" do
      assert DER.octets({0x02, "a"}, 0x04) == {:error, :malformed}
      assert DER.octets({0x80, "a"}, 0x04) == {:error, :malformed}
      assert DER.octets({0x24, [{0x02, "a"}]}, 0x04) == {:error, :malformed}
      assert DER.octets({0x24, [{0x80, "a"}]}, 0x04) == {:error, :malformed}
    end
  end

  describe "uint/1" do
    test "non-negative integers up to 64 bits" do
      assert DER.uint({0x02, <<0>>}) == {:ok, 0}
      assert DER.uint({0x02, <<2048::16>>}) == {:ok, 2048}
      assert DER.uint({0x02, <<0, 0xFF>>}) == {:ok, 255}

      assert DER.uint({0x02, <<0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>}) ==
               {:ok, 0x7FFF_FFFF_FFFF_FFFF}
    end

    test "rejects negative, empty, too large or other elements" do
      for element <- [
            {0x02, <<0x80>>},
            {0x02, <<>>},
            {0x02, <<0, 1, 2, 3, 4, 5, 6, 7, 8>>},
            {0x04, <<1>>},
            {0x22, []}
          ] do
        assert DER.uint(element) == {:error, :malformed}, inspect(element)
      end
    end
  end

  describe "encode/1" do
    test "short and long lengths" do
      assert DER.encode({0x04, "abc"}) == <<0x04, 3, "abc">>

      assert DER.encode({0x04, :binary.copy("a", 128)}) ==
               <<0x04, 0x81, 128>> <> :binary.copy("a", 128)

      assert DER.encode({0x30, [{0x02, <<1>>}]}) == <<0x30, 3, 0x02, 1, 1>>
    end

    property "decode/1 reads back what encode/1 writes" do
      check all element <- element() do
        assert DER.decode(DER.encode(element)) == {:ok, element}
      end
    end
  end

  # Elements with low tag numbers, at most a few levels deep.
  defp element do
    tree(primitive(), fn child ->
      gen(all id <- tag(), children <- list_of(child, max_length: 4), do: {id ||| 0x20, children})
    end)
  end

  defp primitive do
    gen(all id <- tag(), value <- binary(max_length: 300), do: {id, value})
  end

  # Class in the top two bits, constructed bit clear, tag number below 31.
  defp tag do
    gen(
      all class <- member_of([0x00, 0x40, 0x80, 0xC0]),
          number <- integer(0..30),
          do: class ||| number
    )
  end
end
