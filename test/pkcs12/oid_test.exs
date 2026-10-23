defmodule PKCS12.OIDTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias PKCS12.OID

  test "known encodings" do
    assert OID.encode("1.2.840.113549.1.7.1") ==
             <<0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01>>

    assert OID.encode("2.16.840.1.101.3.4.1.42") ==
             <<0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A>>

    assert OID.encode("2.999.3") == <<0x88, 0x37, 0x03>>
  end

  test "decode/1 splits the first subidentifier in two arcs" do
    assert OID.decode(<<0x2A, 0x86, 0x48>>) == {:ok, "1.2.840"}
    assert OID.decode(<<0x00>>) == {:ok, "0.0"}
    assert OID.decode(<<0x4F>>) == {:ok, "1.39"}
    assert OID.decode(<<0x50>>) == {:ok, "2.0"}
    assert OID.decode(<<0x88, 0x37, 0x03>>) == {:ok, "2.999.3"}
  end

  test "decode/1 rejects malformed content" do
    for bin <- [<<>>, <<0x86>>, <<0x2A, 0x86>>, <<0x2A, 0x80, 0x01>>, <<0x80, 0x2A>>] do
      assert OID.decode(bin) == :error, inspect(bin)
    end
  end

  property "decode/1 reads back what encode/1 writes" do
    check all first <- integer(0..2),
              second <- if(first < 2, do: integer(0..39), else: integer(0..100_000)),
              rest <- list_of(integer(0..0xFFFF_FFFF_FFFF), max_length: 10) do
      dotted = Enum.join([first, second | rest], ".")
      assert OID.decode(OID.encode(dotted)) == {:ok, dotted}
    end
  end
end
