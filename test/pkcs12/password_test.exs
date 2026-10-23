defmodule PKCS12.PasswordTest do
  use ExUnit.Case, async: true

  alias PKCS12.Password

  defp forms(password) do
    for candidate <- Password.candidates(password) do
      {candidate.encoding, Password.bmp(candidate), Password.raw(candidate)}
    end
  end

  test "ASCII: the BMPString of RFC 7292 only" do
    assert forms("Beavis") == [
             {:unicode, <<0, ?B, 0, ?e, 0, ?a, 0, ?v, 0, ?i, 0, ?s, 0, 0>>, "Beavis"}
           ]
  end

  test "empty: the terminator alone, then no bytes at all" do
    assert forms("") == [{:unicode, <<0, 0>>, ""}, {:null, <<>>, ""}]
  end

  test "non-ASCII: UTF-16, then one character per byte" do
    assert forms("ç") == [
             {:unicode, <<0, 0xE7, 0, 0>>, "ç"},
             {:latin1, <<0, 0xC3, 0, 0xA7, 0, 0>>, "ç"}
           ]
  end

  test "characters outside the BMP become surrogate pairs" do
    assert [{:unicode, <<0xD8, 0x3D, 0xDE, 0x00, 0, 0>>, _} | _] = forms("😀")
  end

  test "bytes that are not UTF-8: one character per byte only" do
    assert forms(<<0xE7>>) == [{:latin1, <<0, 0xE7, 0, 0>>, <<0xE7>>}]
  end

  test "inspect/1 shows no secret" do
    for candidate <- Password.candidates("hunter2-çã") do
      text = inspect(candidate, limit: :infinity, printable_limit: :infinity)
      refute text =~ "hunter2"
      refute text =~ "104, 117, 110"
      refute text =~ "0, 104, 0, 117"
    end
  end
end
