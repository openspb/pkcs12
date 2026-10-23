# Time of PKCS12.decode/3 on the test files.
#
#     mix run bench/decode.exs
#
# Each file runs for about a second; the median and the 99th percentile of
# the calls are shown, in milliseconds.

dir = Path.expand("../test/fixtures", __DIR__)

files = [
  {"o3_default.p12", "test-password", "OpenSSL 3 default: PBES2 AES-256, 2,048"},
  {"o3_legacy.p12", "test-password", "OpenSSL legacy: RC2-40 + 3DES, 2,048"},
  {"o3_pbmac1.p12", "test-password", "PBMAC1, 2,048"},
  {"java_default.p12", "test-password", "Java default: PBES2 AES-256, 10,000"},
  {"py_best.p12", "test-password", "Python cryptography, best available"},
  {"o3_iter100k.p12", "test-password", "PBES2 AES-256, 100,000"},
  {"o3_legacy_100k.p12", "test-password", "OpenSSL legacy, 100,000"},
  {"java_legacy.p12", "test-password", "Java legacy: MAC 100,000, 50,000"},
  {"o3_default.p12", "wrong", "wrong password, 2,048"}
]

IO.puts(
  "OTP #{System.otp_release()}, Elixir #{System.version()}, #{elem(hd(:crypto.info_lib()), 2)}\n"
)

IO.puts(
  String.pad_trailing("file", 40) <>
    String.pad_leading("median", 10) <> String.pad_leading("p99", 10)
)

for {file, password, label} <- files do
  bin = File.read!(Path.join(dir, file))
  _ = PKCS12.decode(bin, password)

  deadline = System.monotonic_time(:millisecond) + 1000

  times =
    Stream.repeatedly(fn ->
      {us, _} = :timer.tc(fn -> PKCS12.decode(bin, password) end)
      us
    end)
    |> Enum.reduce_while([], fn us, acc ->
      if System.monotonic_time(:millisecond) < deadline,
        do: {:cont, [us | acc]},
        else: {:halt, [us | acc]}
    end)
    |> Enum.sort()

  at = fn q -> Enum.at(times, min(length(times) - 1, trunc(q * length(times)))) / 1000 end

  IO.puts(
    String.pad_trailing(label, 40) <>
      String.pad_leading(:erlang.float_to_binary(at.(0.5), decimals: 2), 10) <>
      String.pad_leading(:erlang.float_to_binary(at.(0.99), decimals: 2), 10)
  )
end
