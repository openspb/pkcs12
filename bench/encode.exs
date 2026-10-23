# Time of PKCS12.encode/3 for an RSA key, its certificate and a CA.
#
#     mix run bench/encode.exs
#
# Each case runs for about a second; the median and the 99th percentile of
# the calls are shown, in milliseconds.

dir = Path.expand("../test/fixtures", __DIR__)
p12 = PKCS12.decode!(File.read!(Path.join(dir, "o3_default.p12")), "test-password")

cases = [
  {[], "modern (default): AES-256, 100,000"},
  {[iterations: 2048], "modern, 2,048"},
  {[mac: :pbmac1], "modern with PBMAC1, 100,000"},
  {[profile: :legacy], "legacy: RC2-40 + 3DES, 2,048"},
  {[key_encryption: :none, certificate_encryption: :none, mac: :none], "nothing protected"}
]

IO.puts(
  "OTP #{System.otp_release()}, Elixir #{System.version()}, #{elem(hd(:crypto.info_lib()), 2)}\n"
)

IO.puts(
  String.pad_trailing("options", 40) <>
    String.pad_leading("median", 10) <> String.pad_leading("p99", 10)
)

for {opts, label} <- cases do
  _ = PKCS12.encode!(p12, "test-password", opts)

  deadline = System.monotonic_time(:millisecond) + 1000

  times =
    Stream.repeatedly(fn ->
      {us, _} = :timer.tc(fn -> PKCS12.encode!(p12, "test-password", opts) end)
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
