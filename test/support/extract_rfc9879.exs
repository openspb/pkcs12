# Extracts the test vectors of RFC 9879, appendix A, into test/fixtures.
#
#     curl -sO https://www.rfc-editor.org/rfc/rfc9879.txt
#     elixir test/support/extract_rfc9879.exs rfc9879.txt
#
# Each section A.n holds one base64 file, split across lines and sometimes
# across a page break; only the lines made of base64 characters are kept.

[rfc] = System.argv()
out = Path.expand("../fixtures", __DIR__)
text = File.read!(rfc)

sections =
  Regex.scan(~r/^A\.(\d)\.  .*?(?=^A\.\d\.  |^Appendix B)/ms, text)
  |> Enum.map(fn [section, n] -> {n, section} end)

6 = length(sections)

for {n, section} <- sections do
  base64 =
    section
    |> String.split("\n")
    |> Enum.filter(&Regex.match?(~r|^   [A-Za-z0-9+/=]{4,}$|, &1))
    |> Enum.map_join(&String.trim/1)

  path = Path.join(out, "rfc9879_a#{n}.p12")
  File.write!(path, Base.decode64!(base64))
  IO.puts("#{path}: #{File.stat!(path).size} bytes")
end
