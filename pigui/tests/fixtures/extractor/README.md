# extractor fixtures

`live.jsonl` contains one JSON record for each PIGUI extractor service:
`conn`, `dns`, `ssl`, `http`, and `quic`. Records follow the field selection
defined in `config/snort/pigui.lua` and generated at runtime into
`var/snort/snort.lua`.

The daemon discriminates records by field presence because Snort's
`file_connector` does not add a service discriminator to text-format output.
