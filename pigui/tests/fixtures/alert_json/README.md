# alert_json fixtures

These fixtures follow the field selection PIGUI requests from Snort's
`alert_json` logger:

```text
seconds gid sid rev priority class msg proto src_addr src_port dst_addr dst_port
action app_id service rule dir pkt_num
```

`valid.jsonl` includes IPv4, IPv6, TCP, UDP, a duplicate alert, and an alert
with only the required fields. `malformed.jsonl` exercises parser resilience.

No packet capture exists in this tree yet, so the values are schema-derived.
A later phase should add a capture script that produces fixtures from a real
pcap run.
