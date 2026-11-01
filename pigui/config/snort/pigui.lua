-- PIGUI Snort overrides.
--
-- Phase 1 only documents the intended telemetry shape. This file is not
-- activated or generated yet; live Snort configuration is part of the next
-- milestone. PIGUI will own the generated copy under pigui/var/ and treat the
-- parent lua/ directory as a read-only source of defaults.

alert_json =
{
    file = true,
    fields = 'seconds timestamp gid sid rev priority class msg proto src_addr src_port dst_addr dst_port action app_id service rule dir pkt_num',
}

dns = { publish_response = true }

extractor =
{
    formatting = 'json',
    connector = 'pigui_extractor',
    time = 'unix',
    protocols =
    {
        { service = 'conn', on_events = 'eof',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state duration orig_pkts resp_pkts orig_bytes resp_bytes' },
        { service = 'dns', on_events = 'response',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto query qtype_name rcode_name answers TTLs' },
        { service = 'ssl', on_events = 'tls_metadata_event',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p server_name version validation_status subject issuer' },
        { service = 'http', on_events = 'eot',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent status_code' },
        { service = 'quic', on_events = 'handshake',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p server_name client_protocol' },
    },
}
