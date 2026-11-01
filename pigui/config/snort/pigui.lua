-- PIGUI Snort overrides.
--
-- This file documents the telemetry shape. The daemon generates the active
-- copy under pigui/var/snort/ by copying the parent lua/ defaults and
-- appending these overrides. The parent lua/ tree is never edited in place.

alert_json =
{
    file = true,
    fields = 'seconds timestamp gid sid rev priority class msg proto src_addr src_port dst_addr dst_port action app_id service rule dir pkt_num',
}

dns = { publish_response = true }

file_connector =
{
    {
        connector = 'pigui_events',
        name = 'pigui',
        direction = 'transmit',
        text_format = true,
    },
}

extractor =
{
    formatting = 'json',
    connector = 'pigui_events',
    time = 'unix',
    default_filter = 'skip',
    protocols =
    {
        { service = 'conn', on_events = 'eof',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state duration orig_pkts resp_pkts orig_bytes resp_bytes' },
        { service = 'dns', on_events = 'response',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p proto query qtype_name rcode_name answers TTLs' },
        { service = 'ssl', on_events = 'tls_metadata_event',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p server_name version validation_status subject issuer' },
        { service = 'http', on_events = 'eot',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent status_code' },
        { service = 'quic', on_events = 'handshake',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p server_name client_protocol' },
    },
}

ips =
{
    variables = default_variables,
    enable_builtin_rules = true,
}
