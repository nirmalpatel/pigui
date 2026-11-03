use std::net::IpAddr;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use pigui_core::error::{Error, Result};

pub const BLOCK_ANCHOR: &str = "com.apple/000.pigui";
pub const ALLOW_ANCHOR: &str = "com.apple/300.pigui.allow";
pub const DYNAMIC_BLOCK4_IN_TABLE: &str = "pigui_block4_in";
pub const DYNAMIC_BLOCK4_OUT_TABLE: &str = "pigui_block4_out";
pub const DYNAMIC_BLOCK6_IN_TABLE: &str = "pigui_block6_in";
pub const DYNAMIC_BLOCK6_OUT_TABLE: &str = "pigui_block6_out";
pub const PFLOG_INTERFACE: &str = "pflog1";
pub const MAX_BLOCK_TTL_SECS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    #[serde(rename = "in")]
    Inbound,
    #[serde(rename = "out")]
    Outbound,
    #[serde(rename = "both")]
    Both,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "in",
            Self::Outbound => "out",
            Self::Both => "both",
        }
    }

    pub const fn as_pf(self) -> Option<&'static str> {
        match self {
            Self::Inbound => Some("in"),
            Self::Outbound => Some("out"),
            Self::Both => None,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "in" | "inbound" => Some(Self::Inbound),
            "out" | "outbound" => Some(Self::Outbound),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
    Reject,
}

impl RuleAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Reject => "reject",
        }
    }

    pub const fn as_pf(self) -> &'static str {
        match self {
            Self::Allow => "pass",
            Self::Block => "block drop",
            Self::Reject => "block return",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "allow" | "pass" => Some(Self::Allow),
            "block" | "drop" => Some(Self::Block),
            "reject" | "return" => Some(Self::Reject),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    Icmp6,
}

impl Protocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Icmp6 => "icmp6",
        }
    }

    pub const fn as_pf(self) -> Option<&'static str> {
        match self {
            Self::Any => None,
            Self::Tcp => Some("tcp"),
            Self::Udp => Some("udp"),
            Self::Icmp => Some("icmp"),
            Self::Icmp6 => Some("icmp6"),
        }
    }

    pub const fn supports_ports(self) -> bool {
        matches!(self, Self::Any | Self::Tcp | Self::Udp)
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "any" => Some(Self::Any),
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "icmp" => Some(Self::Icmp),
            "icmp6" | "icmpv6" => Some(Self::Icmp6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    Blocklist,
    Policy,
}

impl FirewallMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocklist => "blocklist",
            Self::Policy => "policy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "blocklist" => Some(Self::Blocklist),
            "policy" => Some(Self::Policy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub action: RuleAction,
    pub direction: Direction,
    pub protocol: Protocol,
    #[serde(default)]
    pub local_address: Option<String>,
    #[serde(default)]
    pub local_port: Option<String>,
    #[serde(default)]
    pub remote_address: Option<String>,
    #[serde(default)]
    pub remote_port: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default = "default_true")]
    pub log: bool,
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

impl FirewallRule {
    pub fn normalized(&self) -> Result<Self> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(Error::Firewall("rule name must not be empty".into()));
        }
        if name.chars().count() > 128 {
            return Err(Error::Firewall(
                "rule name must be 128 characters or fewer".into(),
            ));
        }
        if self.priority < 0 {
            return Err(Error::Firewall("rule priority must not be negative".into()));
        }

        let local_address = normalize_address(optional_text(self.local_address.as_deref()))?;
        let local_port = normalize_port(optional_text(self.local_port.as_deref()))?;
        let remote_address = normalize_address(optional_text(self.remote_address.as_deref()))?;
        let remote_port = normalize_port(optional_text(self.remote_port.as_deref()))?;
        let interface = normalize_interface(optional_text(self.interface.as_deref()))?;

        if !self.protocol.supports_ports() && (local_port.is_some() || remote_port.is_some()) {
            return Err(Error::Firewall(format!(
                "protocol {} does not support ports",
                self.protocol.as_str()
            )));
        }

        let mut rule = self.clone();
        rule.name = name.to_string();
        rule.local_address = local_address;
        rule.local_port = local_port;
        rule.remote_address = remote_address;
        rule.remote_port = remote_port;
        rule.interface = interface;
        Ok(rule)
    }

    pub fn is_broad(&self) -> bool {
        self.local_address.is_none()
            && self.local_port.is_none()
            && self.remote_address.is_none()
            && self.remote_port.is_none()
            && self.interface.is_none()
    }

    pub fn label_id(&self) -> i64 {
        self.id.max(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    pub enabled: bool,
    pub mode: FirewallMode,
    pub generation: i64,
    pub applied_generation: i64,
    pub applied_at: Option<i64>,
    pub last_error: Option<String>,
    pub pf_enabled_by_pigui: bool,
}

impl Default for FirewallState {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: FirewallMode::Blocklist,
            generation: 0,
            applied_generation: 0,
            applied_at: None,
            last_error: None,
            pf_enabled_by_pigui: false,
        }
    }
}

impl FirewallState {
    pub fn needs_apply(&self) -> bool {
        self.generation != self.applied_generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallBlock {
    #[serde(default)]
    pub id: i64,
    pub address: String,
    pub direction: Direction,
    pub ttl_secs: i64,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default = "default_manual")]
    pub source: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: i64,
}

impl FirewallBlock {
    pub fn normalized(&self) -> Result<Self> {
        let address = normalize_address(&self.address)?
            .ok_or_else(|| Error::Firewall("block address must not be any".into()))?;
        if self.ttl_secs <= 0 {
            return Err(Error::Firewall("block TTL must be positive".into()));
        }
        if self.ttl_secs > MAX_BLOCK_TTL_SECS {
            return Err(Error::Firewall(format!(
                "block TTL must be {MAX_BLOCK_TTL_SECS} seconds or fewer"
            )));
        }
        let reason = self
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        if reason
            .as_ref()
            .is_some_and(|value| value.chars().count() > 512)
        {
            return Err(Error::Firewall(
                "block reason must be 512 characters or fewer".into(),
            ));
        }
        let source = self.source.trim();
        if source.is_empty() {
            return Err(Error::Firewall("block source must not be empty".into()));
        }

        let mut block = self.clone();
        block.address = address;
        block.reason = reason;
        block.source = source.to_string();
        Ok(block)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallAuditEntry {
    #[serde(default)]
    pub id: i64,
    #[serde(default)]
    pub ts: i64,
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub rule_id: Option<i64>,
    #[serde(default)]
    pub detail: Option<String>,
    pub result: String,
    #[serde(default)]
    pub error: Option<String>,
}

impl FirewallAuditEntry {
    pub fn normalized(&self) -> Result<Self> {
        let actor = self.actor.trim();
        if actor.is_empty() {
            return Err(Error::Firewall("audit actor must not be empty".into()));
        }
        let action = self.action.trim();
        if action.is_empty() {
            return Err(Error::Firewall("audit action must not be empty".into()));
        }
        let result = self.result.trim();
        if result.is_empty() {
            return Err(Error::Firewall("audit result must not be empty".into()));
        }
        let mut entry = self.clone();
        entry.actor = actor.to_string();
        entry.action = action.to_string();
        entry.result = result.to_string();
        Ok(entry)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleRequest {
    pub rule: FirewallRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleIdRequest {
    pub id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallReorderRequest {
    pub ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleList {
    pub rules: Vec<FirewallRule>,
    pub state: FirewallState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallBlockRequest {
    pub address: String,
    pub direction: Direction,
    pub ttl_secs: i64,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default = "default_manual")]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallBlockList {
    pub blocks: Vec<FirewallBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallBlockRemoveRequest {
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub direction: Option<Direction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallEventsRequest {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatusPayload {
    pub state: FirewallState,
    pub rule_count: u64,
    pub block_count: u64,
    pub helper: Value,
    #[serde(default)]
    pub helper_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledFirewall {
    pub block_anchor: String,
    pub allow_anchor: String,
    pub block_rule_count: usize,
    pub allow_rule_count: usize,
}

impl CompiledFirewall {
    pub fn is_empty(&self) -> bool {
        self.block_rule_count == 0 && self.allow_rule_count == 0
    }
}

pub fn compile_firewall(rules: &[FirewallRule]) -> Result<CompiledFirewall> {
    let mut normalized = Vec::new();
    for rule in rules.iter().filter(|rule| rule.enabled) {
        normalized.push(rule.normalized()?);
    }
    normalized.sort_by_key(|rule| (rule.priority, rule.id));

    let mut block_anchor = String::from("# PIGUI managed block rules. Do not edit.\n");
    block_anchor.push_str(DYNAMIC_BLOCK_RULES);
    let mut allow_anchor = String::from("# PIGUI managed allow rules. Do not edit.\n");
    let mut block_rule_count = 0;
    let mut allow_rule_count = 0;

    for (index, rule) in normalized.iter().enumerate() {
        let label_id = if rule.id > 0 {
            rule.id
        } else {
            (index as i64) + 1
        };
        let directions = match rule.direction {
            Direction::Both => vec![Some("in"), Some("out")],
            direction => vec![direction.as_pf()],
        };
        for direction in directions {
            let label = match (rule.direction, direction) {
                (Direction::Both, Some(direction)) => {
                    format!("pigui-rule-{label_id}-{direction}")
                }
                _ => format!("pigui-rule-{label_id}"),
            };
            let line = compile_rule(rule, direction, &label);
            match rule.action {
                RuleAction::Allow => {
                    allow_anchor.push_str(&line);
                    allow_anchor.push('\n');
                    allow_rule_count += 1;
                }
                RuleAction::Block | RuleAction::Reject => {
                    block_anchor.push_str(&line);
                    block_anchor.push('\n');
                    block_rule_count += 1;
                }
            }
        }
    }

    Ok(CompiledFirewall {
        block_anchor,
        allow_anchor,
        block_rule_count,
        allow_rule_count,
    })
}

fn compile_rule(rule: &FirewallRule, direction: Option<&str>, label: &str) -> String {
    let mut parts = vec![rule.action.as_pf().to_string()];
    if let Some(direction) = direction {
        parts.push(direction.to_string());
    }
    if rule.log {
        parts.push(format!("log (to {PFLOG_INTERFACE})"));
    }
    parts.push("quick".to_string());
    if let Some(interface) = &rule.interface {
        parts.push("on".to_string());
        parts.push(interface.clone());
    }
    if let Some(protocol) = rule.protocol.as_pf() {
        parts.push("proto".to_string());
        parts.push(protocol.to_string());
    }

    let (source_address, source_port, destination_address, destination_port) = match direction {
        Some("out") => (
            rule.local_address.as_deref(),
            rule.local_port.as_deref(),
            rule.remote_address.as_deref(),
            rule.remote_port.as_deref(),
        ),
        _ => (
            rule.remote_address.as_deref(),
            rule.remote_port.as_deref(),
            rule.local_address.as_deref(),
            rule.local_port.as_deref(),
        ),
    };

    if source_address.is_some() || source_port.is_some() {
        parts.push("from".to_string());
        parts.push(source_address.unwrap_or("any").to_string());
        if let Some(port) = source_port {
            parts.push("port".to_string());
            parts.push(port.to_string());
        }
    }
    if destination_address.is_some() || destination_port.is_some() {
        parts.push("to".to_string());
        parts.push(destination_address.unwrap_or("any").to_string());
        if let Some(port) = destination_port {
            parts.push("port".to_string());
            parts.push(port.to_string());
        }
    }

    parts.push("label".to_string());
    parts.push(format!("\"{label}\""));

    parts.join(" ")
}

const DYNAMIC_BLOCK_RULES: &str = "\
table <pigui_block4_in> persist
table <pigui_block4_out> persist
table <pigui_block6_in> persist
table <pigui_block6_out> persist
block drop in log (to pflog1) quick inet from <pigui_block4_in> to any label \"pigui-dynamic4-in-src\"
block drop in log (to pflog1) quick inet from any to <pigui_block4_in> label \"pigui-dynamic4-in-dst\"
block drop out log (to pflog1) quick inet from <pigui_block4_out> to any label \"pigui-dynamic4-out-src\"
block drop out log (to pflog1) quick inet from any to <pigui_block4_out> label \"pigui-dynamic4-out-dst\"
block drop in log (to pflog1) quick inet6 from <pigui_block6_in> to any label \"pigui-dynamic6-in-src\"
block drop in log (to pflog1) quick inet6 from any to <pigui_block6_in> label \"pigui-dynamic6-in-dst\"
block drop out log (to pflog1) quick inet6 from <pigui_block6_out> to any label \"pigui-dynamic6-out-src\"
block drop out log (to pflog1) quick inet6 from any to <pigui_block6_out> label \"pigui-dynamic6-out-dst\"
";

pub fn normalize_address(value: &str) -> Result<Option<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("any") {
        return Ok(None);
    }
    let (address, prefix) = match trimmed.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (trimmed, None),
    };
    let ip: IpAddr = address
        .parse()
        .map_err(|_| Error::Firewall(format!("invalid IP address: {value}")))?;
    match prefix {
        Some(prefix) => {
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| Error::Firewall(format!("invalid CIDR prefix: {value}")))?;
            let max = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return Err(Error::Firewall(format!(
                    "CIDR prefix must be {max} or lower: {value}"
                )));
            }
            Ok(Some(format!("{ip}/{prefix}")))
        }
        None => Ok(Some(ip.to_string())),
    }
}

pub fn normalize_port(value: &str) -> Result<Option<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("any") {
        return Ok(None);
    }
    let normalized = trimmed.replace('-', ":");
    if let Some((start, end)) = normalized.split_once(':') {
        if end.contains(':') {
            return Err(Error::Firewall(format!("invalid port range: {value}")));
        }
        let start = parse_port(start, value)?;
        let end = parse_port(end, value)?;
        if start > end {
            return Err(Error::Firewall(format!(
                "port range start must not exceed end: {value}"
            )));
        }
        Ok(Some(format!("{start}:{end}")))
    } else {
        Ok(Some(parse_port(&normalized, value)?.to_string()))
    }
}

fn parse_port(value: &str, original: &str) -> Result<u16> {
    let port: u16 = value
        .trim()
        .parse()
        .map_err(|_| Error::Firewall(format!("invalid port: {original}")))?;
    if port == 0 {
        return Err(Error::Firewall(format!("port must be 1-65535: {original}")));
    }
    Ok(port)
}

pub fn normalize_interface(value: &str) -> Result<Option<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("any") {
        return Ok(None);
    }
    if trimmed.len() > 15 {
        return Err(Error::Firewall(format!(
            "interface name is too long: {trimmed}"
        )));
    }
    let mut chars = trimmed.chars();
    let first = chars.next().unwrap_or_default();
    if !first.is_ascii_alphanumeric()
        || !trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err(Error::Firewall(format!(
            "invalid interface name: {trimmed}"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

fn optional_text(value: Option<&str>) -> &str {
    value.unwrap_or("")
}

const fn default_true() -> bool {
    true
}

fn default_manual() -> String {
    "manual".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    pub ip: String,
    pub direction: Direction,
    pub ttl_secs: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOutcome {
    Applied,
    WouldBlock,
}

pub trait FirewallBackend {
    fn name(&self) -> &'static str;
    fn apply_block(&self, request: &BlockRequest) -> Result<BlockOutcome>;
    fn flush(&self) -> Result<usize>;
}

/// Records intended blocks without touching the system firewall.
#[derive(Debug, Default)]
pub struct DryRunBackend {
    blocks: Mutex<Vec<BlockRequest>>,
}

impl DryRunBackend {
    pub fn blocks(&self) -> Vec<BlockRequest> {
        self.blocks.lock().expect("dry-run lock poisoned").clone()
    }
}

impl FirewallBackend for DryRunBackend {
    fn name(&self) -> &'static str {
        "dry-run"
    }

    fn apply_block(&self, request: &BlockRequest) -> Result<BlockOutcome> {
        self.blocks
            .lock()
            .map_err(|_| Error::Firewall("dry-run lock poisoned".into()))?
            .push(request.clone());
        Ok(BlockOutcome::WouldBlock)
    }

    fn flush(&self) -> Result<usize> {
        let mut blocks = self
            .blocks
            .lock()
            .map_err(|_| Error::Firewall("dry-run lock poisoned".into()))?;
        let count = blocks.len();
        blocks.clear();
        Ok(count)
    }
}

/// PF backend placeholder. Real anchor management lands in P2.
#[derive(Debug, Default)]
pub struct PfBackend;

impl FirewallBackend for PfBackend {
    fn name(&self) -> &'static str {
        "pf"
    }

    fn apply_block(&self, _request: &BlockRequest) -> Result<BlockOutcome> {
        Err(Error::NotImplemented(
            "PF enforcement is planned for P2".into(),
        ))
    }

    fn flush(&self) -> Result<usize> {
        Err(Error::NotImplemented(
            "PF enforcement is planned for P2".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: RuleAction, direction: Direction) -> FirewallRule {
        FirewallRule {
            id: 1,
            name: "test".into(),
            enabled: true,
            action,
            direction,
            protocol: Protocol::Tcp,
            local_address: None,
            local_port: None,
            remote_address: Some("192.0.2.10".into()),
            remote_port: Some("443".into()),
            interface: None,
            log: true,
            priority: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn compiles_inbound_block_rule() {
        let compiled = compile_firewall(&[rule(RuleAction::Block, Direction::Inbound)]).unwrap();
        assert_eq!(compiled.block_rule_count, 1);
        assert_eq!(compiled.allow_rule_count, 0);
        assert!(compiled.block_anchor.contains(
            "block drop in log (to pflog1) quick proto tcp from 192.0.2.10 port 443 label \"pigui-rule-1\""
        ));
        assert!(
            compiled
                .block_anchor
                .contains("table <pigui_block4_in> persist")
        );
    }

    #[test]
    fn compiles_outbound_allow_rule_with_swapped_endpoints() {
        let mut rule = rule(RuleAction::Allow, Direction::Outbound);
        rule.local_address = Some("10.0.0.5".into());
        rule.local_port = Some("50000".into());
        let compiled = compile_firewall(&[rule]).unwrap();
        assert_eq!(compiled.block_rule_count, 0);
        assert_eq!(compiled.allow_rule_count, 1);
        assert!(compiled.allow_anchor.contains(
            "pass out log (to pflog1) quick proto tcp from 10.0.0.5 port 50000 to 192.0.2.10 port 443 label \"pigui-rule-1\""
        ));
        assert!(!compiled.allow_anchor.contains("table <pigui_block"));
    }

    #[test]
    fn both_direction_emits_two_rules() {
        let compiled = compile_firewall(&[rule(RuleAction::Reject, Direction::Both)]).unwrap();
        assert_eq!(compiled.block_rule_count, 2);
        assert!(
            compiled.block_anchor.contains(
                "block return in log (to pflog1) quick proto tcp from 192.0.2.10 port 443"
            )
        );
        assert!(
            compiled.block_anchor.contains(
                "block return out log (to pflog1) quick proto tcp to 192.0.2.10 port 443"
            )
        );
        assert!(compiled.block_anchor.contains("label \"pigui-rule-1-in\""));
        assert!(compiled.block_anchor.contains("label \"pigui-rule-1-out\""));
    }

    #[test]
    fn skips_disabled_rules_and_orders_by_priority() {
        let mut first = rule(RuleAction::Block, Direction::Inbound);
        first.id = 1;
        first.priority = 10;
        first.remote_address = Some("192.0.2.1".into());
        first.remote_port = None;
        let mut second = rule(RuleAction::Block, Direction::Inbound);
        second.id = 2;
        second.priority = 5;
        second.remote_address = Some("192.0.2.2".into());
        second.remote_port = None;
        let mut disabled = rule(RuleAction::Block, Direction::Inbound);
        disabled.id = 3;
        disabled.enabled = false;
        disabled.priority = 1;

        let compiled = compile_firewall(&[first, second, disabled]).unwrap();
        let lines: Vec<&str> = compiled
            .block_anchor
            .lines()
            .filter(|line| line.contains("pigui-rule-"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("pigui-rule-2"));
        assert!(lines[1].contains("pigui-rule-1"));
    }

    #[test]
    fn normalizes_addresses_ports_and_interfaces() {
        assert_eq!(
            normalize_address(" 192.0.2.5/24 ").unwrap().as_deref(),
            Some("192.0.2.5/24")
        );
        assert_eq!(normalize_address("any").unwrap(), None);
        assert_eq!(
            normalize_port("1024-2048").unwrap().as_deref(),
            Some("1024:2048")
        );
        assert_eq!(normalize_port("443").unwrap().as_deref(), Some("443"));
        assert_eq!(
            normalize_interface(" en0 ").unwrap().as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(normalize_address("192.0.2.1/33").is_err());
        assert!(normalize_address("not-an-ip").is_err());
        assert!(normalize_port("0").is_err());
        assert!(normalize_port("70000").is_err());
        assert!(normalize_port("100-50").is_err());
        assert!(normalize_interface("en 0").is_err());

        let mut icmp = rule(RuleAction::Block, Direction::Inbound);
        icmp.protocol = Protocol::Icmp;
        icmp.remote_port = Some("443".into());
        assert!(icmp.normalized().is_err());
    }

    #[test]
    fn normalizes_rule_name_and_optional_fields() {
        let mut rule = rule(RuleAction::Block, Direction::Inbound);
        rule.name = "  test  ".into();
        rule.local_address = Some("any".into());
        rule.remote_port = Some(" 443 ".into());
        rule.interface = Some(" any ".into());
        let normalized = rule.normalized().unwrap();
        assert_eq!(normalized.name, "test");
        assert_eq!(normalized.local_address, None);
        assert_eq!(normalized.remote_port.as_deref(), Some("443"));
        assert_eq!(normalized.interface, None);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn compiled_output_passes_pfctl_syntax_check() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut inbound = rule(RuleAction::Block, Direction::Inbound);
        inbound.interface = Some("en0".into());
        let mut outbound = rule(RuleAction::Allow, Direction::Outbound);
        outbound.local_address = Some("10.0.0.5".into());
        outbound.local_port = Some("50000".into());
        let mut both = rule(RuleAction::Reject, Direction::Both);
        both.protocol = Protocol::Udp;
        both.remote_port = Some("53".into());

        let compiled = compile_firewall(&[inbound, outbound, both]).unwrap();
        for (name, text) in [
            ("block", compiled.block_anchor),
            ("allow", compiled.allow_anchor),
        ] {
            let mut child = Command::new("/sbin/pfctl")
                .args(["-nf", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start pfctl");
            child
                .stdin
                .as_mut()
                .expect("pfctl stdin")
                .write_all(text.as_bytes())
                .expect("write pfctl rules");
            let output = child.wait_with_output().expect("wait for pfctl");
            assert!(
                output.status.success(),
                "pfctl rejected {name} anchor: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn block_ttl_and_source_are_validated() {
        let block = FirewallBlock {
            id: 0,
            address: " 192.0.2.10 ".into(),
            direction: Direction::Both,
            ttl_secs: 3600,
            reason: Some("manual".into()),
            source: "manual".into(),
            created_at: 0,
            expires_at: 0,
        };
        let normalized = block.normalized().unwrap();
        assert_eq!(normalized.address, "192.0.2.10");

        let mut invalid = block.clone();
        invalid.ttl_secs = 0;
        assert!(invalid.normalized().is_err());
        invalid.ttl_secs = MAX_BLOCK_TTL_SECS + 1;
        assert!(invalid.normalized().is_err());
        invalid.ttl_secs = 60;
        invalid.address = "any".into();
        assert!(invalid.normalized().is_err());
    }
}
