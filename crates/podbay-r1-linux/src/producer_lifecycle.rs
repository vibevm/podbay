//! Pure negative-only lifecycle data. No I/O handles, callbacks, live evidence
//! or origin types enter this module. Every entry/packet returns a refusal.
#![forbid(unsafe_code)]

pub(crate) const SCHEMA: &str = "podbay.r1.producer-lifecycle/2";
const MAX_PACKET: usize = 1024;
const KEYS: [&str; 16] = [
    "schema",
    "generation",
    "boot_id",
    "nonce",
    "sequence",
    "producer_pid",
    "producer_birth",
    "child_pid",
    "child_birth",
    "attempt",
    "channel",
    "migration",
    "pending",
    "activation",
    "owner_epoch",
    "request",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    InvalidArguments,
    MalformedPacket,
    ForeignBinding,
    OutOfOrder,
    AttemptSpent,
    PartialAttempt,
    CustodyLost,
    RestartRefused,
    PrematureReady,
    LiveProvenanceUnavailable,
}
impl Refusal {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "INVALID_ARGUMENTS",
            Self::MalformedPacket => "MALFORMED_LIFECYCLE_PACKET",
            Self::ForeignBinding => "FOREIGN_LIFECYCLE_BINDING",
            Self::OutOfOrder => "OUT_OF_ORDER_LIFECYCLE_PACKET",
            Self::AttemptSpent => "ATTEMPT_SPENT",
            Self::PartialAttempt => "PARTIAL_ATTEMPT",
            Self::CustodyLost => "CUSTODY_LOST",
            Self::RestartRefused => "RESTART_REFUSED",
            Self::PrematureReady => "PREMATURE_READY_REFUSED",
            Self::LiveProvenanceUnavailable => "COLD_BOOT_PROVENANCE_UNAVAILABLE",
        }
    }
}

pub(crate) fn entry(has_arguments: bool) -> Refusal {
    if has_arguments {
        Refusal::InvalidArguments
    } else {
        Refusal::LiveProvenanceUnavailable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    pub(crate) birth: u64,
}
/// Expectations are supplied data, not observations of these processes.
pub(crate) struct Expected<'a> {
    pub(crate) generation: &'a str,
    pub(crate) boot_id: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) producer: ProcessIdentity,
    pub(crate) child: ProcessIdentity,
}

struct Packet<'a> {
    generation: &'a str,
    boot_id: &'a str,
    nonce: &'a str,
    sequence: u64,
    producer: ProcessIdentity,
    child: ProcessIdentity,
    attempt: &'a str,
    channel: &'a str,
    migration: &'a str,
    pending: &'a str,
    activation: &'a str,
    owner_epoch: u64,
    request: &'a str,
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn number(value: &str) -> Result<u64, Refusal> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(Refusal::MalformedPacket);
    }
    value.parse().map_err(|_| Refusal::MalformedPacket)
}
fn process(pid: &str, birth: &str) -> Result<ProcessIdentity, Refusal> {
    let pid = number(pid)?;
    let birth = number(birth)?;
    if !(2..u32::MAX as u64).contains(&pid) || birth == 0 {
        return Err(Refusal::MalformedPacket);
    }
    Ok(ProcessIdentity {
        pid: pid as u32,
        birth,
    })
}
fn parse(raw: &[u8]) -> Result<Packet<'_>, Refusal> {
    if raw.is_empty()
        || raw.len() > MAX_PACKET
        || !raw.ends_with(b"\n")
        || !raw.iter().all(|b| *b == b'\n' || (0x20..=0x7e).contains(b))
    {
        return Err(Refusal::MalformedPacket);
    }
    let text = std::str::from_utf8(raw).map_err(|_| Refusal::MalformedPacket)?;
    let mut lines = text[..text.len() - 1].split('\n');
    let mut values = [""; 16];
    for (index, key) in KEYS.iter().enumerate() {
        let line = lines.next().ok_or(Refusal::MalformedPacket)?;
        let (found, value) = line.split_once('=').ok_or(Refusal::MalformedPacket)?;
        if found != *key || value.is_empty() {
            return Err(Refusal::MalformedPacket);
        }
        values[index] = value;
    }
    if lines.next().is_some()
        || values[0] != SCHEMA
        || !hex(values[1], 64)
        || !boot(values[2])
        || !hex(values[3], 64)
        || !["unclaimed", "spent", "partial"].contains(&values[9])
        || !["live", "lost"].contains(&values[10])
        || !["absent", "durable"].contains(&values[11])
        || !["unresolved", "resolved"].contains(&values[12])
        || !["absent", "durable"].contains(&values[13])
        || !["validate", "ready", "restart"].contains(&values[15])
    {
        return Err(Refusal::MalformedPacket);
    }
    let sequence = number(values[4])?;
    let producer = process(values[5], values[6])?;
    let child = process(values[7], values[8])?;
    if sequence == 0 || producer.pid == child.pid {
        return Err(Refusal::MalformedPacket);
    }
    Ok(Packet {
        generation: values[1],
        boot_id: values[2],
        nonce: values[3],
        sequence,
        producer,
        child,
        attempt: values[9],
        channel: values[10],
        migration: values[11],
        pending: values[12],
        activation: values[13],
        owner_epoch: number(values[14])?,
        request: values[15],
    })
}

/// Sticky local refusal bookkeeping only. It neither creates nor observes an
/// OS attempt latch; constructing a new value cannot create positive authority.
pub(crate) struct NegativeLifecycle {
    spent: bool,
}
impl NegativeLifecycle {
    pub(crate) fn new() -> Self {
        Self { spent: false }
    }
    pub(crate) fn inspect(&mut self, expected: &Expected<'_>, raw: &[u8]) -> Refusal {
        if self.spent {
            return Refusal::AttemptSpent;
        }
        self.spent = true; // malformed, lost and rejected packets cannot retry
        let packet = match parse(raw) {
            Ok(p) => p,
            Err(r) => return r,
        };
        if packet.generation != expected.generation
            || packet.boot_id != expected.boot_id
            || packet.nonce != expected.nonce
            || packet.producer != expected.producer
            || packet.child != expected.child
        {
            return Refusal::ForeignBinding;
        }
        if packet.sequence != 1 {
            return Refusal::OutOfOrder;
        }
        if packet.attempt == "spent" {
            return Refusal::AttemptSpent;
        }
        if packet.attempt == "partial" {
            return Refusal::PartialAttempt;
        }
        if packet.channel == "lost" {
            return Refusal::CustodyLost;
        }
        if packet.request == "restart" {
            return Refusal::RestartRefused;
        }
        if packet.request == "ready"
            && (packet.migration != "durable"
                || packet.pending != "resolved"
                || packet.activation != "durable"
                || packet.owner_epoch == 0)
        {
            return Refusal::PrematureReady;
        }
        // Even a complete, internally consistent, caller-declared transcript
        // lacks actual pre-issuer provenance. There is intentionally no success.
        Refusal::LiveProvenanceUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BOOT: &str = "00000000-0000-0000-0000-000000000001";
    fn expected() -> Expected<'static> {
        Expected {
            generation: GENERATION,
            boot_id: BOOT,
            nonce: NONCE,
            producer: ProcessIdentity {
                pid: 20,
                birth: 100,
            },
            child: ProcessIdentity {
                pid: 21,
                birth: 101,
            },
        }
    }
    fn packet() -> String {
        format!(
            "schema={SCHEMA}\ngeneration={GENERATION}\nboot_id={BOOT}\nnonce={NONCE}\nsequence=1\nproducer_pid=20\nproducer_birth=100\nchild_pid=21\nchild_birth=101\nattempt=unclaimed\nchannel=live\nmigration=absent\npending=unresolved\nactivation=absent\nowner_epoch=0\nrequest=validate\n"
        )
    }
    fn inspect(raw: &str) -> Refusal {
        NegativeLifecycle::new().inspect(&expected(), raw.as_bytes())
    }
    #[test]
    fn entry_always_refuses_without_io_capabilities() {
        assert_eq!(entry(false), Refusal::LiveProvenanceUnavailable);
        assert_eq!(entry(true), Refusal::InvalidArguments);
    }
    #[test]
    fn valid_claim_is_data_and_refuses() {
        assert_eq!(inspect(&packet()), Refusal::LiveProvenanceUnavailable);
        let ready = packet()
            .replace("request=validate", "request=ready")
            .replace("migration=absent", "migration=durable")
            .replace("pending=unresolved", "pending=resolved")
            .replace("activation=absent", "activation=durable")
            .replace("owner_epoch=0", "owner_epoch=1");
        assert_eq!(inspect(&ready), Refusal::LiveProvenanceUnavailable);
    }
    #[test]
    fn every_unresolved_release_predicate_refuses_ready() {
        let ready = packet()
            .replace("request=validate", "request=ready")
            .replace("migration=absent", "migration=durable")
            .replace("pending=unresolved", "pending=resolved")
            .replace("activation=absent", "activation=durable")
            .replace("owner_epoch=0", "owner_epoch=1");
        for (good, bad) in [
            ("migration=durable", "migration=absent"),
            ("pending=resolved", "pending=unresolved"),
            ("activation=durable", "activation=absent"),
            ("owner_epoch=1", "owner_epoch=0"),
        ] {
            assert_eq!(inspect(&ready.replace(good, bad)), Refusal::PrematureReady);
        }
    }
    #[test]
    fn attempt_loss_restart_and_replay_are_terminal() {
        for (old, new, want) in [
            ("attempt=unclaimed", "attempt=spent", Refusal::AttemptSpent),
            (
                "attempt=unclaimed",
                "attempt=partial",
                Refusal::PartialAttempt,
            ),
            ("channel=live", "channel=lost", Refusal::CustodyLost),
            (
                "request=validate",
                "request=restart",
                Refusal::RestartRefused,
            ),
            ("sequence=1", "sequence=2", Refusal::OutOfOrder),
        ] {
            let mut state = NegativeLifecycle::new();
            assert_eq!(
                state.inspect(&expected(), packet().replace(old, new).as_bytes()),
                want
            );
            assert_eq!(
                state.inspect(&expected(), packet().as_bytes()),
                Refusal::AttemptSpent
            );
        }
    }
    #[test]
    fn bound_identity_changes_refuse() {
        for (old, new) in [
            (GENERATION, NONCE),
            (NONCE, GENERATION),
            (BOOT, "00000000-0000-0000-0000-000000000002"),
            ("producer_pid=20", "producer_pid=22"),
            ("producer_birth=100", "producer_birth=102"),
            ("child_pid=21", "child_pid=23"),
            ("child_birth=101", "child_birth=103"),
        ] {
            assert_eq!(
                inspect(&packet().replace(old, new)),
                Refusal::ForeignBinding
            );
        }
    }
    #[test]
    fn closed_shape_bounds_numbers_and_partial_frames_refuse() {
        let p = packet();
        for raw in [
            String::new(),
            p.trim_end().to_string(),
            format!("{p}\n"),
            format!("{p}force=1\n"),
            p.replace("channel=live\n", ""),
            p.replace("channel=live", "channel=live\nchannel=live"),
            p.replace("sequence=1", "sequence=01"),
            p.replace("sequence=1", "sequence=18446744073709551616"),
            p.replace("sequence=1", "sequence=true"),
            p.replace("child_pid=21", "child_pid=20"),
            p.replace("producer_birth=100", "producer_birth=0"),
            p.replace("channel=live", "channel=unknown"),
            p.replace('\n', "\r\n"),
            p.replace("request=validate", "request=validate\0"),
            "x".repeat(MAX_PACKET + 1),
        ] {
            let mut state = NegativeLifecycle::new();
            assert_eq!(
                state.inspect(&expected(), raw.as_bytes()),
                Refusal::MalformedPacket
            );
            assert_eq!(
                state.inspect(&expected(), p.as_bytes()),
                Refusal::AttemptSpent
            );
        }
    }
}
