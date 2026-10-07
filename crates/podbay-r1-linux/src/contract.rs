//! Installer syntax only. No schema bytes or peer claims grant cold origin.
pub(crate) const MANIFEST_PATH: &str = "/etc/podbay/r1-install-manifest.json";
pub(crate) const MANIFEST_SCHEMA: &str = "podbay.r1.install-manifest/1";

/// Intentionally uninhabited in ordinary and test builds. There is no factory,
/// deserializer, caller flag, PID1 socket or test variant that constructs it.
#[allow(dead_code, reason = "No acquisition constructor exists in this atom")]
pub(crate) enum ColdOriginPermit {}

/// Both roles require the same unavailable external deployment provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Bootstrap,
    Custodian,
}
