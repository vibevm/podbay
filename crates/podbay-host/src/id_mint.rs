//! Host-owned fresh identities for one proposed root launch. These values are
//! candidates only; minting does not admit a command or reserve a launch slot.

use std::error::Error;
use std::fmt::{Display, Formatter};

use podbay_core::{AttemptId, PodId, ResourceId, RunId, SessionId};

const RANDOM_BYTES_PER_ID: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootIdMintError {
    EntropyUnavailable,
    GeneratedIdInvalid,
}

impl Display for RootIdMintError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EntropyUnavailable => "OS entropy unavailable for root launch identities",
            Self::GeneratedIdInvalid => "generated root launch identity failed validation",
        })
    }
}

impl Error for RootIdMintError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootLaunchIds {
    pub session_id: SessionId,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub pod_id: PodId,
    pub resource_id: ResourceId,
}

impl RootLaunchIds {
    /// Draw 128 fresh OS-random bits independently for each kind. No request
    /// ID, command key, timestamp, counter, or downstream provider ID is an
    /// entropy source. Failure returns no partial identity bundle.
    pub fn mint() -> Result<Self, RootIdMintError> {
        Self::mint_with(|bytes| {
            getrandom::fill(bytes).map_err(|_| RootIdMintError::EntropyUnavailable)
        })
    }

    fn mint_with(
        mut fill: impl FnMut(&mut [u8]) -> Result<(), RootIdMintError>,
    ) -> Result<Self, RootIdMintError> {
        let session_id = SessionId::try_from(mint_kind("session.", &mut fill)?)
            .map_err(|_| RootIdMintError::GeneratedIdInvalid)?;
        let run_id = RunId::try_from(mint_kind("run.", &mut fill)?)
            .map_err(|_| RootIdMintError::GeneratedIdInvalid)?;
        let attempt_id = AttemptId::try_from(mint_kind("attempt.", &mut fill)?)
            .map_err(|_| RootIdMintError::GeneratedIdInvalid)?;
        let pod_id = PodId::try_from(mint_kind("pod.", &mut fill)?)
            .map_err(|_| RootIdMintError::GeneratedIdInvalid)?;
        let resource_id = ResourceId::try_from(mint_kind("resource.", &mut fill)?)
            .map_err(|_| RootIdMintError::GeneratedIdInvalid)?;
        Ok(Self {
            session_id,
            run_id,
            attempt_id,
            pod_id,
            resource_id,
        })
    }
}

fn mint_kind(
    prefix: &str,
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), RootIdMintError>,
) -> Result<String, RootIdMintError> {
    let mut random = [0u8; RANDOM_BYTES_PER_ID];
    fill(&mut random)?;
    let mut id = String::with_capacity(prefix.len() + RANDOM_BYTES_PER_ID * 2);
    id.push_str(prefix);
    for byte in random {
        id.push(HEX[(byte >> 4) as usize] as char);
        id.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_distinct_even_with_identical_random_bytes() {
        let mut calls = 0u8;
        let ids = RootLaunchIds::mint_with(|bytes| {
            calls += 1;
            bytes.fill(0x5a);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 5);
        for (value, prefix) in [
            (ids.session_id.as_str(), "session."),
            (ids.run_id.as_str(), "run."),
            (ids.attempt_id.as_str(), "attempt."),
            (ids.pod_id.as_str(), "pod."),
            (ids.resource_id.as_str(), "resource."),
        ] {
            assert!(value.starts_with(prefix));
            assert_eq!(value.len(), prefix.len() + 32);
            assert!(
                value[prefix.len()..]
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert!(value.ends_with(&"5a".repeat(16)));
        }
        assert_ne!(ids.session_id.as_str(), ids.run_id.as_str());
        assert_ne!(ids.pod_id.as_str(), ids.resource_id.as_str());
    }

    #[test]
    fn five_independent_draws_and_typed_entropy_failure() {
        let mut calls = 0u8;
        let ids = RootLaunchIds::mint_with(|bytes| {
            calls += 1;
            bytes.fill(calls);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 5);
        assert!(ids.session_id.as_str().ends_with(&"01".repeat(16)));
        assert!(ids.run_id.as_str().ends_with(&"02".repeat(16)));
        assert!(ids.attempt_id.as_str().ends_with(&"03".repeat(16)));
        assert!(ids.pod_id.as_str().ends_with(&"04".repeat(16)));
        assert!(ids.resource_id.as_str().ends_with(&"05".repeat(16)));

        let mut failed_calls = 0;
        let result = RootLaunchIds::mint_with(|bytes| {
            failed_calls += 1;
            if failed_calls == 4 {
                return Err(RootIdMintError::EntropyUnavailable);
            }
            bytes.fill(0xaa);
            Ok(())
        });
        assert_eq!(result, Err(RootIdMintError::EntropyUnavailable));
        assert_eq!(failed_calls, 4);
    }

    #[test]
    fn os_entropy_mints_typed_bounded_candidates() {
        let ids = RootLaunchIds::mint().unwrap();
        assert!(SessionId::try_from(ids.session_id.as_str()).is_ok());
        assert!(RunId::try_from(ids.run_id.as_str()).is_ok());
        assert!(AttemptId::try_from(ids.attempt_id.as_str()).is_ok());
        assert!(PodId::try_from(ids.pod_id.as_str()).is_ok());
        assert!(ResourceId::try_from(ids.resource_id.as_str()).is_ok());
    }
}
