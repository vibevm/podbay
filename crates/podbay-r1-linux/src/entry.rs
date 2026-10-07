use crate::contract::{MANIFEST_PATH, Role};
use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    InvalidArguments,
    RootRequired,
    ColdBootProvenanceUnavailable,
}

pub(crate) fn arguments(args: &[OsString]) -> Result<Role, Refusal> {
    if args.len() != 3 || args[1] != "--manifest" || args[2] != MANIFEST_PATH {
        return Err(Refusal::InvalidArguments);
    }
    match args[0].to_str() {
        Some("bootstrap") => Ok(Role::Bootstrap),
        Some("custodian") => Ok(Role::Custodian),
        _ => Err(Refusal::InvalidArguments),
    }
}

/// This function is deliberately pure. No I/O capability enters the refusal
/// boundary. Even a synthetic root identity cannot reach source/lock code.
pub(crate) fn acquisition(_role: Role, real_uid: u32, effective_uid: u32) -> Refusal {
    if real_uid != 0 || effective_uid != 0 {
        Refusal::RootRequired
    } else {
        Refusal::ColdBootProvenanceUnavailable
    }
}

impl Refusal {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::InvalidArguments => "INVALID_ARGUMENTS",
            Self::RootRequired => "ROOT_REQUIRED",
            Self::ColdBootProvenanceUnavailable => "COLD_BOOT_PROVENANCE_UNAVAILABLE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_identity_and_role_stays_unavailable() {
        for role in [Role::Bootstrap, Role::Custodian] {
            for (real, effective) in [(0, 0), (1000, 1000), (0, 1000), (1000, 0)] {
                assert_eq!(
                    acquisition(role, real, effective),
                    if (real, effective) == (0, 0) {
                        Refusal::ColdBootProvenanceUnavailable
                    } else {
                        Refusal::RootRequired
                    }
                );
            }
        }
    }

    #[test]
    fn exact_installer_argv_and_no_manual_override() {
        for command in ["bootstrap", "custodian"] {
            assert!(
                arguments(&[command.into(), "--manifest".into(), MANIFEST_PATH.into()]).is_ok()
            );
        }
        for args in [
            vec![],
            vec!["bootstrap", "--cold", MANIFEST_PATH],
            vec!["custodian", "--manifest", "/tmp/foreign.json"],
            vec!["bootstrap", "--manifest", MANIFEST_PATH, "--force"],
        ] {
            assert_eq!(
                arguments(&args.into_iter().map(OsString::from).collect::<Vec<_>>()),
                Err(Refusal::InvalidArguments)
            );
        }
    }
}
