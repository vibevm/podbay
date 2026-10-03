//! Pure timeout classification: an elapsed deadline never dispatches an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimeoutCompletion {
    Canceled,
    CompletedAfterDeadline,
    FailedAfterDeadline,
    PendingQuarantined,
}
impl TimeoutCompletion {
    pub(crate) fn dispatch_allowed(self) -> bool {
        false
    }
    pub(crate) fn diagnostic(self) -> &'static str {
        match self {
            Self::Canceled => "pipe I/O canceled after deadline",
            Self::CompletedAfterDeadline => "pipe I/O completed after deadline",
            Self::FailedAfterDeadline => "pipe I/O failed after deadline",
            Self::PendingQuarantined => "pipe I/O cancellation completion not observed",
        }
    }
}
pub(crate) fn confirmed_completion_before_deadline(
    deadline_elapsed: bool,
) -> Result<(), TimeoutCompletion> {
    if deadline_elapsed {
        Err(TimeoutCompletion::CompletedAfterDeadline)
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timeout_races_never_authorize_dispatch() {
        for status in [
            TimeoutCompletion::Canceled,
            TimeoutCompletion::CompletedAfterDeadline,
            TimeoutCompletion::FailedAfterDeadline,
            TimeoutCompletion::PendingQuarantined,
        ] {
            assert!(!status.dispatch_allowed());
            assert!(!status.diagnostic().is_empty());
        }
    }
    #[test]
    fn late_confirmed_completion_cannot_authorize_dispatch() {
        assert!(confirmed_completion_before_deadline(false).is_ok());
        assert_eq!(
            confirmed_completion_before_deadline(true),
            Err(TimeoutCompletion::CompletedAfterDeadline)
        );
    }
}
