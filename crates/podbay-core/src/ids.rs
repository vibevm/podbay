//! Opaque, non-interchangeable runtime identities and checked counters.
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const MAX_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    Empty,
    TooLong,
    InvalidCharacter,
    ZeroCounter,
    CounterOverflow,
}

impl Display for IdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "identity is empty",
            Self::TooLong => "identity exceeds the bounded length",
            Self::InvalidCharacter => "identity contains control or boundary whitespace",
            Self::ZeroCounter => "counter must be positive",
            Self::CounterOverflow => "counter exhausted its range",
        })
    }
}

impl Error for IdError {}

fn validate_id(value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(IdError::Empty);
    }
    if value.len() > MAX_ID_BYTES {
        return Err(IdError::TooLong);
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(IdError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! opaque_id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
            pub struct $name(Box<str>);

            impl $name {
                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl TryFrom<&str> for $name {
                type Error = IdError;

                fn try_from(value: &str) -> Result<Self, Self::Error> {
                    validate_id(value)?;
                    Ok(Self(value.into()))
                }
            }

            impl TryFrom<String> for $name {
                type Error = IdError;

                fn try_from(value: String) -> Result<Self, Self::Error> {
                    validate_id(&value)?;
                    Ok(Self(value.into_boxed_str()))
                }
            }

            impl FromStr for $name {
                type Err = IdError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::try_from(value)
                }
            }

            impl AsRef<str> for $name {
                fn as_ref(&self) -> &str {
                    self.as_str()
                }
            }

            impl Display for $name {
                fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                    formatter.write_str(self.as_str())
                }
            }
        )+
    };
}

opaque_id!(
    SessionId,
    RunId,
    AttemptId,
    PodId,
    ResourceId,
    ActorId,
    CommandId,
    DeliveryId,
    EventId,
    SourceId,
    ScopeId,
    ReportId,
    WorkIntervalId,
);

macro_rules! positive_counter {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, IdError> {
                if value == 0 {
                    Err(IdError::ZeroCounter)
                } else {
                    Ok(Self(value))
                }
            }

            pub const fn get(self) -> u64 {
                self.0
            }

            pub fn checked_next(self) -> Result<Self, IdError> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(IdError::CounterOverflow)
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                Display::fmt(&self.0, formatter)
            }
        }
    };
}

positive_counter!(Revision);
positive_counter!(Epoch);

impl Revision {
    pub const INITIAL: Self = Self(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_bounded_and_distinct() {
        assert_eq!(
            SessionId::try_from("session.one").unwrap().as_str(),
            "session.one"
        );
        assert_eq!(RunId::try_from("run.one").unwrap().as_str(), "run.one");
        assert_eq!(CommandId::try_from(" "), Err(IdError::InvalidCharacter));
        assert_eq!(ActorId::try_from(""), Err(IdError::Empty));
        assert_eq!(PodId::try_from("x".repeat(257)), Err(IdError::TooLong));
        assert_eq!(Epoch::new(0), Err(IdError::ZeroCounter));
    }
}
