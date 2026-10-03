//! Store-lineage and exact-query-scope-bound replay cursors.
use serde::{Deserialize, Serialize};

use crate::{DecimalString, WireError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventCursor {
    pub store_lineage: String,
    pub scope_id: String,
    pub sequence: DecimalString,
}

impl EventCursor {
    pub fn initial(
        store_lineage: impl Into<String>,
        scope_id: impl Into<String>,
    ) -> Result<Self, WireError> {
        let cursor = Self {
            store_lineage: store_lineage.into(),
            scope_id: scope_id.into(),
            sequence: DecimalString::ZERO,
        };
        cursor.validate_shape()?;
        Ok(cursor)
    }

    pub fn validate_shape(&self) -> Result<(), WireError> {
        valid_identity(&self.store_lineage).map_err(|_| WireError::InvalidField("storeLineage"))?;
        valid_identity(&self.scope_id).map_err(|_| WireError::InvalidField("scopeId"))?;
        self.sequence.try_i64()?;
        Ok(())
    }

    pub fn validate_for(
        &self,
        store_lineage: &str,
        scope_id: &str,
        earliest_retained: DecimalString,
        current_head: DecimalString,
    ) -> Result<(), WireError> {
        self.validate_shape()?;
        if self.store_lineage != store_lineage {
            return Err(WireError::ForeignLineage);
        }
        if self.scope_id != scope_id {
            return Err(WireError::ForeignScope);
        }
        if self.sequence > current_head {
            return Err(WireError::FutureCursor);
        }
        if self.sequence.get() < earliest_retained.get().saturating_sub(1) {
            return Err(WireError::ReplayGap {
                earliest: earliest_retained,
            });
        }
        Ok(())
    }
}

pub(crate) fn valid_identity(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(())
    } else {
        Ok(())
    }
}
