use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::model::{LaunchDispatchStage, LaunchDispatchStatus, LaunchPortResult, StoreError};
use crate::store::PodBayStore;

impl PodBayStore {
    pub fn launch_dispatch_status(
        &self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
    ) -> Result<LaunchDispatchStatus, StoreError> {
        valid_identity(scope_id)?;
        valid_identity(target_id)?;
        let row: Option<(
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        )> = self
            .connection
            .query_row(
                "SELECT o.scope_id,o.target_id,o.kind,o.state,d.stage,d.receipt_ref
                 FROM outbox o LEFT JOIN launch_dispatch_outcomes d
                   ON d.outbox_id=o.outbox_id WHERE o.outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let (scope, target, kind, state, outcome_stage, receipt_ref) =
            row.ok_or(StoreError::NotFound)?;
        if scope != scope_id || target != target_id {
            return Err(StoreError::WrongScope);
        }
        if kind != "pod.offer" {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if let Some(stage) = outcome_stage {
            return Ok(LaunchDispatchStatus {
                stage: decode_stage(&stage)?,
                receipt_ref,
            });
        }
        let stage = match state.as_str() {
            "prepared" => LaunchDispatchStage::Prepared,
            "claimed_uncertain" | "observed" => LaunchDispatchStage::ClaimedUncertain,
            _ => return Err(StoreError::Conflict("unknown launch outbox state")),
        };
        Ok(LaunchDispatchStatus {
            stage,
            receipt_ref: None,
        })
    }

    /// Persists the port's own outcome after its external call has returned.
    /// A missing row after a crash remains claimed-uncertain and cannot be resent.
    pub fn record_launch_port_result(
        &mut self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
        expected_owner_epoch: u64,
        claim_key: &str,
        result: LaunchPortResult,
    ) -> Result<LaunchDispatchStatus, StoreError> {
        valid_identity(scope_id)?;
        valid_identity(target_id)?;
        valid_identity(claim_key)?;
        let owner = i64::try_from(expected_owner_epoch)
            .map_err(|_| StoreError::InvalidInput("manager epoch exceeds SQLite range"))?;
        let (stage, receipt_ref) = match result {
            LaunchPortResult::RefusedBeforeEffect => ("refused_before_effect", None),
            LaunchPortResult::UncertainAfterPossibleEffect { receipt_ref } => {
                ("uncertain_after_possible_effect", receipt_ref)
            }
            LaunchPortResult::HostAccepted { receipt_ref } => ("host_accepted", receipt_ref),
            LaunchPortResult::PortSettled { receipt_ref } => ("port_settled", receipt_ref),
        };
        if let Some(reference) = &receipt_ref {
            valid_identity(reference)?;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_owner: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        if current_owner != owner {
            return Err(StoreError::StaleEpoch);
        }
        let row: Option<(String, String, String, String, Option<String>)> = transaction
            .query_row(
                "SELECT scope_id,target_id,kind,state,claim_key FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (scope, target, kind, state, prior_claim) = row.ok_or(StoreError::NotFound)?;
        if scope != scope_id || target != target_id {
            return Err(StoreError::WrongScope);
        }
        if kind != "pod.offer" {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if !matches!(state.as_str(), "claimed_uncertain" | "observed")
            || prior_claim.as_deref() != Some(claim_key)
        {
            return Err(StoreError::Conflict(
                "launch effect was not claimed by this identity",
            ));
        }
        let existing: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT stage,receipt_ref FROM launch_dispatch_outcomes WHERE outbox_id=?1",
                [outbox_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((old_stage, old_ref)) = existing {
            if old_stage != stage || old_ref != receipt_ref {
                return Err(StoreError::Conflict("launch port outcome changed"));
            }
        } else {
            transaction.execute(
                "INSERT INTO launch_dispatch_outcomes(
                   outbox_id,claim_key,stage,receipt_ref,recorded_at)
                 VALUES(?1,?2,?3,?4,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![outbox_id, claim_key, stage, receipt_ref],
            )?;
        }
        transaction.commit()?;
        Ok(LaunchDispatchStatus {
            stage: decode_stage(stage)?,
            receipt_ref,
        })
    }
}

fn decode_stage(value: &str) -> Result<LaunchDispatchStage, StoreError> {
    match value {
        "refused_before_effect" => Ok(LaunchDispatchStage::RefusedBeforeEffect),
        "uncertain_after_possible_effect" => Ok(LaunchDispatchStage::UncertainAfterPossibleEffect),
        "host_accepted" => Ok(LaunchDispatchStage::HostAccepted),
        "port_settled" => Ok(LaunchDispatchStage::PortSettled),
        _ => Err(StoreError::Conflict("unknown launch dispatch stage")),
    }
}

fn valid_identity(value: &str) -> Result<(), StoreError> {
    if value.len() < 3 || value.len() > 160 || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput("invalid launch identity"));
    }
    Ok(())
}
