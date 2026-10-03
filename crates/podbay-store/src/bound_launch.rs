//! Initial root-run admission. Every row, including authority and the outbox,
//! commits under one SQLite writer transaction. This module performs no OS effect.
use podbay_core::{
    AdmissionState, AttemptId, DesiredMode, Epoch, ExecutionState, InputEpoch, LaunchBinding,
    OwnerEpoch, PodId, ResourceId, ResourceKind, Revision, Role, Run, ScopeId, Session,
    SessionState, StoreLineageId, WorkKind,
};
use podbay_wire::{
    EFFECTIVE_LAUNCH_VERSION, EffectiveLaunchContract, ImmutableLaunchDescriptor,
    LAUNCH_DESCRIPTOR_SCHEMA, NativeResourceKind, NativeRole, NativeWorkKind,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::BTreeMap;

use crate::model::{
    CommandRequest, DIGEST_VERSION, LaunchLookupRequest, Receipt, StoreError, VerifiedPrincipal,
};
use crate::store::{
    PodBayStore, digest_request, integer, sha256_hex, stable_command_id, valid_id, validate_request,
};

const NAMESPACE: &str = "podbay.launch";

fn positive_stored_epoch(value: i64, reason: &'static str) -> Result<u64, StoreError> {
    if value <= 0 {
        return Err(StoreError::Conflict(reason));
    }
    Ok(value as u64)
}

/// Authenticated caller identity and exact caller bytes. A duplicate can omit
/// the proposal, so a profile change never changes the original receipt.
pub struct BoundLaunchRequest<'a> {
    pub principal: VerifiedPrincipal,
    pub command_key: &'a str,
    pub canonical_intent: &'a [u8],
    pub scope_id: &'a str,
    pub pod_id: &'a str,
    pub proposal: Option<BoundLaunchProposal<'a>>,
}

/// Trusted, reviewed snapshots for a new Session and its first root Run.
/// The store verifies their exact binding and fences; constructing this value
/// does not itself prove a host grant or policy review. Effective-spec bytes
/// receive only a version-prefix/hash check here: the host must verify policy
/// provenance before calling this method.
pub struct BoundLaunchProposal<'a> {
    pub session: &'a Session,
    pub run: &'a Run,
    pub binding: &'a LaunchBinding,
    pub effective_spec: &'a [u8],
    pub descriptor: &'a ImmutableLaunchDescriptor,
    pub expected_owner_epoch: u64,
    pub expected_authority_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundLaunchResource {
    pub ordinal: u64,
    pub id: String,
    pub kind: String,
    pub epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundLaunchRecord {
    pub receipt: Receipt,
    pub scope_id: String,
    pub session_id: String,
    pub run_id: String,
    pub attempt_id: String,
    pub pod_id: String,
    pub pod_incarnation: u64,
    pub resources: Vec<BoundLaunchResource>,
    pub effective_spec: Vec<u8>,
    pub descriptor: Vec<u8>,
}

/// One read-only, active-run candidate. It proves database associations at
/// one committed SQLite snapshot, not process liveness, launch authority or
/// a control grant; the host must still obtain fresh OS and pod evidence.
pub struct CurrentBoundPodSnapshot {
    store_lineage: StoreLineageId,
    owner_epoch: OwnerEpoch,
    authority_revision: u64,
    scope_id: ScopeId,
    pod_id: PodId,
    pod_incarnation: Epoch,
    attempt_id: AttemptId,
    attempt_ordinal: u64,
    attempt_epoch: Epoch,
    launch: BoundLaunchRecord,
    resources: Vec<CurrentBoundResource>,
}

pub struct CurrentBoundResource {
    id: ResourceId,
    kind: ResourceKind,
    epoch: Epoch,
    input_epoch: InputEpoch,
}

impl CurrentBoundPodSnapshot {
    pub fn store_lineage(&self) -> &StoreLineageId {
        &self.store_lineage
    }
    pub fn owner_epoch(&self) -> OwnerEpoch {
        self.owner_epoch
    }
    pub fn authority_revision(&self) -> u64 {
        self.authority_revision
    }
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn pod_id(&self) -> &PodId {
        &self.pod_id
    }
    pub fn pod_incarnation(&self) -> Epoch {
        self.pod_incarnation
    }
    pub fn attempt_id(&self) -> &AttemptId {
        &self.attempt_id
    }
    pub fn attempt_ordinal(&self) -> u64 {
        self.attempt_ordinal
    }
    pub fn attempt_epoch(&self) -> Epoch {
        self.attempt_epoch
    }
    pub fn launch(&self) -> &BoundLaunchRecord {
        &self.launch
    }
    pub fn resources(&self) -> &[CurrentBoundResource] {
        &self.resources
    }
}

impl CurrentBoundResource {
    pub fn id(&self) -> &ResourceId {
        &self.id
    }
    pub fn kind(&self) -> ResourceKind {
        self.kind
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn input_epoch(&self) -> InputEpoch {
        self.input_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundLaunchAdmission {
    Committed(BoundLaunchRecord),
    Duplicate(BoundLaunchRecord),
}

impl PodBayStore {
    /// Current bound Pod and resource context from one DEFERRED SQLite
    /// snapshot. Caller supplies only scope/PodId; historical command keys,
    /// principals and caller bytes cannot select or revive a stale launch.
    pub fn current_bound_pod_snapshot(
        &mut self,
        scope_id: &str,
        pod_id: &str,
    ) -> Result<CurrentBoundPodSnapshot, StoreError> {
        valid_id(scope_id)?;
        valid_id(pod_id)?;
        let scope = ScopeId::try_from(scope_id)
            .map_err(|_| StoreError::InvalidInput("scope ID is invalid"))?;
        let pod =
            PodId::try_from(pod_id).map_err(|_| StoreError::InvalidInput("Pod ID is invalid"))?;
        let cached_lineage = self.store_lineage.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let (lineage, owner, revision): (String, i64, i64) = transaction.query_row(
            "SELECT (SELECT lineage FROM store_identity WHERE singleton=1),
                    (SELECT value FROM metadata WHERE key='owner_epoch'),
                    (SELECT value FROM metadata WHERE key='authority_revision')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if lineage != cached_lineage {
            return Err(StoreError::WrongScope);
        }
        let owner = positive_stored_epoch(owner, "current owner epoch is invalid")?;
        let authority_revision =
            positive_stored_epoch(revision, "current authority revision is invalid")?;
        let registered: Option<(String, i64)> = transaction
            .query_row(
                "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
                [pod_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((registered_scope, incarnation)) = registered else {
            return Err(StoreError::NotFound);
        };
        if registered_scope != scope_id {
            return Err(StoreError::WrongScope);
        }
        let incarnation = positive_stored_epoch(incarnation, "current Pod incarnation is invalid")?;
        let target: Option<i64> = transaction
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![scope_id, pod_id],
                |row| row.get(0),
            )
            .optional()?;
        if target != Some(incarnation as i64) {
            return Err(StoreError::StaleEpoch);
        }
        let binding_rowid: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM launch_bindings
             WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                params![scope_id, pod_id, incarnation as i64],
                |row| row.get(0),
            )
            .optional()?;
        let Some(binding_rowid) = binding_rowid else {
            let historical: Option<i64> = transaction
                .query_row(
                    "SELECT command_rowid FROM launch_slots
                 WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                    params![scope_id, pod_id, incarnation as i64],
                    |row| row.get(0),
                )
                .optional()?;
            return if historical.is_some() {
                Err(StoreError::Conflict(
                    "historical launch has no bound v8 descriptor",
                ))
            } else {
                Err(StoreError::NotFound)
            };
        };
        let (bound_ordinal, bound_attempt_epoch): (i64, i64) = transaction.query_row(
            "SELECT attempt_ordinal,attempt_epoch FROM launch_bindings WHERE command_rowid=?1",
            [binding_rowid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let bound_ordinal =
            positive_stored_epoch(bound_ordinal, "bound attempt ordinal is invalid")?;
        let bound_attempt_epoch =
            positive_stored_epoch(bound_attempt_epoch, "bound attempt epoch is invalid")?;
        let launch = read_bound_record(&transaction, binding_rowid)?;
        let descriptor = ImmutableLaunchDescriptor::decode_json(&launch.descriptor)
            .map_err(|_| StoreError::Conflict("stored descriptor is malformed"))?;
        if descriptor.attempt_ordinal() != bound_ordinal
            || descriptor.attempt_epoch() != bound_attempt_epoch
        {
            return Err(StoreError::Conflict(
                "bound attempt differs from descriptor",
            ));
        }
        if launch.scope_id != scope_id
            || launch.pod_id != pod_id
            || launch.pod_incarnation != incarnation
        {
            return Err(StoreError::Conflict("current Pod binding differs"));
        }
        let session: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT state,current_run_id FROM runtime_sessions WHERE session_id=?1",
                [&launch.session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if session != Some(("open".into(), Some(launch.run_id.clone()))) {
            return Err(StoreError::Conflict(
                "current Session no longer points at bound Run",
            ));
        }
        let run: Option<(String, String, String, Option<String>, i64)> = transaction
            .query_row(
                "SELECT admission_state,desired_mode,execution_state,current_attempt_id,
                        last_attempt_ordinal FROM runtime_runs WHERE run_id=?1",
                [&launch.run_id],
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
        if !run.is_some_and(
            |(admission, desired, execution, current_attempt, ordinal)| {
                admission == "admitted"
                    && desired == "run"
                    && matches!(execution.as_str(), "starting" | "running")
                    && current_attempt.as_deref() == Some(launch.attempt_id.as_str())
                    && ordinal == bound_ordinal as i64
            },
        ) {
            return Err(StoreError::Conflict(
                "current Run is not active at the bound Attempt",
            ));
        }
        let mut authority = BTreeMap::new();
        let mut statement = transaction.prepare(
            "SELECT resource_id,scope_id,pod_incarnation,resource_epoch,input_epoch
             FROM authority_resources WHERE pod_id=?1 ORDER BY resource_id",
        )?;
        let rows = statement.query_map([pod_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        for row in rows {
            let (id, resource_scope, pod_incarnation, resource_epoch, input_epoch) = row?;
            if authority
                .insert(
                    id,
                    (resource_scope, pod_incarnation, resource_epoch, input_epoch),
                )
                .is_some()
            {
                return Err(StoreError::Conflict("duplicate current resource identity"));
            }
        }
        if authority.len() != launch.resources.len() {
            return Err(StoreError::Conflict(
                "current resource inventory differs from launch",
            ));
        }
        let mut resources = Vec::with_capacity(launch.resources.len());
        for bound in &launch.resources {
            let current = authority.remove(&bound.id).ok_or(StoreError::Conflict(
                "bound resource lacks current authority",
            ))?;
            if current.0 != scope_id
                || current.1 != incarnation as i64
                || current.2 != bound.epoch as i64
            {
                return Err(StoreError::Conflict("current resource association differs"));
            }
            let input = positive_stored_epoch(current.3, "current input epoch is invalid")?;
            let kind = match bound.kind.as_str() {
                "pty" => ResourceKind::Pty,
                "structured_provider" => ResourceKind::StructuredProvider,
                "auxiliary" => ResourceKind::Auxiliary,
                _ => return Err(StoreError::Conflict("unknown bound resource kind")),
            };
            resources.push(CurrentBoundResource {
                id: ResourceId::try_from(bound.id.as_str())
                    .map_err(|_| StoreError::Conflict("bound resource ID is invalid"))?,
                kind,
                epoch: Epoch::new(bound.epoch)
                    .map_err(|_| StoreError::Conflict("bound resource epoch is invalid"))?,
                input_epoch: InputEpoch::new(input)
                    .map_err(|_| StoreError::Conflict("current input epoch is invalid"))?,
            });
        }
        drop(statement);
        transaction.commit()?;
        Ok(CurrentBoundPodSnapshot {
            store_lineage: StoreLineageId::try_from(lineage.as_str())
                .map_err(|_| StoreError::Conflict("store lineage is invalid"))?,
            owner_epoch: OwnerEpoch::new(owner).map_err(|_| StoreError::StaleEpoch)?,
            authority_revision,
            scope_id: scope,
            pod_id: pod,
            pod_incarnation: Epoch::new(incarnation)
                .map_err(|_| StoreError::Conflict("current Pod incarnation is invalid"))?,
            attempt_id: AttemptId::try_from(launch.attempt_id.as_str())
                .map_err(|_| StoreError::Conflict("bound Attempt ID is invalid"))?,
            attempt_ordinal: bound_ordinal,
            attempt_epoch: Epoch::new(bound_attempt_epoch)
                .map_err(|_| StoreError::Conflict("bound attempt epoch is invalid"))?,
            launch,
            resources,
        })
    }

    /// Read-only pre-profile duplicate lookup. `None` is only a genuinely new
    /// caller key; an existing unbound command is a conflict, never a proposal.
    pub fn lookup_bound_launch(
        &mut self,
        request: &LaunchLookupRequest,
    ) -> Result<Option<BoundLaunchRecord>, StoreError> {
        for id in [&request.command_key, &request.scope_id, &request.target_id] {
            valid_id(id)?;
        }
        if request.namespace != NAMESPACE {
            return Err(StoreError::NotFound);
        }
        if request.canonical_intent.is_empty() || request.canonical_intent.len() > 1_048_576 {
            return Err(StoreError::InvalidInput(
                "canonical caller intent size is invalid",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row: Option<(i64, String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT command_rowid,scope_id,target_id,canonical_request FROM commands
             WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![request.principal.as_str(), NAMESPACE, request.command_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((rowid, scope, pod, canonical)) = row else {
            transaction.commit()?;
            return Ok(None);
        };
        if scope != request.scope_id || pod != request.target_id {
            return Err(StoreError::NotFound);
        }
        if canonical != request.canonical_intent {
            return Err(StoreError::Conflict(
                "command key changed canonical caller intent",
            ));
        }
        let record = read_bound_record(&transaction, rowid)?;
        transaction.commit()?;
        Ok(Some(record))
    }

    pub fn admit_bound_launch(
        &mut self,
        request: BoundLaunchRequest<'_>,
    ) -> Result<BoundLaunchAdmission, StoreError> {
        for id in [request.command_key, request.scope_id, request.pod_id] {
            valid_id(id)?;
        }
        if request.canonical_intent.is_empty() || request.canonical_intent.len() > 1_048_576 {
            return Err(StoreError::InvalidInput(
                "canonical caller intent size is invalid",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(i64, String, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT command_rowid,scope_id,target_id,canonical_request FROM commands
                 WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![request.principal.as_str(), NAMESPACE, request.command_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((rowid, scope, pod, caller_bytes)) = existing {
            if scope != request.scope_id || pod != request.pod_id {
                return Err(StoreError::NotFound);
            }
            if caller_bytes != request.canonical_intent {
                return Err(StoreError::Conflict(
                    "command key changed canonical caller intent",
                ));
            }
            // A v7 admission has no reviewed binding and is inspection-only.
            let record = read_bound_record(&transaction, rowid)?;
            transaction.commit()?;
            return Ok(BoundLaunchAdmission::Duplicate(record));
        }
        let proposal = request.proposal.as_ref().ok_or(StoreError::InvalidInput(
            "new bound launch requires reviewed proposal",
        ))?;
        validate_initial(&request, proposal)?;
        let binding = proposal.binding;
        let descriptor = proposal
            .descriptor
            .encode_json()
            .map_err(|_| StoreError::InvalidInput("launch descriptor cannot encode"))?;
        let effective = EffectiveLaunchContract::decode(proposal.effective_spec)
            .map_err(|_| StoreError::InvalidInput("effective launch bytes are malformed"))?;
        effective
            .compare_with_descriptor(proposal.descriptor)
            .map_err(|_| StoreError::Conflict("effective launch differs from descriptor"))?;
        let spec_digest = effective.digest().to_owned();
        let command = CommandRequest {
            principal: request.principal,
            namespace: NAMESPACE.into(),
            command_key: request.command_key.into(),
            scope_id: request.scope_id.into(),
            target_id: request.pod_id.into(),
            expected_owner_epoch: proposal.expected_owner_epoch,
            expected_target_epoch: binding.pod_incarnation().get(),
            canonical_request: request.canonical_intent.to_vec(),
            event_kind: "launch.bound".into(),
            event_payload: descriptor.clone(),
            effect_kind: "pod.offer".into(),
            effect_payload: descriptor.clone(),
        };
        validate_request(&command)?;
        let owner = integer(proposal.expected_owner_epoch)?;
        let authority_revision = integer(proposal.expected_authority_revision)?;
        let next_authority_revision = integer(
            proposal
                .expected_authority_revision
                .checked_add(1)
                .ok_or(StoreError::InvalidInput("authority revision exhausted"))?,
        )?;
        let pod_incarnation = integer(binding.pod_incarnation().get())?;
        let actual: (i64, i64) = transaction.query_row(
            "SELECT (SELECT value FROM metadata WHERE key='owner_epoch'),
                    (SELECT value FROM metadata WHERE key='authority_revision')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if actual != (owner, authority_revision) || owner == 0 {
            return Err(StoreError::StaleEpoch);
        }
        let prior_target: Option<i64> = transaction
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![request.scope_id, request.pod_id],
                |row| row.get(0),
            )
            .optional()?;
        if prior_target.is_some() {
            return Err(StoreError::Conflict("initial pod already has target epoch"));
        }
        let prior_session: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM runtime_sessions WHERE session_id=?1",
                [binding.session_id().as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if prior_session.is_some() {
            return Err(StoreError::Conflict("session writer already exists"));
        }
        transaction.execute(
            "INSERT INTO runtime_sessions(
               session_id,scope_id,actor_id,revision,state,current_run_id)
             VALUES(?1,?2,?3,?4,'open',?5)",
            params![
                binding.session_id().as_str(),
                binding.scope_id().as_str(),
                binding.actor_id().as_str(),
                integer(proposal.session.revision().get())?,
                binding.run_id().as_str(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO runtime_runs(
               run_id,session_id,scope_id,role,work_kind,parent_run_id,revision,
               admission_state,desired_mode,execution_state,current_attempt_id,last_attempt_ordinal)
             VALUES(?1,?2,?3,?4,?5,NULL,?6,'admitted','run','starting',?7,1)",
            params![
                binding.run_id().as_str(),
                binding.session_id().as_str(),
                binding.scope_id().as_str(),
                role_text(binding.role()),
                work_kind_text(binding.work_kind()),
                integer(proposal.run.revision().get())?,
                binding.attempt_id().as_str(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO authority_pods(pod_id,scope_id,incarnation) VALUES(?1,?2,?3)",
            params![
                binding.pod_id().as_str(),
                binding.scope_id().as_str(),
                pod_incarnation
            ],
        )?;
        transaction.execute(
            "INSERT INTO target_epochs(scope_id,target_id,epoch) VALUES(?1,?2,?3)",
            params![
                binding.scope_id().as_str(),
                binding.pod_id().as_str(),
                pod_incarnation
            ],
        )?;
        let digest = digest_request(&command);
        let command_id = stable_command_id(&command);
        transaction.execute(
            "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
               digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                command_id,
                command.principal.as_str(),
                command.namespace,
                command.command_key,
                command.scope_id,
                command.target_id,
                DIGEST_VERSION,
                digest,
                command.canonical_request,
                owner,
                pod_incarnation,
            ],
        )?;
        let command_rowid = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)
             VALUES(?1,?2,?3,?4)",
            params![
                binding.scope_id().as_str(),
                binding.pod_id().as_str(),
                pod_incarnation,
                command_rowid
            ],
        )?;
        transaction.execute(
            "INSERT INTO launch_bindings(
               command_rowid,scope_id,session_id,run_id,attempt_id,attempt_ordinal,
               attempt_epoch,pod_id,pod_incarnation,resource_count,
               effective_spec_version,effective_spec_digest,effective_spec,
               descriptor_version,descriptor_digest,descriptor)
             VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                command_rowid,
                binding.scope_id().as_str(),
                binding.session_id().as_str(),
                binding.run_id().as_str(),
                binding.attempt_id().as_str(),
                integer(binding.attempt_epoch().get())?,
                binding.pod_id().as_str(),
                pod_incarnation,
                integer(binding.resources().len() as u64)?,
                EFFECTIVE_LAUNCH_VERSION,
                spec_digest,
                proposal.effective_spec,
                LAUNCH_DESCRIPTOR_SCHEMA,
                proposal.descriptor.digest(),
                descriptor,
            ],
        )?;
        for (ordinal, resource) in binding.resources().iter().enumerate() {
            transaction.execute(
                "INSERT INTO launch_resources(command_rowid,resource_ordinal,resource_id,
                   resource_kind,resource_epoch) VALUES(?1,?2,?3,?4,?5)",
                params![
                    command_rowid,
                    integer(ordinal as u64)?,
                    resource.id().as_str(),
                    resource_kind_text(resource.kind()),
                    integer(resource.epoch().get())?,
                ],
            )?;
            transaction.execute(
                "INSERT INTO authority_resources(resource_id,scope_id,pod_id,pod_incarnation,
                   resource_epoch,input_epoch) VALUES(?1,?2,?3,?4,?5,1)",
                params![
                    resource.id().as_str(),
                    binding.scope_id().as_str(),
                    binding.pod_id().as_str(),
                    pod_incarnation,
                    integer(resource.epoch().get())?,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO events(event_id,schema_version,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,source_id,source_kind,source_epoch,source_sequence,
               source_digest,source_order,kind,payload,recorded_at,provenance,causation_id)
             VALUES('event.pb07.' || lower(hex(randomblob(16))),1,?1,?2,?3,?4,?5,?6,
                    'manager.admission',?4,1,?7,'contiguous','launch.bound',?8,
                    strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                    'authenticated.manager.admission',?6)",
            params![
                command_rowid,
                binding.scope_id().as_str(),
                binding.pod_id().as_str(),
                owner,
                pod_incarnation,
                command_id,
                digest,
                command.event_payload
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
               kind,payload,effect_digest,state)
             VALUES(?1,?2,?3,?4,?5,'pod.offer',?6,?7,'prepared')",
            params![
                command_rowid,
                binding.scope_id().as_str(),
                binding.pod_id().as_str(),
                owner,
                pod_incarnation,
                command.effect_payload,
                sha256_hex(&descriptor)
            ],
        )?;
        let outbox_id = transaction.last_insert_rowid();
        transaction.execute(
            "UPDATE commands SET event_sequence=?1,outbox_id=?2 WHERE command_rowid=?3",
            params![event_sequence, outbox_id, command_rowid],
        )?;
        let changed = transaction.execute(
            "UPDATE metadata SET value=?1 WHERE key='authority_revision' AND value=?2",
            params![next_authority_revision, authority_revision],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        let record = read_bound_record(&transaction, command_rowid)?;
        transaction.commit()?;
        Ok(BoundLaunchAdmission::Committed(record))
    }
}

fn validate_initial(
    request: &BoundLaunchRequest<'_>,
    proposal: &BoundLaunchProposal<'_>,
) -> Result<(), StoreError> {
    let session = proposal.session;
    let run = proposal.run;
    let binding = proposal.binding;
    if binding.parent_run_id().is_some()
        || binding.attempt_ordinal() != 1
        || binding.attempt_epoch().get() != 1
        || binding.pod_incarnation().get() != 1
        || binding
            .resources()
            .iter()
            .any(|resource| resource.epoch().get() != 1)
    {
        return Err(StoreError::InvalidInput(
            "only first root attempt is supported",
        ));
    }
    let first_session_revision = Revision::INITIAL
        .checked_next()
        .map_err(|_| StoreError::InvalidInput("initial revision exhausted"))?;
    let first_run_revision = first_session_revision
        .checked_next()
        .map_err(|_| StoreError::InvalidInput("initial revision exhausted"))?;
    if session.state() != SessionState::Open
        || session.revision() != first_session_revision
        || run.revision() != first_run_revision
        || run.admission() != AdmissionState::Admitted
        || run.desired() != DesiredMode::Run
        || run.execution() != ExecutionState::Starting
        || session.current_run_id() != Some(run.id())
        || run.current_attempt_id() != Some(binding.attempt_id())
        || run.last_attempt_ordinal() != 1
        || run.parent_run_id().is_some()
        || session.id() != binding.session_id()
        || session.actor_id() != binding.actor_id()
        || session.scope_id() != binding.scope_id()
        || run.id() != binding.run_id()
        || run.session_id() != binding.session_id()
        || run.actor_id() != binding.actor_id()
        || run.scope_id() != binding.scope_id()
        || run.role() != binding.role()
        || run.work_kind() != binding.work_kind()
        || binding.scope_id().as_str() != request.scope_id
        || binding.pod_id().as_str() != request.pod_id
    {
        return Err(StoreError::Conflict(
            "initial aggregates differ from launch binding",
        ));
    }
    proposal
        .descriptor
        .validate_against_binding(binding)
        .map_err(|_| StoreError::Conflict("descriptor differs from launch binding"))?;
    for (index, resource) in binding.resources().iter().enumerate() {
        let native = proposal
            .descriptor
            .resource(index)
            .ok_or(StoreError::Conflict("descriptor resource is missing"))?;
        if native.resource_id != resource.id().as_str()
            || native.epoch != resource.epoch().get()
            || native.kind != NativeResourceKind::from(resource.kind())
        {
            return Err(StoreError::Conflict("descriptor resource differs"));
        }
    }
    Ok(())
}

fn role_text(value: Role) -> &'static str {
    match value {
        Role::Coordinator => "coordinator",
        Role::Worker => "worker",
        Role::Advisor => "advisor",
    }
}
fn work_kind_text(value: WorkKind) -> &'static str {
    match value {
        WorkKind::Task => "task",
        WorkKind::Service => "service",
    }
}
fn resource_kind_text(value: ResourceKind) -> &'static str {
    match value {
        ResourceKind::Pty => "pty",
        ResourceKind::StructuredProvider => "structured_provider",
        ResourceKind::Auxiliary => "auxiliary",
    }
}

pub(crate) fn read_bound_record(
    transaction: &Transaction<'_>,
    rowid: i64,
) -> Result<BoundLaunchRecord, StoreError> {
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        Vec<u8>,
        String,
        Vec<u8>,
        String,
        Vec<u8>,
        String,
        i64,
        i64,
        i64,
        i64,
    )> = transaction
        .query_row(
            "SELECT c.command_id,c.scope_id,b.session_id,b.run_id,b.attempt_id,b.pod_id,
                    b.pod_incarnation,b.effective_spec_digest,b.effective_spec,
                    b.descriptor_digest,b.descriptor,c.request_digest,c.canonical_request,
                    c.principal,c.owner_epoch,c.target_epoch,c.event_sequence,c.outbox_id
             FROM commands c JOIN launch_bindings b ON b.command_rowid=c.command_rowid
             WHERE c.command_rowid=?1",
            [rowid],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                ))
            },
        )
        .optional()?;
    let (
        command_id,
        scope_id,
        session_id,
        run_id,
        attempt_id,
        pod_id,
        pod_incarnation,
        spec_digest,
        effective_spec,
        descriptor_digest,
        descriptor,
        request_digest,
        canonical,
        principal,
        owner,
        target_epoch,
        event_sequence,
        outbox_id,
    ) = row.ok_or(StoreError::Conflict(
        "historical launch has no bound v8 descriptor",
    ))?;
    let effective = EffectiveLaunchContract::decode(&effective_spec)
        .map_err(|_| StoreError::Conflict("stored effective launch is malformed"))?;
    if effective.digest() != spec_digest
        || sha256_hex(&effective_spec) != spec_digest
        || pod_incarnation != target_epoch
    {
        return Err(StoreError::Conflict(
            "bound launch identity or effective spec changed",
        ));
    }
    let command_identity: (String, String, String) = transaction.query_row(
        "SELECT namespace,target_id,digest_version FROM commands WHERE command_rowid=?1",
        [rowid],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if command_identity != (NAMESPACE.into(), pod_id.clone(), DIGEST_VERSION.into()) {
        return Err(StoreError::Conflict("bound command identity differs"));
    }
    let binding_facts: (String, String, i64, i64, i64, String, String) = transaction.query_row(
        "SELECT scope_id,attempt_id,attempt_ordinal,attempt_epoch,resource_count,
                effective_spec_version,descriptor_version
         FROM launch_bindings WHERE command_rowid=?1",
        [rowid],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )?;
    if binding_facts.0 != scope_id
        || binding_facts.1 != attempt_id
        || binding_facts.2 != 1
        || binding_facts.3 != 1
        || binding_facts.4 <= 0
        || binding_facts.5 != EFFECTIVE_LAUNCH_VERSION
        || binding_facts.6 != LAUNCH_DESCRIPTOR_SCHEMA
    {
        return Err(StoreError::Conflict(
            "bound launch version or attempt differs",
        ));
    }
    let session: Option<(String, String)> = transaction
        .query_row(
            "SELECT scope_id,actor_id
         FROM runtime_sessions WHERE session_id=?1",
            [&session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (session_scope, session_actor) =
        session.ok_or(StoreError::Conflict("bound session is missing"))?;
    let run: Option<(String, String, Option<String>, String, String)> = transaction
        .query_row(
            "SELECT session_id,scope_id,parent_run_id,role,work_kind
         FROM runtime_runs WHERE run_id=?1",
            [&run_id],
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
    let (run_session, run_scope, parent_run, run_role, run_work) =
        run.ok_or(StoreError::Conflict("bound run is missing"))?;
    if session_scope != scope_id
        || run_session != session_id
        || run_scope != scope_id
        || parent_run.is_some()
    {
        return Err(StoreError::Conflict(
            "bound session or run association differs",
        ));
    }
    let slot: Option<i64> = transaction
        .query_row(
            "SELECT command_rowid FROM launch_slots
         WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
            params![scope_id, pod_id, pod_incarnation],
            |row| row.get(0),
        )
        .optional()?;
    if slot != Some(rowid) {
        return Err(StoreError::Conflict("bound launch slot differs"));
    }
    let decoded = ImmutableLaunchDescriptor::decode_json(&descriptor)
        .map_err(|_| StoreError::Conflict("stored descriptor is malformed"))?;
    effective
        .compare_with_descriptor(&decoded)
        .map_err(|_| StoreError::Conflict("stored effective launch differs from descriptor"))?;
    if decoded.digest() != descriptor_digest
        || decoded.effective_spec_digest() != spec_digest
        || decoded.scope_id() != scope_id
        || decoded.session_id() != session_id
        || decoded.run_id() != run_id
        || decoded.attempt_id() != attempt_id
        || decoded.pod_id() != pod_id
        || decoded.pod_incarnation() != pod_incarnation as u64
        || decoded.actor_id() != session_actor
        || role_native_text(decoded.role()) != run_role
        || work_native_text(decoded.work_kind()) != run_work
        || decoded.parent_run_id().is_some()
        || decoded.attempt_ordinal() != 1
        || decoded.attempt_epoch() != 1
    {
        return Err(StoreError::Conflict(
            "stored descriptor differs from binding",
        ));
    }
    let event: Option<(String, Vec<u8>, String, String, i64, i64)> = transaction
        .query_row(
            "SELECT kind,payload,scope_id,target_id,owner_epoch,target_epoch
             FROM events WHERE sequence=?1 AND command_rowid=?2",
            params![event_sequence, rowid],
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
    let outbox: Option<(String, Vec<u8>, String, String, String, i64, i64)> = transaction
        .query_row(
            "SELECT kind,payload,effect_digest,scope_id,target_id,owner_epoch,target_epoch
             FROM outbox WHERE outbox_id=?1 AND command_rowid=?2",
            params![outbox_id, rowid],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    let (event_kind, event_payload, event_scope, event_target, event_owner, event_epoch) =
        event.ok_or(StoreError::Conflict("bound event is missing"))?;
    let (
        effect_kind,
        effect_payload,
        effect_digest,
        effect_scope,
        effect_target,
        effect_owner,
        effect_epoch,
    ) = outbox.ok_or(StoreError::Conflict("bound outbox is missing"))?;
    if event_kind != "launch.bound"
        || effect_kind != "pod.offer"
        || event_payload != descriptor
        || effect_payload != descriptor
        || sha256_hex(&effect_payload) != effect_digest
        || event_scope != scope_id
        || event_target != pod_id
        || event_owner != owner
        || event_epoch != target_epoch
        || effect_scope != scope_id
        || effect_target != pod_id
        || effect_owner != owner
        || effect_epoch != target_epoch
    {
        return Err(StoreError::Conflict("bound event or outbox differs"));
    }
    let principal = VerifiedPrincipal::from_authenticated_boundary(&principal)?;
    let command = CommandRequest {
        principal,
        namespace: NAMESPACE.into(),
        command_key: transaction.query_row(
            "SELECT command_key FROM commands WHERE command_rowid=?1",
            [rowid],
            |row| row.get(0),
        )?,
        scope_id: scope_id.clone(),
        target_id: pod_id.clone(),
        expected_owner_epoch: owner as u64,
        expected_target_epoch: target_epoch as u64,
        canonical_request: canonical,
        event_kind,
        event_payload,
        effect_kind,
        effect_payload,
    };
    if digest_request(&command) != request_digest || stable_command_id(&command) != command_id {
        return Err(StoreError::Conflict("bound command digest differs"));
    }
    let mut resources = Vec::new();
    let mut statement = transaction.prepare(
        "SELECT resource_ordinal,resource_id,resource_kind,resource_epoch
         FROM launch_resources WHERE command_rowid=?1 ORDER BY resource_ordinal",
    )?;
    let rows = statement.query_map([rowid], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?;
    for (expected, row) in rows.enumerate() {
        let (ordinal, id, kind, epoch) = row?;
        let native = decoded
            .resource(expected)
            .ok_or(StoreError::Conflict("bound resource count differs"))?;
        if ordinal != expected as i64
            || epoch != 1
            || native.resource_id != id
            || native.epoch != epoch as u64
            || native.kind != resource_kind_native(&kind)?
        {
            return Err(StoreError::Conflict(
                "bound resource differs from descriptor",
            ));
        }
        resources.push(BoundLaunchResource {
            ordinal: ordinal as u64,
            id,
            kind,
            epoch: epoch as u64,
        });
    }
    if resources.len() != decoded.resources_len() || resources.len() != binding_facts.4 as usize {
        return Err(StoreError::Conflict(
            "bound resource inventory is incomplete",
        ));
    }
    Ok(BoundLaunchRecord {
        receipt: Receipt {
            command_id,
            event_sequence,
            outbox_id,
            digest_version: DIGEST_VERSION,
            request_digest,
        },
        scope_id,
        session_id,
        run_id,
        attempt_id,
        pod_id,
        pod_incarnation: pod_incarnation as u64,
        resources,
        effective_spec,
        descriptor,
    })
}

fn resource_kind_native(value: &str) -> Result<NativeResourceKind, StoreError> {
    match value {
        "pty" => Ok(NativeResourceKind::Pty),
        "structured_provider" => Ok(NativeResourceKind::StructuredProvider),
        "auxiliary" => Ok(NativeResourceKind::Auxiliary),
        _ => Err(StoreError::Conflict("unknown bound resource kind")),
    }
}

fn role_native_text(value: NativeRole) -> &'static str {
    match value {
        NativeRole::Coordinator => "coordinator",
        NativeRole::Worker => "worker",
        NativeRole::Advisor => "advisor",
    }
}

fn work_native_text(value: NativeWorkKind) -> &'static str {
    match value {
        NativeWorkKind::Task => "task",
        NativeWorkKind::Service => "service",
    }
}

/// Current-state gate for a *new* outbox claim. Immutable receipt lookup never
/// calls this: an ended run or newer pod incarnation cannot erase its history.
pub(crate) fn ensure_current_dispatch_eligible(
    transaction: &Transaction<'_>,
    record: &BoundLaunchRecord,
) -> Result<(), StoreError> {
    let session: Option<(String, Option<String>)> = transaction
        .query_row(
            "SELECT state,current_run_id FROM runtime_sessions WHERE session_id=?1",
            [&record.session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let run: Option<(String, String, String, Option<String>, i64)> = transaction
        .query_row(
            "SELECT admission_state,desired_mode,execution_state,current_attempt_id,
                last_attempt_ordinal FROM runtime_runs WHERE run_id=?1",
            [&record.run_id],
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
    if session != Some(("open".into(), Some(record.run_id.clone())))
        || run
            != Some((
                "admitted".into(),
                "run".into(),
                "starting".into(),
                Some(record.attempt_id.clone()),
                1,
            ))
    {
        return Err(StoreError::Conflict(
            "bound launch is no longer dispatch eligible",
        ));
    }
    let pod: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [&record.pod_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let target: Option<i64> = transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![record.scope_id, record.pod_id],
            |row| row.get(0),
        )
        .optional()?;
    if pod != Some((record.scope_id.clone(), record.pod_incarnation as i64))
        || target != Some(record.pod_incarnation as i64)
    {
        return Err(StoreError::StaleEpoch);
    }
    for resource in &record.resources {
        let authority: Option<(String, String, i64, i64, i64)> = transaction
            .query_row(
                "SELECT scope_id,pod_id,pod_incarnation,resource_epoch,input_epoch
             FROM authority_resources WHERE resource_id=?1",
                [&resource.id],
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
        if authority.is_none_or(|(scope, pod, incarnation, epoch, input_epoch)| {
            scope != record.scope_id
                || pod != record.pod_id
                || incarnation != record.pod_incarnation as i64
                || epoch != resource.epoch as i64
                || input_epoch <= 0
        }) {
            return Err(StoreError::StaleEpoch);
        }
    }
    Ok(())
}
