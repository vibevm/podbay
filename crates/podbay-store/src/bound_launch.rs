//! Initial root-run admission. Every row, including authority and the outbox,
//! commits under one SQLite writer transaction. This module performs no OS effect.
use podbay_core::{
    AdmissionState, Attempt, AttemptId, CommandAdmission, CommandId, DesiredMode, Epoch,
    ExecutionState, InputEpoch, LaunchBinding, OwnerEpoch, PlannedRootBinding, PodId, ResourceId,
    ResourceKind, Revision, Role, Run, RunCommandKind, RunId, ScopeId, Session, SessionId,
    SessionState, StoreLineageId, WorkKind,
};
use podbay_wire::{
    EFFECTIVE_LAUNCH_V2_VERSION, EFFECTIVE_LAUNCH_VERSION, EffectiveLaunchContract,
    EffectiveLaunchContractV2, ImmutableLaunchDescriptor, ImmutableLaunchDescriptorV2,
    LAUNCH_DESCRIPTOR_SCHEMA, LAUNCH_DESCRIPTOR_V2_SCHEMA, NativeResourceKind, NativeRole,
    NativeWorkKind,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use std::collections::BTreeMap;

use crate::model::{
    CommandRequest, DIGEST_VERSION, LaunchKeyLookupRequest, LaunchLookupRequest, Receipt,
    StoreError, VerifiedPrincipal,
};
use crate::store::{
    PodBayStore, digest_request, integer, sha256_hex, stable_command_id, valid_id, validate_request,
};

const NAMESPACE: &str = "podbay.launch";
const CURRENT_V2_REBIND_PAGE_SIZE: usize = 128;

/// Store-issued cursor. Its exact lineage, owner epoch and authority revision
/// bind every later page to the first manager view; callers cannot construct
/// a cursor from arbitrary selector text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentV2RebindCursor {
    scope_id: ScopeId,
    pod_id: PodId,
    store_lineage: StoreLineageId,
    owner_epoch: u64,
    authority_revision: u64,
}

pub struct CurrentV2RebindPage {
    candidates: Vec<(ScopeId, PodId)>,
    next_cursor: Option<CurrentV2RebindCursor>,
}

impl CurrentV2RebindPage {
    pub fn candidates(&self) -> &[(ScopeId, PodId)] {
        &self.candidates
    }
    pub fn next_cursor(&self) -> Option<&CurrentV2RebindCursor> {
        self.next_cursor.as_ref()
    }
}

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

/// Trusted, reviewed V1 snapshots for a new Session and its first root Run.
/// The store verifies their exact binding and fences; constructing this value
/// does not itself prove a host grant or policy review. The host must verify
/// policy provenance before calling this method.
pub struct BoundLaunchProposal<'a> {
    pub session: &'a Session,
    pub run: &'a Run,
    pub binding: &'a LaunchBinding,
    pub effective_spec: &'a [u8],
    pub descriptor: &'a ImmutableLaunchDescriptor,
    pub expected_owner_epoch: u64,
    pub expected_authority_revision: u64,
}

/// Reviewed internal Codex V2 proof for a new first root launch. Both values are
/// typed and canonical before the store checks them again under one writer
/// transaction. This cannot admit a child Worker of an existing parent Run
/// and does not itself grant host launch authority.
pub struct BoundRootLaunchProposalV2<'a> {
    pub session: &'a Session,
    pub run: &'a Run,
    pub binding: &'a PlannedRootBinding,
    pub effective_spec: &'a EffectiveLaunchContractV2,
    pub descriptor: &'a ImmutableLaunchDescriptorV2,
    pub expected_owner_epoch: u64,
    pub expected_authority_revision: u64,
}

/// The caller requests one new Session and its first root Run. A Worker/Task
/// here is a root Worker, not a delegated child of an existing Run.
pub struct BoundRootLaunchRequestV2<'a> {
    pub principal: VerifiedPrincipal,
    pub command_key: &'a str,
    pub canonical_intent: &'a [u8],
    pub scope_id: &'a str,
    pub pod_id: &'a str,
    pub proposal: Option<BoundRootLaunchProposalV2<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundLaunchFormat {
    V1,
    CodexV2,
}

impl BoundLaunchFormat {
    fn effective_version(self) -> &'static str {
        match self {
            Self::V1 => EFFECTIVE_LAUNCH_VERSION,
            Self::CodexV2 => EFFECTIVE_LAUNCH_V2_VERSION,
        }
    }

    fn descriptor_version(self) -> &'static str {
        match self {
            Self::V1 => LAUNCH_DESCRIPTOR_SCHEMA,
            Self::CodexV2 => LAUNCH_DESCRIPTOR_V2_SCHEMA,
        }
    }
}

enum ProposalKind<'a> {
    V1(BoundLaunchProposal<'a>),
    CodexV2(BoundRootLaunchProposalV2<'a>),
}

struct AdmissionRequest<'a> {
    principal: VerifiedPrincipal,
    command_key: &'a str,
    canonical_intent: &'a [u8],
    scope_id: &'a str,
    pod_id: &'a str,
    proposal: Option<ProposalKind<'a>>,
    format: BoundLaunchFormat,
}

struct CheckedProposal<'a> {
    session: &'a Session,
    run: &'a Run,
    binding: &'a LaunchBinding,
    planned_binding: Option<&'a PlannedRootBinding>,
    effective_spec: &'a [u8],
    descriptor: Vec<u8>,
    spec_digest: String,
    descriptor_digest: String,
    format: BoundLaunchFormat,
    max_children: u32,
    expected_owner_epoch: u64,
    expected_authority_revision: u64,
}

/// This witness exists only while the same SQLite writer transaction contains
/// the exact command row. It cannot be constructed by a proposal or returned
/// to a caller as a substitute for durable admission.
struct InsertedRootCommand<'a, 'connection> {
    transaction: &'a Transaction<'connection>,
    rowid: i64,
    command_id: CommandId,
    run_id: RunId,
    principal: String,
    command_key: String,
    scope_id: String,
    pod_id: String,
    request_digest: String,
    canonical_intent: Vec<u8>,
    owner_epoch: i64,
    target_epoch: i64,
}

impl CommandAdmission for InsertedRootCommand<'_, '_> {
    fn admits_run(&self, command_id: &CommandId, run_id: &RunId, kind: RunCommandKind) -> bool {
        if kind != RunCommandKind::Launch
            || command_id != &self.command_id
            || run_id != &self.run_id
        {
            return false;
        }
        self.transaction
            .query_row(
                "SELECT command_id,principal,namespace,command_key,scope_id,target_id,
                        digest_version,request_digest,canonical_request,owner_epoch,target_epoch
                 FROM commands WHERE command_rowid=?1",
                [self.rowid],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .is_ok_and(|row| {
                row == (
                    self.command_id.as_str().to_owned(),
                    self.principal.clone(),
                    NAMESPACE.into(),
                    self.command_key.clone(),
                    self.scope_id.clone(),
                    self.pod_id.clone(),
                    DIGEST_VERSION.into(),
                    self.request_digest.clone(),
                    self.canonical_intent.clone(),
                    self.owner_epoch,
                    self.target_epoch,
                )
            })
    }
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
    pub format: BoundLaunchFormat,
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

/// A read-only lifetime child-admission budget tied to one scoped Run. It is
/// not a reservation, parent-liveness observation, or launch authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunChildBudget {
    scope_id: ScopeId,
    run_id: RunId,
    max_children: u32,
    reserved_children: u32,
}

impl RunChildBudget {
    pub fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }
    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }
    pub fn max_children(&self) -> u32 {
        self.max_children
    }
    pub fn reserved_children(&self) -> u32 {
        self.reserved_children
    }
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

/// Store-issued parent snapshot for a proposed first child. Its private
/// fields cannot be supplied as caller JSON. It proves current SQLite links
/// and budget only; the host must separately attest the live parent pod and
/// authenticated delegating actor before any child admission or OS effect.
pub struct CurrentDelegatingParentSnapshot {
    current: CurrentBoundPodSnapshot,
    parent_run_id: RunId,
    parent_session_id: SessionId,
    parent_session_actor_id: podbay_core::ActorId,
    session_revision: Revision,
    run_revision: Revision,
    budget: RunChildBudget,
}

impl CurrentDelegatingParentSnapshot {
    pub fn current_pod(&self) -> &CurrentBoundPodSnapshot {
        &self.current
    }
    pub fn parent_run_id(&self) -> &RunId {
        &self.parent_run_id
    }
    pub fn parent_session_id(&self) -> &SessionId {
        &self.parent_session_id
    }
    pub fn parent_session_actor_id(&self) -> &podbay_core::ActorId {
        &self.parent_session_actor_id
    }
    pub fn session_revision(&self) -> Revision {
        self.session_revision
    }
    pub fn run_revision(&self) -> Revision {
        self.run_revision
    }
    pub fn budget(&self) -> &RunChildBudget {
        &self.budget
    }
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

fn read_current_delegating_parent(
    transaction: &Transaction<'_>,
    current: &CurrentBoundPodSnapshot,
) -> Result<(podbay_core::ActorId, Revision, Revision, RunChildBudget), StoreError> {
    let launch = current.launch();
    let metadata: (String, i64, i64) = transaction.query_row(
        "SELECT (SELECT lineage FROM store_identity WHERE singleton=1),
                (SELECT value FROM metadata WHERE key='owner_epoch'),
                (SELECT value FROM metadata WHERE key='authority_revision')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if metadata
        != (
            current.store_lineage.as_str().to_owned(),
            integer(current.owner_epoch.get())?,
            integer(current.authority_revision)?,
        )
    {
        return Err(StoreError::StaleEpoch);
    }
    let session: Option<(String, String, String, Option<String>, i64)> = transaction
        .query_row(
            "SELECT scope_id,actor_id,state,current_run_id,revision
             FROM runtime_sessions WHERE session_id=?1",
            [&launch.session_id],
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
    let Some((session_scope, session_actor, state, current_run, session_revision)) = session else {
        return Err(StoreError::Conflict("delegating parent Session is missing"));
    };
    if session_scope != launch.scope_id
        || state != "open"
        || current_run.as_deref() != Some(launch.run_id.as_str())
    {
        return Err(StoreError::StaleEpoch);
    }
    let run: Option<(
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        Option<String>,
        i64,
    )> = transaction
        .query_row(
            "SELECT session_id,scope_id,role,work_kind,parent_run_id,revision,
                    admission_state,desired_mode,execution_state,current_attempt_id,
                    last_attempt_ordinal FROM runtime_runs WHERE run_id=?1",
            [&launch.run_id],
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
                ))
            },
        )
        .optional()?;
    let Some((
        run_session,
        run_scope,
        role,
        work,
        parent_run,
        run_revision,
        admission,
        desired,
        execution,
        attempt,
        ordinal,
    )) = run
    else {
        return Err(StoreError::Conflict("delegating parent Run is missing"));
    };
    if run_session != launch.session_id
        || run_scope != launch.scope_id
        || role != "coordinator"
        || work != "service"
        || parent_run.is_some()
        || admission != "admitted"
        || desired != "run"
        || !matches!(execution.as_str(), "starting" | "running")
        || attempt.as_deref() != Some(launch.attempt_id.as_str())
        || ordinal != 1
    {
        return Err(StoreError::Conflict(
            "delegating parent is not an active Coordinator/Service",
        ));
    }
    let pod: Option<(String, i64)> = transaction
        .query_row(
            "SELECT scope_id,incarnation FROM authority_pods WHERE pod_id=?1",
            [&launch.pod_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let target: Option<i64> = transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![launch.scope_id, launch.pod_id],
            |row| row.get(0),
        )
        .optional()?;
    let binding: Option<(String, String, i64, i64)> = transaction
        .query_row(
            "SELECT run_id,attempt_id,pod_incarnation,command_rowid FROM launch_bindings
             WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
            params![
                launch.scope_id,
                launch.pod_id,
                integer(launch.pod_incarnation)?
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    if pod != Some((launch.scope_id.clone(), integer(launch.pod_incarnation)?))
        || target != Some(integer(launch.pod_incarnation)?)
        || !binding
            .as_ref()
            .is_some_and(|(run, attempt, incarnation, _)| {
                run == &launch.run_id
                    && attempt == &launch.attempt_id
                    && *incarnation == launch.pod_incarnation as i64
            })
    {
        return Err(StoreError::StaleEpoch);
    }
    let (_, _, _, command_rowid) = binding.expect("binding checked above");
    if read_bound_record(transaction, command_rowid)? != *launch {
        return Err(StoreError::StaleEpoch);
    }
    for resource in &current.resources {
        let authority: Option<(String, String, i64, i64, i64)> = transaction
            .query_row(
                "SELECT scope_id,pod_id,pod_incarnation,resource_epoch,input_epoch
                 FROM authority_resources WHERE resource_id=?1",
                [resource.id.as_str()],
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
        if authority
            != Some((
                launch.scope_id.clone(),
                launch.pod_id.clone(),
                integer(launch.pod_incarnation)?,
                integer(resource.epoch.get())?,
                integer(resource.input_epoch.get())?,
            ))
        {
            return Err(StoreError::StaleEpoch);
        }
    }
    let budget: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT max_children,reserved_children FROM run_child_budgets WHERE run_id=?1",
            [&launch.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (maximum, reserved) =
        budget.ok_or(StoreError::Conflict("parent child budget is missing"))?;
    let maximum = u32::try_from(maximum)
        .map_err(|_| StoreError::Conflict("parent child budget is invalid"))?;
    let reserved = u32::try_from(reserved)
        .map_err(|_| StoreError::Conflict("parent child reservation is invalid"))?;
    if reserved >= maximum {
        return Err(StoreError::Conflict("parent child budget is exhausted"));
    }
    Ok((
        podbay_core::ActorId::try_from(session_actor.as_str())
            .map_err(|_| StoreError::Conflict("parent Session actor ID is invalid"))?,
        Revision::new(positive_stored_epoch(
            session_revision,
            "parent Session revision is invalid",
        )?)
        .map_err(|_| StoreError::Conflict("parent Session revision is invalid"))?,
        Revision::new(positive_stored_epoch(
            run_revision,
            "parent Run revision is invalid",
        )?)
        .map_err(|_| StoreError::Conflict("parent Run revision is invalid"))?,
        RunChildBudget {
            scope_id: current.scope_id.clone(),
            run_id: RunId::try_from(launch.run_id.as_str())
                .map_err(|_| StoreError::Conflict("parent Run ID is invalid"))?,
            max_children: maximum,
            reserved_children: reserved,
        },
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundLaunchAdmission {
    Committed(BoundLaunchRecord),
    Duplicate(BoundLaunchRecord),
}

impl PodBayStore {
    /// One indexed page of current V2 selectors in `(scope_id,pod_id)` order.
    /// The target-epoch key drives indexed Pod/binding lookups; no command or
    /// event log is scanned. Host revalidates each complete binding and live
    /// OS pod before any rebind effect. Mixed-version bindings fail closed.
    pub fn current_codex_v2_rebind_page(
        &mut self,
        cursor: Option<&CurrentV2RebindCursor>,
        expected_owner_epoch: u64,
        expected_authority_revision: u64,
    ) -> Result<CurrentV2RebindPage, StoreError> {
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
        if lineage != self.store_lineage
            || owner != expected_owner_epoch as i64
            || revision != expected_authority_revision as i64
        {
            return Err(StoreError::StaleEpoch);
        }
        let (after_scope, after_pod) = match cursor {
            Some(value)
                if value.store_lineage.as_str() == lineage
                    && value.owner_epoch == expected_owner_epoch
                    && value.authority_revision == expected_authority_revision =>
            {
                (value.scope_id.as_str(), value.pod_id.as_str())
            }
            Some(_) => return Err(StoreError::StaleEpoch),
            None => ("", ""),
        };
        let mut statement = transaction.prepare(
            "SELECT t.scope_id,t.target_id,b.effective_spec_version,b.descriptor_version
             FROM target_epochs AS t
             CROSS JOIN authority_pods AS p
             CROSS JOIN launch_bindings AS b
             WHERE (t.scope_id,t.target_id)>(?1,?2)
               AND t.scope_id=p.scope_id AND t.target_id=p.pod_id
               AND t.epoch=p.incarnation
               AND b.scope_id=p.scope_id AND b.pod_id=p.pod_id
               AND b.pod_incarnation=p.incarnation
               AND (b.effective_spec_version=?3 OR b.descriptor_version=?4)
             ORDER BY t.scope_id,t.target_id LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                after_scope,
                after_pod,
                EFFECTIVE_LAUNCH_V2_VERSION,
                LAUNCH_DESCRIPTOR_V2_SCHEMA,
                (CURRENT_V2_REBIND_PAGE_SIZE + 1) as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?;
        let mut candidates = Vec::new();
        for row in rows {
            let (scope, pod, effective, descriptor) = row?;
            if effective != EFFECTIVE_LAUNCH_V2_VERSION || descriptor != LAUNCH_DESCRIPTOR_V2_SCHEMA
            {
                return Err(StoreError::Conflict(
                    "current V2 launch version pair differs",
                ));
            }
            candidates.push((
                ScopeId::try_from(scope.as_str())
                    .map_err(|_| StoreError::Conflict("current V2 scope ID is malformed"))?,
                PodId::try_from(pod.as_str())
                    .map_err(|_| StoreError::Conflict("current V2 Pod ID is malformed"))?,
            ));
        }
        let has_more = candidates.len() > CURRENT_V2_REBIND_PAGE_SIZE;
        candidates.truncate(CURRENT_V2_REBIND_PAGE_SIZE);
        let next_cursor = if has_more {
            let (scope_id, pod_id) = candidates
                .last()
                .ok_or(StoreError::Conflict("current V2 page cursor is empty"))?;
            Some(CurrentV2RebindCursor {
                scope_id: scope_id.clone(),
                pod_id: pod_id.clone(),
                store_lineage: StoreLineageId::try_from(lineage.as_str())
                    .map_err(|_| StoreError::Conflict("current V2 lineage is malformed"))?,
                owner_epoch: expected_owner_epoch,
                authority_revision: expected_authority_revision,
            })
        } else {
            None
        };
        drop(statement);
        transaction.commit()?;
        Ok(CurrentV2RebindPage {
            candidates,
            next_cursor,
        })
    }

    /// Read the exact current parent Run/Pod in a validated store snapshot,
    /// then pin its mutable rows under an IMMEDIATE transaction. This is not
    /// process liveness, an actor grant or a child reservation.
    pub fn preflight_delegating_parent(
        &mut self,
        scope_id: &ScopeId,
        parent_run_id: &RunId,
        parent_pod_id: &PodId,
    ) -> Result<CurrentDelegatingParentSnapshot, StoreError> {
        let current = self.current_bound_pod_snapshot(scope_id.as_str(), parent_pod_id.as_str())?;
        if current.launch().run_id != parent_run_id.as_str() {
            return Err(StoreError::WrongScope);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (parent_session_actor_id, session_revision, run_revision, budget) =
            read_current_delegating_parent(&transaction, &current)?;
        transaction.commit()?;
        Ok(CurrentDelegatingParentSnapshot {
            parent_run_id: parent_run_id.clone(),
            parent_session_id: SessionId::try_from(current.launch().session_id.as_str())
                .map_err(|_| StoreError::Conflict("parent Session ID is invalid"))?,
            parent_session_actor_id,
            current,
            session_revision,
            run_revision,
            budget,
        })
    }

    /// Re-read the parent, owner, authority and budget rows under the same
    /// writer-lock kind that a future child admission must use. This separate
    /// read transaction does not reserve capacity; future admission must call
    /// the private recheck inside its own mutation transaction.
    pub fn recheck_delegating_parent(
        &mut self,
        witness: &CurrentDelegatingParentSnapshot,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (session_actor, session_revision, run_revision, budget) =
            read_current_delegating_parent(&transaction, &witness.current)?;
        if session_actor != witness.parent_session_actor_id
            || session_revision != witness.session_revision
            || run_revision != witness.run_revision
            || budget != witness.budget
        {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Inspect a Run's committed budget only through its exact scope. A
    /// missing budget row is corruption, not permission to infer capacity.
    pub fn inspect_run_child_budget(
        &self,
        scope_id: &ScopeId,
        run_id: &RunId,
    ) -> Result<RunChildBudget, StoreError> {
        let row: Option<(Option<i64>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT budget.max_children,budget.reserved_children
                 FROM runtime_runs AS run
                 LEFT JOIN run_child_budgets AS budget ON budget.run_id=run.run_id
                 WHERE run.scope_id=?1 AND run.run_id=?2",
                params![scope_id.as_str(), run_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (Some(max), Some(reserved)) = row.ok_or(StoreError::NotFound)? else {
            return Err(StoreError::Conflict("Run child budget is missing"));
        };
        let max_children = u32::try_from(max)
            .map_err(|_| StoreError::Conflict("Run child budget maximum is invalid"))?;
        let reserved_children = u32::try_from(reserved)
            .map_err(|_| StoreError::Conflict("Run child budget reservation is invalid"))?;
        if reserved_children > max_children {
            return Err(StoreError::Conflict(
                "Run child budget reservation exceeds maximum",
            ));
        }
        Ok(RunChildBudget {
            scope_id: scope_id.clone(),
            run_id: run_id.clone(),
            max_children,
            reserved_children,
        })
    }

    /// Indexed historical V2 root selector for an authenticated principal.
    /// It returns the exact immutable command binding from one read snapshot;
    /// the host must separately prove today's Session, Run, Pod, Resource,
    /// manager and writer lease before using it as a current guard readback.
    pub fn lookup_bound_root_v2_by_command_id(
        &mut self,
        principal: &VerifiedPrincipal,
        scope: &ScopeId,
        command_id: &CommandId,
    ) -> Result<Option<BoundLaunchRecord>, StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rowid: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM commands
                 WHERE command_id=?1 AND principal=?2 AND scope_id=?3 AND namespace=?4",
                params![
                    command_id.as_str(),
                    principal.as_str(),
                    scope.as_str(),
                    NAMESPACE
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(rowid) = rowid else {
            transaction.commit()?;
            return Ok(None);
        };
        let record = read_bound_record(&transaction, rowid)?;
        if record.format != BoundLaunchFormat::CodexV2
            || record.scope_id != scope.as_str()
            || record.receipt.command_id != command_id.as_str()
            || record.resources.len() != 1
            || record.resources[0].kind != "structured_provider"
        {
            return Err(StoreError::Conflict("indexed V2 root binding differs"));
        }
        transaction.commit()?;
        Ok(Some(record))
    }

    /// Read an existing bound launch before a manager mints any Session, Run,
    /// Attempt, Pod, or Resource IDs. A miss permits planning; a changed
    /// canonical caller intent conflicts and must never mint another launch.
    /// This does not authorize dispatch or prove that the pod is current.
    pub fn lookup_bound_launch_by_key(
        &mut self,
        request: &LaunchKeyLookupRequest,
    ) -> Result<Option<BoundLaunchRecord>, StoreError> {
        valid_id(&request.command_key)?;
        valid_id(&request.scope_id)?;
        if request.canonical_intent.is_empty() || request.canonical_intent.len() > 1_048_576 {
            return Err(StoreError::InvalidInput(
                "canonical caller intent size is invalid",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row: Option<(i64, String, Vec<u8>)> = transaction
            .query_row(
                "SELECT command_rowid,scope_id,canonical_request FROM commands
                 WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![request.principal.as_str(), NAMESPACE, request.command_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((rowid, scope, canonical)) = row else {
            transaction.commit()?;
            return Ok(None);
        };
        if scope != request.scope_id {
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
        let (attempt_ordinal, attempt_epoch) = match launch.format {
            BoundLaunchFormat::V1 => {
                let descriptor = ImmutableLaunchDescriptor::decode_json(&launch.descriptor)
                    .map_err(|_| StoreError::Conflict("stored descriptor is malformed"))?;
                (descriptor.attempt_ordinal(), descriptor.attempt_epoch())
            }
            BoundLaunchFormat::CodexV2 => {
                let descriptor = ImmutableLaunchDescriptorV2::decode_json(&launch.descriptor)
                    .map_err(|_| StoreError::Conflict("stored V2 descriptor is malformed"))?;
                (descriptor.attempt_ordinal(), descriptor.attempt_epoch())
            }
        };
        if attempt_ordinal != bound_ordinal || attempt_epoch != bound_attempt_epoch {
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
        self.admit_bound_launch_internal(AdmissionRequest {
            principal: request.principal,
            command_key: request.command_key,
            canonical_intent: request.canonical_intent,
            scope_id: request.scope_id,
            pod_id: request.pod_id,
            proposal: request.proposal.map(ProposalKind::V1),
            format: BoundLaunchFormat::V1,
        })
    }

    /// Admits only a new first root Session/Run/Attempt. Child Worker/Task
    /// admission requires a separate parent-Run transaction and authority gate.
    pub fn admit_bound_root_launch_v2(
        &mut self,
        request: BoundRootLaunchRequestV2<'_>,
    ) -> Result<BoundLaunchAdmission, StoreError> {
        self.admit_bound_launch_internal(AdmissionRequest {
            principal: request.principal,
            command_key: request.command_key,
            canonical_intent: request.canonical_intent,
            scope_id: request.scope_id,
            pod_id: request.pod_id,
            proposal: request.proposal.map(ProposalKind::CodexV2),
            format: BoundLaunchFormat::CodexV2,
        })
    }

    fn admit_bound_launch_internal(
        &mut self,
        request: AdmissionRequest<'_>,
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
            if record.format != request.format {
                return Err(StoreError::Conflict(
                    "command key changed bound launch format",
                ));
            }
            transaction.commit()?;
            return Ok(BoundLaunchAdmission::Duplicate(record));
        }
        let proposal = request.proposal.as_ref().ok_or(StoreError::InvalidInput(
            "new bound launch requires reviewed proposal",
        ))?;
        let checked = check_proposal(&request, proposal)?;
        if checked.format != request.format {
            return Err(StoreError::Conflict("reviewed launch format differs"));
        }
        let binding = checked.binding;
        let descriptor = checked.descriptor.clone();
        let spec_digest = checked.spec_digest.clone();
        let command = CommandRequest {
            principal: request.principal,
            namespace: NAMESPACE.into(),
            command_key: request.command_key.into(),
            scope_id: request.scope_id.into(),
            target_id: request.pod_id.into(),
            expected_owner_epoch: checked.expected_owner_epoch,
            expected_target_epoch: binding.pod_incarnation().get(),
            canonical_request: request.canonical_intent.to_vec(),
            event_kind: "launch.bound".into(),
            event_payload: descriptor.clone(),
            effect_kind: "pod.offer".into(),
            effect_payload: descriptor.clone(),
        };
        validate_request(&command)?;
        let owner = integer(checked.expected_owner_epoch)?;
        let authority_revision = integer(checked.expected_authority_revision)?;
        let next_authority_revision = integer(
            checked
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
        let digest = digest_request(&command);
        let command_id = stable_command_id(&command);
        // V2 needs a real row before Run::admit. V1 keeps its original SQL
        // ordering; both formats still commit all rows in one transaction.
        let early_command_rowid = (checked.format == BoundLaunchFormat::CodexV2)
            .then(|| {
                insert_launch_command(
                    &transaction,
                    &command,
                    &command_id,
                    &digest,
                    owner,
                    pod_incarnation,
                )
            })
            .transpose()?;
        let admitted_run = if checked.format == BoundLaunchFormat::CodexV2 {
            let command_identity = CommandId::try_from(command_id.as_str())
                .map_err(|_| StoreError::Conflict("V2 command identity is invalid"))?;
            let witness = InsertedRootCommand {
                transaction: &transaction,
                rowid: early_command_rowid.expect("V2 inserted command before admission"),
                command_id: command_identity.clone(),
                run_id: binding.run_id().clone(),
                principal: command.principal.as_str().to_owned(),
                command_key: request.command_key.to_owned(),
                scope_id: request.scope_id.to_owned(),
                pod_id: request.pod_id.to_owned(),
                request_digest: digest.clone(),
                canonical_intent: request.canonical_intent.to_vec(),
                owner_epoch: owner,
                target_epoch: pod_incarnation,
            };
            let mut run = checked.run.clone();
            run.admit(run.revision(), &command_identity, &witness)
                .map_err(|_| StoreError::Conflict("V2 Run lacks inserted launch command"))?;
            let attempt = Attempt::new(
                binding.attempt_id().clone(),
                binding.run_id().clone(),
                binding.attempt_ordinal(),
                binding.attempt_epoch(),
            )
            .map_err(|_| StoreError::Conflict("V2 planned Attempt is invalid"))?;
            run.start_attempt(run.revision(), &attempt)
                .map_err(|_| StoreError::Conflict("V2 planned Attempt cannot start"))?;
            let strict = checked
                .planned_binding
                .ok_or(StoreError::Conflict("V2 planned binding is missing"))?
                .confirm_after_admission(checked.session, &run)
                .map_err(|_| StoreError::Conflict("V2 post-command binding differs"))?;
            validate_initial(
                request.scope_id,
                request.pod_id,
                checked.session,
                &run,
                &strict,
            )?;
            Some(run)
        } else {
            None
        };
        let committed_run = admitted_run.as_ref().unwrap_or(checked.run);
        transaction.execute(
            "INSERT INTO runtime_sessions(
               session_id,scope_id,actor_id,revision,state,current_run_id)
             VALUES(?1,?2,?3,?4,'open',?5)",
            params![
                binding.session_id().as_str(),
                binding.scope_id().as_str(),
                binding.actor_id().as_str(),
                integer(checked.session.revision().get())?,
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
                integer(committed_run.revision().get())?,
                binding.attempt_id().as_str(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO run_child_budgets(run_id,max_children,reserved_children)
             VALUES(?1,?2,0)",
            params![
                binding.run_id().as_str(),
                integer(u64::from(checked.max_children))?,
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
        let command_rowid = match early_command_rowid {
            Some(rowid) => rowid,
            None => insert_launch_command(
                &transaction,
                &command,
                &command_id,
                &digest,
                owner,
                pod_incarnation,
            )?,
        };
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
                checked.format.effective_version(),
                spec_digest,
                checked.effective_spec,
                checked.format.descriptor_version(),
                checked.descriptor_digest,
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

fn insert_launch_command(
    transaction: &Transaction<'_>,
    command: &CommandRequest,
    command_id: &str,
    digest: &str,
    owner: i64,
    pod_incarnation: i64,
) -> Result<i64, StoreError> {
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
    Ok(transaction.last_insert_rowid())
}

fn check_proposal<'a>(
    request: &AdmissionRequest<'a>,
    proposal: &ProposalKind<'a>,
) -> Result<CheckedProposal<'a>, StoreError> {
    match proposal {
        ProposalKind::V1(proposal) => {
            validate_initial(
                request.scope_id,
                request.pod_id,
                proposal.session,
                proposal.run,
                proposal.binding,
            )?;
            proposal
                .descriptor
                .validate_against_binding(proposal.binding)
                .map_err(|_| StoreError::Conflict("descriptor differs from launch binding"))?;
            for (index, resource) in proposal.binding.resources().iter().enumerate() {
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
            let descriptor = proposal
                .descriptor
                .encode_json()
                .map_err(|_| StoreError::InvalidInput("launch descriptor cannot encode"))?;
            let effective = EffectiveLaunchContract::decode(proposal.effective_spec)
                .map_err(|_| StoreError::InvalidInput("effective launch bytes are malformed"))?;
            effective
                .compare_with_descriptor(proposal.descriptor)
                .map_err(|_| StoreError::Conflict("effective launch differs from descriptor"))?;
            Ok(CheckedProposal {
                session: proposal.session,
                run: proposal.run,
                binding: proposal.binding,
                planned_binding: None,
                effective_spec: proposal.effective_spec,
                descriptor,
                spec_digest: effective.digest().to_owned(),
                descriptor_digest: proposal.descriptor.digest().to_owned(),
                format: BoundLaunchFormat::V1,
                max_children: 0,
                expected_owner_epoch: proposal.expected_owner_epoch,
                expected_authority_revision: proposal.expected_authority_revision,
            })
        }
        ProposalKind::CodexV2(proposal) => {
            let binding = proposal.binding.identity();
            validate_planned_initial(request, proposal.session, proposal.run, binding)?;
            proposal
                .descriptor
                .validate_against_planned_root(proposal.binding)
                .map_err(|_| StoreError::Conflict("V2 descriptor differs from launch binding"))?;
            for (index, resource) in binding.resources().iter().enumerate() {
                let native = proposal
                    .descriptor
                    .resource(index)
                    .ok_or(StoreError::Conflict("V2 descriptor resource is missing"))?;
                if native.resource_id != resource.id().as_str()
                    || native.epoch != resource.epoch().get()
                    || native.kind != NativeResourceKind::from(resource.kind())
                {
                    return Err(StoreError::Conflict("V2 descriptor resource differs"));
                }
            }
            let descriptor = proposal
                .descriptor
                .encode_json()
                .map_err(|_| StoreError::InvalidInput("V2 descriptor cannot encode"))?;
            let decoded_descriptor = ImmutableLaunchDescriptorV2::decode_json(&descriptor)
                .map_err(|_| StoreError::InvalidInput("V2 descriptor is malformed"))?;
            if decoded_descriptor != *proposal.descriptor {
                return Err(StoreError::Conflict("V2 descriptor is not canonical"));
            }
            let effective_spec = proposal.effective_spec.canonical_bytes();
            let effective = EffectiveLaunchContractV2::decode(effective_spec)
                .map_err(|_| StoreError::InvalidInput("V2 effective launch is malformed"))?;
            if effective != *proposal.effective_spec {
                return Err(StoreError::Conflict("V2 effective launch is not canonical"));
            }
            effective
                .compare_with_descriptor(proposal.descriptor)
                .map_err(|_| StoreError::Conflict("V2 effective launch differs from descriptor"))?;
            Ok(CheckedProposal {
                session: proposal.session,
                run: proposal.run,
                binding,
                planned_binding: Some(proposal.binding),
                effective_spec,
                descriptor,
                spec_digest: effective.digest().to_owned(),
                descriptor_digest: proposal.descriptor.digest().to_owned(),
                format: BoundLaunchFormat::CodexV2,
                max_children: effective.base().max_children(),
                expected_owner_epoch: proposal.expected_owner_epoch,
                expected_authority_revision: proposal.expected_authority_revision,
            })
        }
    }
}

fn validate_planned_initial(
    request: &AdmissionRequest<'_>,
    session: &Session,
    run: &Run,
    binding: &LaunchBinding,
) -> Result<(), StoreError> {
    PlannedRootBinding::from_queued_snapshot(session, run, binding)
        .map_err(|_| StoreError::Conflict("V2 root Run is not a queued plan"))?;
    let first_session_revision = Revision::INITIAL
        .checked_next()
        .map_err(|_| StoreError::InvalidInput("initial revision exhausted"))?;
    if session.revision() != first_session_revision
        || run.revision() != Revision::INITIAL
        || binding.attempt_ordinal() != 1
        || binding.attempt_epoch().get() != 1
        || binding.pod_incarnation().get() != 1
        || binding
            .resources()
            .iter()
            .any(|resource| resource.epoch().get() != 1)
        || binding.scope_id().as_str() != request.scope_id
        || binding.pod_id().as_str() != request.pod_id
    {
        return Err(StoreError::Conflict("V2 first-root plan differs"));
    }
    Ok(())
}

fn validate_initial(
    scope_id: &str,
    pod_id: &str,
    session: &Session,
    run: &Run,
    binding: &LaunchBinding,
) -> Result<(), StoreError> {
    if !binding.is_admitted() {
        return Err(StoreError::Conflict("launch binding is not admitted"));
    }
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
        || binding.scope_id().as_str() != scope_id
        || binding.pod_id().as_str() != pod_id
    {
        return Err(StoreError::Conflict(
            "initial aggregates differ from launch binding",
        ));
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

struct StoredNativeResource {
    id: String,
    kind: NativeResourceKind,
    epoch: u64,
}

/// Projection from strictly decoded V1 or V2 wire types only. It is never
/// formed by parsing raw JSON fields or by trusting a stored digest alone.
struct StoredLaunchFacts {
    effective_digest: String,
    descriptor_digest: String,
    effective_spec_digest: String,
    scope_id: String,
    actor_id: String,
    session_id: String,
    run_id: String,
    attempt_id: String,
    pod_id: String,
    pod_incarnation: u64,
    role: NativeRole,
    work_kind: NativeWorkKind,
    parent_run_id: Option<String>,
    attempt_ordinal: u64,
    attempt_epoch: u64,
    resources: Vec<StoredNativeResource>,
}

fn stored_launch_facts(
    format: BoundLaunchFormat,
    effective_bytes: &[u8],
    descriptor_bytes: &[u8],
) -> Result<StoredLaunchFacts, StoreError> {
    match format {
        BoundLaunchFormat::V1 => {
            let effective = EffectiveLaunchContract::decode(effective_bytes)
                .map_err(|_| StoreError::Conflict("stored effective launch is malformed"))?;
            let descriptor = ImmutableLaunchDescriptor::decode_json(descriptor_bytes)
                .map_err(|_| StoreError::Conflict("stored descriptor is malformed"))?;
            effective
                .compare_with_descriptor(&descriptor)
                .map_err(|_| {
                    StoreError::Conflict("stored effective launch differs from descriptor")
                })?;
            let resources = (0..descriptor.resources_len())
                .map(|index| {
                    let native = descriptor.resource(index).expect("index is in bounds");
                    StoredNativeResource {
                        id: native.resource_id.to_owned(),
                        kind: native.kind,
                        epoch: native.epoch,
                    }
                })
                .collect();
            Ok(StoredLaunchFacts {
                effective_digest: effective.digest().to_owned(),
                descriptor_digest: descriptor.digest().to_owned(),
                effective_spec_digest: descriptor.effective_spec_digest().to_owned(),
                scope_id: descriptor.scope_id().to_owned(),
                actor_id: descriptor.actor_id().to_owned(),
                session_id: descriptor.session_id().to_owned(),
                run_id: descriptor.run_id().to_owned(),
                attempt_id: descriptor.attempt_id().to_owned(),
                pod_id: descriptor.pod_id().to_owned(),
                pod_incarnation: descriptor.pod_incarnation(),
                role: descriptor.role(),
                work_kind: descriptor.work_kind(),
                parent_run_id: descriptor.parent_run_id().map(str::to_owned),
                attempt_ordinal: descriptor.attempt_ordinal(),
                attempt_epoch: descriptor.attempt_epoch(),
                resources,
            })
        }
        BoundLaunchFormat::CodexV2 => {
            let effective = EffectiveLaunchContractV2::decode(effective_bytes)
                .map_err(|_| StoreError::Conflict("stored V2 effective launch is malformed"))?;
            let descriptor = ImmutableLaunchDescriptorV2::decode_json(descriptor_bytes)
                .map_err(|_| StoreError::Conflict("stored V2 descriptor is malformed"))?;
            effective
                .compare_with_descriptor(&descriptor)
                .map_err(|_| {
                    StoreError::Conflict("stored V2 effective launch differs from descriptor")
                })?;
            let resources = (0..descriptor.resources_len())
                .map(|index| {
                    let native = descriptor.resource(index).expect("index is in bounds");
                    StoredNativeResource {
                        id: native.resource_id.to_owned(),
                        kind: native.kind,
                        epoch: native.epoch,
                    }
                })
                .collect();
            Ok(StoredLaunchFacts {
                effective_digest: effective.digest().to_owned(),
                descriptor_digest: descriptor.digest().to_owned(),
                effective_spec_digest: descriptor.effective_spec_digest().to_owned(),
                scope_id: descriptor.scope_id().to_owned(),
                actor_id: descriptor.actor_id().to_owned(),
                session_id: descriptor.session_id().to_owned(),
                run_id: descriptor.run_id().to_owned(),
                attempt_id: descriptor.attempt_id().to_owned(),
                pod_id: descriptor.pod_id().to_owned(),
                pod_incarnation: descriptor.pod_incarnation(),
                role: descriptor.role(),
                work_kind: descriptor.work_kind(),
                parent_run_id: descriptor.parent_run_id().map(str::to_owned),
                attempt_ordinal: descriptor.attempt_ordinal(),
                attempt_epoch: descriptor.attempt_epoch(),
                resources,
            })
        }
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
    let format = match (binding_facts.5.as_str(), binding_facts.6.as_str()) {
        (EFFECTIVE_LAUNCH_VERSION, LAUNCH_DESCRIPTOR_SCHEMA) => BoundLaunchFormat::V1,
        (EFFECTIVE_LAUNCH_V2_VERSION, LAUNCH_DESCRIPTOR_V2_SCHEMA) => BoundLaunchFormat::CodexV2,
        _ => return Err(StoreError::Conflict("bound launch version pair differs")),
    };
    if binding_facts.0 != scope_id
        || binding_facts.1 != attempt_id
        || binding_facts.2 != 1
        || binding_facts.3 != 1
        || binding_facts.4 <= 0
    {
        return Err(StoreError::Conflict(
            "bound launch version or attempt differs",
        ));
    }
    let facts = stored_launch_facts(format, &effective_spec, &descriptor)?;
    if facts.effective_digest != spec_digest
        || (format == BoundLaunchFormat::V1 && sha256_hex(&effective_spec) != spec_digest)
        || pod_incarnation != target_epoch
    {
        return Err(StoreError::Conflict(
            "bound launch identity or effective spec changed",
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
    if facts.descriptor_digest != descriptor_digest
        || facts.effective_spec_digest != spec_digest
        || facts.scope_id != scope_id
        || facts.session_id != session_id
        || facts.run_id != run_id
        || facts.attempt_id != attempt_id
        || facts.pod_id != pod_id
        || facts.pod_incarnation != pod_incarnation as u64
        || facts.actor_id != session_actor
        || role_native_text(facts.role) != run_role
        || work_native_text(facts.work_kind) != run_work
        || facts.parent_run_id.is_some()
        || facts.attempt_ordinal != 1
        || facts.attempt_epoch != 1
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
        let native = facts
            .resources
            .get(expected)
            .ok_or(StoreError::Conflict("bound resource count differs"))?;
        if ordinal != expected as i64
            || epoch != 1
            || native.id != id
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
    if resources.len() != facts.resources.len() || resources.len() != binding_facts.4 as usize {
        return Err(StoreError::Conflict(
            "bound resource inventory is incomplete",
        ));
    }
    Ok(BoundLaunchRecord {
        format,
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
