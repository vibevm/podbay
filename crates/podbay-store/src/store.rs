use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::authority::advance_policy_fence_epoch;
use crate::bound_launch::{ensure_current_dispatch_eligible, read_bound_record};

use crate::model::{
    Admission, AdmittedLaunchInspection, CommandInspection, CommandLookupSelector, CommandRequest,
    CommittedEvent, DIGEST_VERSION, EffectClaim, EffectObservation, EffectState, EventCursor,
    EventReference, HostAcceptanceProof, LaunchDispatchStage, LaunchDispatchStatus,
    LaunchIntentBinding, LaunchLookupRequest, ObservedStage, QuarantinedSourceEvent, Receipt,
    ScopeSnapshot, SourceAnomaly, SourceOrder, StoreError, StoredEffect, VerifiedPrincipal,
};

const SCHEMA_VERSION: i64 = 23;
const MAX_BYTES: usize = 1_048_576;
const CODEX_NATIVE_SOURCES_V23: &str = "CREATE TABLE codex_native_sources (
  resource_id TEXT PRIMARY KEY CHECK(length(resource_id)>0),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  session_id TEXT NOT NULL REFERENCES runtime_sessions(session_id),
  run_id TEXT NOT NULL CHECK(length(run_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  resource_epoch INTEGER NOT NULL CHECK(resource_epoch>=1),
  watermark INTEGER NOT NULL CHECK(watermark>=0),
  earliest_retained INTEGER NOT NULL CHECK(earliest_retained>=0),
  last_status TEXT CHECK(last_status IS NULL OR last_status IN
    ('idle','active','waiting','completed','failed','interrupted','system_error')),
  output_events INTEGER NOT NULL CHECK(output_events>=0),
  question_events INTEGER NOT NULL CHECK(question_events>=0),
  permission_events INTEGER NOT NULL CHECK(permission_events>=0),
  opaque_events INTEGER NOT NULL CHECK(opaque_events>=0),
  external_conflict INTEGER NOT NULL CHECK(external_conflict IN (0,1)),
  fidelity TEXT NOT NULL CHECK(fidelity IN ('exact','partial','unknown')),
  quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1))
) STRICT";
const CODEX_NATIVE_EVIDENCE_V23: &str = "CREATE TABLE codex_native_evidence (
  resource_id TEXT NOT NULL REFERENCES codex_native_sources(resource_id),
  source_sequence INTEGER NOT NULL CHECK(source_sequence>=1),
  event_id TEXT NOT NULL UNIQUE CHECK(length(event_id)>0),
  kind TEXT NOT NULL CHECK(kind IN ('status','output','question','permission','opaque')),
  status TEXT CHECK(status IS NULL OR status IN
    ('idle','active','waiting','completed','failed','interrupted','system_error')),
  recorded_at_unix_millis INTEGER NOT NULL CHECK(recorded_at_unix_millis>=0),
  provenance TEXT NOT NULL CHECK(provenance='codex.app-server.pod-observed/1'),
  external_conflict INTEGER NOT NULL CHECK(external_conflict IN (0,1)),
  content_digest TEXT NOT NULL CHECK(length(content_digest)=64),
  raw_jsonl BLOB NOT NULL CHECK(length(raw_jsonl) BETWEEN 1 AND 4194304),
  PRIMARY KEY(resource_id,source_sequence)
) STRICT";
const CODEX_NATIVE_CONFLICTS_V23: &str = "CREATE TABLE codex_native_conflicts (
  resource_id TEXT NOT NULL REFERENCES codex_native_sources(resource_id),
  source_sequence INTEGER NOT NULL CHECK(source_sequence>=1),
  incoming_digest TEXT NOT NULL CHECK(length(incoming_digest)=64),
  raw_jsonl BLOB NOT NULL CHECK(length(raw_jsonl) BETWEEN 1 AND 4194304),
  PRIMARY KEY(resource_id,source_sequence,incoming_digest)
) STRICT";
// Schema creation records no native thread anchor, command, or provider input.
const CODEX_LATER_TURNS_V22: &str = "CREATE TABLE codex_later_turns (
  command_rowid INTEGER NOT NULL PRIMARY KEY REFERENCES commands(command_rowid),
  bootstrap_command_rowid INTEGER NOT NULL REFERENCES codex_bootstrap_sends(command_rowid),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  session_id TEXT NOT NULL REFERENCES runtime_sessions(session_id),
  session_revision INTEGER NOT NULL CHECK(session_revision>=1),
  run_id TEXT NOT NULL CHECK(length(run_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  resource_epoch INTEGER NOT NULL CHECK(resource_epoch>=1),
  resource_input_epoch INTEGER NOT NULL CHECK(resource_input_epoch>=1),
  native_thread_id TEXT NOT NULL CHECK(length(native_thread_id) BETWEEN 1 AND 256),
  holder_actor_id TEXT NOT NULL CHECK(length(holder_actor_id)>0),
  holder_credential_generation INTEGER NOT NULL CHECK(holder_credential_generation>=1),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  manager_credential_epoch INTEGER NOT NULL CHECK(manager_credential_epoch>=1),
  authority_revision INTEGER NOT NULL CHECK(authority_revision>=1),
  writer_epoch INTEGER NOT NULL CHECK(writer_epoch>=1),
  lease_expires_at_unix_seconds INTEGER NOT NULL CHECK(lease_expires_at_unix_seconds>=1),
  wire_payload_digest TEXT NOT NULL CHECK(length(wire_payload_digest)=64),
  prompt_digest TEXT NOT NULL CHECK(length(prompt_digest)=64),
  binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64)
) STRICT";
const CODEX_LATER_TURNS_SESSION_V22: &str = "CREATE INDEX codex_later_turns_session_v22
  ON codex_later_turns(session_id,command_rowid)";
// Only V3 atomic admission may insert this row beside its immutable binding.
const LAUNCH_POLICY_FENCES_V20: &str = "CREATE TABLE launch_policy_fences (
  command_rowid INTEGER NOT NULL PRIMARY KEY REFERENCES launch_bindings(command_rowid),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  policy_fence_epoch INTEGER NOT NULL CHECK(policy_fence_epoch>=1),
  admission_authority_revision INTEGER NOT NULL CHECK(admission_authority_revision>=1)
) STRICT";
// Recovery attempts are append-only identities. A later manager appends a
// successor instead of deleting or relabelling an abandoned rebind row.
// Fresh schema creation inserts no supersession evidence.
const REBIND_SUPERSESSION_ATTEMPTS_V21: &str = "CREATE TABLE rebind_supersession_attempts (
  supersession_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  abandoned_rebind_rowid INTEGER NOT NULL REFERENCES manager_rebinds(rebind_rowid),
  abandoned_request_digest TEXT NOT NULL CHECK(length(abandoned_request_digest)=64
    AND abandoned_request_digest NOT GLOB '*[^0-9a-f]*'),
  abandoned_phase TEXT NOT NULL CHECK(abandoned_phase IN
    ('pending','pod_acknowledged','activated')),
  abandoned_checkpoint_ref TEXT,
  prior_active_checkpoint_digest TEXT NOT NULL CHECK(length(prior_active_checkpoint_digest)=64
    AND prior_active_checkpoint_digest NOT GLOB '*[^0-9a-f]*'),
  observed_phase TEXT NOT NULL CHECK(observed_phase IN
    ('active_prior','pending_store','pending_pod')),
  observed_checkpoint_digest TEXT NOT NULL CHECK(length(observed_checkpoint_digest)=64
    AND observed_checkpoint_digest NOT GLOB '*[^0-9a-f]*'),
  supervisor_process_id TEXT NOT NULL CHECK(length(supervisor_process_id) BETWEEN 1 AND 256),
  supervisor_birth_identity TEXT NOT NULL CHECK(length(supervisor_birth_identity) BETWEEN 1 AND 256),
  child_process_id TEXT NOT NULL CHECK(length(child_process_id) BETWEEN 1 AND 256),
  child_birth_identity TEXT NOT NULL CHECK(length(child_birth_identity) BETWEEN 1 AND 256),
  boot_identity TEXT NOT NULL CHECK(length(boot_identity) BETWEEN 1 AND 256),
  unit_name TEXT NOT NULL CHECK(length(unit_name) BETWEEN 1 AND 256),
  cgroup_path TEXT NOT NULL CHECK(length(cgroup_path) BETWEEN 1 AND 4096),
  recovering_owner_epoch INTEGER NOT NULL CHECK(recovering_owner_epoch>=1),
  recovering_credential_epoch INTEGER NOT NULL CHECK(recovering_credential_epoch>=1),
  recovering_os_identity TEXT NOT NULL CHECK(length(recovering_os_identity) BETWEEN 1 AND 256),
  recovering_process_id TEXT NOT NULL CHECK(length(recovering_process_id) BETWEEN 1 AND 256),
  recovering_boot_identity TEXT NOT NULL CHECK(length(recovering_boot_identity) BETWEEN 1 AND 256),
  recovering_birth_identity TEXT NOT NULL CHECK(length(recovering_birth_identity) BETWEEN 1 AND 256),
  recovering_containment TEXT NOT NULL CHECK(length(recovering_containment) BETWEEN 1 AND 4096),
  command_key TEXT NOT NULL CHECK(length(command_key)>0),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64
    AND request_digest NOT GLOB '*[^0-9a-f]*'),
  intent_bytes BLOB NOT NULL CHECK(length(intent_bytes) BETWEEN 64 AND 65536),
  predecessor_rowid INTEGER REFERENCES rebind_supersession_attempts(supersession_rowid),
  resource_count INTEGER NOT NULL CHECK(resource_count BETWEEN 1 AND 64),
  phase TEXT NOT NULL CHECK(phase IN ('planned','pod_checkpointed','replaced')),
  recovery_checkpoint_digest TEXT,
  CHECK((phase='planned' AND recovery_checkpoint_digest IS NULL)
    OR (phase='pod_checkpointed' AND length(recovery_checkpoint_digest)=64
      AND recovery_checkpoint_digest NOT GLOB '*[^0-9a-f]*')
    OR (phase='replaced' AND (recovery_checkpoint_digest IS NULL
      OR (length(recovery_checkpoint_digest)=64
        AND recovery_checkpoint_digest NOT GLOB '*[^0-9a-f]*')))),
  UNIQUE(scope_id,pod_id,pod_incarnation,command_key),
  UNIQUE(abandoned_rebind_rowid,recovering_owner_epoch),
  UNIQUE(predecessor_rowid)
) STRICT";
const REBIND_SUPERSESSION_RESOURCES_V21: &str = "CREATE TABLE rebind_supersession_resources (
  supersession_rowid INTEGER NOT NULL REFERENCES rebind_supersession_attempts(supersession_rowid),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  abandoned_input_epoch INTEGER NOT NULL CHECK(abandoned_input_epoch>=1),
  recovering_input_epoch INTEGER NOT NULL CHECK(recovering_input_epoch>abandoned_input_epoch),
  PRIMARY KEY(supersession_rowid,resource_id)
) STRICT";
const REBIND_SUPERSESSION_LATEST_INDEX_V21: &str = "CREATE INDEX rebind_supersession_latest_v21
  ON rebind_supersession_attempts(abandoned_rebind_rowid,supersession_rowid DESC)";
const CURRENT_SCOPE_SESSIONS_INDEX_V19: &str = "CREATE INDEX runtime_sessions_open_scope_v19
  ON runtime_sessions(scope_id,session_id) WHERE state='open'";
const CURRENT_SCOPE_RESOURCES_INDEX_V19: &str = "CREATE INDEX authority_resources_pod_v19
  ON authority_resources(pod_id,resource_id)";

// Immutable launch identities and current runtime rows are created together
// only by an authorized admission transaction.
const RUNTIME_SESSIONS_V8: &str = "CREATE TABLE runtime_sessions (
  session_id TEXT PRIMARY KEY CHECK(length(session_id)>0),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  actor_id TEXT NOT NULL CHECK(length(actor_id)>0),
  revision INTEGER NOT NULL CHECK(revision>=0),
  state TEXT NOT NULL CHECK(length(state)>0),
  current_run_id TEXT CHECK(current_run_id IS NULL OR length(current_run_id)>0),
  UNIQUE(session_id,scope_id)
) STRICT";
const RUNTIME_RUNS_V8: &str = "CREATE TABLE runtime_runs (
  run_id TEXT PRIMARY KEY CHECK(length(run_id)>0),
  session_id TEXT NOT NULL,
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  role TEXT NOT NULL CHECK(length(role)>0),
  work_kind TEXT NOT NULL CHECK(length(work_kind)>0),
  parent_run_id TEXT CHECK(parent_run_id IS NULL OR length(parent_run_id)>0),
  revision INTEGER NOT NULL CHECK(revision>=0),
  admission_state TEXT NOT NULL CHECK(length(admission_state)>0),
  desired_mode TEXT NOT NULL CHECK(length(desired_mode)>0),
  execution_state TEXT NOT NULL CHECK(length(execution_state)>0),
  current_attempt_id TEXT CHECK(current_attempt_id IS NULL OR length(current_attempt_id)>0),
  last_attempt_ordinal INTEGER NOT NULL CHECK(last_attempt_ordinal>=0),
  FOREIGN KEY(session_id,scope_id) REFERENCES runtime_sessions(session_id,scope_id),
  UNIQUE(run_id,session_id,scope_id)
) STRICT";
// A Run's child capacity is a lifetime admission budget. No process exit or
// uncertain effect refunds it.
const RUN_CHILD_BUDGETS_V16: &str = "CREATE TABLE run_child_budgets (
  run_id TEXT NOT NULL PRIMARY KEY REFERENCES runtime_runs(run_id) CHECK(length(run_id)>0),
  max_children INTEGER NOT NULL DEFAULT 0 CHECK(max_children>=0 AND max_children<=4294967295),
  reserved_children INTEGER NOT NULL DEFAULT 0 CHECK(reserved_children>=0 AND reserved_children<=max_children)
) STRICT";
// Fresh schema creation invents no native writer. One row is exclusive per ResourceId;
// any takeover increments writer_epoch, independently of PTY input_epoch.
const NATIVE_WRITER_LEASES_V17: &str = "CREATE TABLE native_writer_leases (
  resource_id TEXT NOT NULL PRIMARY KEY CHECK(length(resource_id)>0),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  session_id TEXT NOT NULL CHECK(length(session_id)>0),
  run_id TEXT NOT NULL CHECK(length(run_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  resource_epoch INTEGER NOT NULL CHECK(resource_epoch>=1),
  resource_input_epoch INTEGER NOT NULL CHECK(resource_input_epoch>=1),
  holder_actor_id TEXT NOT NULL CHECK(length(holder_actor_id)>0),
  holder_credential_generation INTEGER NOT NULL CHECK(holder_credential_generation>=1),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  manager_credential_epoch INTEGER NOT NULL CHECK(manager_credential_epoch>=1),
  authority_revision INTEGER NOT NULL CHECK(authority_revision>=1),
  writer_epoch INTEGER NOT NULL CHECK(writer_epoch>=1),
  expires_at_unix_seconds INTEGER NOT NULL CHECK(expires_at_unix_seconds>=1)
) STRICT";
// Fresh schema creation adds no bootstrap command. One Session may have only
// one first native turn; a changed key cannot create another bootstrap.
const CODEX_BOOTSTRAP_SENDS_V18: &str = "CREATE TABLE codex_bootstrap_sends (
  command_rowid INTEGER NOT NULL PRIMARY KEY REFERENCES commands(command_rowid),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  session_id TEXT NOT NULL UNIQUE REFERENCES runtime_sessions(session_id),
  session_revision INTEGER NOT NULL CHECK(session_revision>=1),
  run_id TEXT NOT NULL CHECK(length(run_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  resource_epoch INTEGER NOT NULL CHECK(resource_epoch>=1),
  resource_input_epoch INTEGER NOT NULL CHECK(resource_input_epoch>=1),
  holder_actor_id TEXT NOT NULL CHECK(length(holder_actor_id)>0),
  holder_credential_generation INTEGER NOT NULL CHECK(holder_credential_generation>=1),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  manager_credential_epoch INTEGER NOT NULL CHECK(manager_credential_epoch>=1),
  authority_revision INTEGER NOT NULL CHECK(authority_revision>=1),
  writer_epoch INTEGER NOT NULL CHECK(writer_epoch>=1),
  lease_expires_at_unix_seconds INTEGER NOT NULL CHECK(lease_expires_at_unix_seconds>=1),
  wire_payload_digest TEXT NOT NULL CHECK(length(wire_payload_digest)=64),
  prompt_digest TEXT NOT NULL CHECK(length(prompt_digest)=64),
  binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64),
  UNIQUE(resource_id,resource_epoch)
) STRICT";
const LAUNCH_BINDINGS_V8: &str = "CREATE TABLE launch_bindings (
  command_rowid INTEGER PRIMARY KEY,
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  session_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL UNIQUE CHECK(length(attempt_id)>0),
  attempt_ordinal INTEGER NOT NULL CHECK(attempt_ordinal>=1),
  attempt_epoch INTEGER NOT NULL CHECK(attempt_epoch>=1),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  resource_count INTEGER NOT NULL CHECK(resource_count>=1),
  effective_spec_version TEXT NOT NULL CHECK(length(effective_spec_version)>0),
  effective_spec_digest TEXT NOT NULL CHECK(length(effective_spec_digest)=64),
  effective_spec BLOB NOT NULL CHECK(length(effective_spec)>0),
  descriptor_version TEXT NOT NULL CHECK(length(descriptor_version)>0),
  descriptor_digest TEXT NOT NULL CHECK(length(descriptor_digest)=64),
  descriptor BLOB NOT NULL CHECK(length(descriptor)>0),
  FOREIGN KEY(run_id,session_id,scope_id) REFERENCES runtime_runs(run_id,session_id,scope_id),
  FOREIGN KEY(scope_id,pod_id,pod_incarnation,command_rowid)
    REFERENCES launch_slots(scope_id,pod_id,pod_incarnation,command_rowid),
  UNIQUE(scope_id,pod_id,pod_incarnation),
  UNIQUE(run_id,attempt_ordinal)
) STRICT";
const LAUNCH_RESOURCES_V8: &str = "CREATE TABLE launch_resources (
  command_rowid INTEGER NOT NULL REFERENCES launch_bindings(command_rowid),
  resource_ordinal INTEGER NOT NULL CHECK(resource_ordinal>=0),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  resource_kind TEXT NOT NULL CHECK(length(resource_kind)>0),
  resource_epoch INTEGER NOT NULL CHECK(resource_epoch>=1),
  PRIMARY KEY(command_rowid,resource_ordinal),
  UNIQUE(command_rowid,resource_id)
) STRICT";
const LAUNCH_SLOT_BINDING_INDEX_V8: &str = "CREATE UNIQUE INDEX launch_slots_binding_identity
  ON launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)";

// A rebind is durable evidence, never an OS peer/liveness attestation.
const MANAGER_REBINDS_V9: &str = "CREATE TABLE manager_rebinds (
  rebind_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  expected_owner_epoch INTEGER NOT NULL CHECK(expected_owner_epoch>=1),
  next_owner_epoch INTEGER NOT NULL CHECK(next_owner_epoch=expected_owner_epoch+1),
  expected_credential_epoch INTEGER NOT NULL CHECK(expected_credential_epoch>=1),
  next_credential_epoch INTEGER NOT NULL
    CHECK(next_credential_epoch=expected_credential_epoch+1),
  manager_os_identity TEXT NOT NULL CHECK(length(manager_os_identity)>0),
  manager_process_id TEXT NOT NULL CHECK(length(manager_process_id)>0),
  manager_boot_identity TEXT NOT NULL CHECK(length(manager_boot_identity)>0),
  manager_birth_identity TEXT NOT NULL CHECK(length(manager_birth_identity)>0),
  manager_containment TEXT NOT NULL CHECK(length(manager_containment)>0),
  command_key TEXT NOT NULL CHECK(length(command_key)>0),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64),
  resource_count INTEGER NOT NULL CHECK(resource_count>=1),
  phase TEXT NOT NULL CHECK(phase IN ('pending','pod_acknowledged','activated')),
  pod_checkpoint_ref TEXT,
  CHECK((phase='pending' AND pod_checkpoint_ref IS NULL)
    OR (phase!='pending' AND pod_checkpoint_ref IS NOT NULL
      AND length(pod_checkpoint_ref)>0)),
  FOREIGN KEY(scope_id,pod_id,pod_incarnation)
    REFERENCES launch_bindings(scope_id,pod_id,pod_incarnation),
  UNIQUE(scope_id,pod_id,pod_incarnation,next_owner_epoch),
  UNIQUE(scope_id,pod_id,pod_incarnation,command_key)
) STRICT";
const MANAGER_REBIND_RESOURCES_V9: &str = "CREATE TABLE manager_rebind_resources (
  rebind_rowid INTEGER NOT NULL REFERENCES manager_rebinds(rebind_rowid),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  expected_input_epoch INTEGER NOT NULL CHECK(expected_input_epoch>=1),
  next_input_epoch INTEGER NOT NULL CHECK(next_input_epoch=expected_input_epoch+1),
  PRIMARY KEY(rebind_rowid,resource_id)
) STRICT";

// The current rebind envelope permits monotonic jumps only with exact prior
// pod-checkpoint evidence.
fn manager_rebinds_v12() -> String {
    MANAGER_REBINDS_V9
        .replace(
            "next_owner_epoch=expected_owner_epoch+1",
            "next_owner_epoch>expected_owner_epoch",
        )
        .replace(
            "next_credential_epoch=expected_credential_epoch+1",
            "next_credential_epoch>expected_credential_epoch",
        )
}

fn manager_rebind_resources_v12() -> String {
    MANAGER_REBIND_RESOURCES_V9.replace(
        "next_input_epoch=expected_input_epoch+1",
        "next_input_epoch>expected_input_epoch",
    )
}

// An empty manager claim table makes no claim about a manager or its pod peer.
// Only successful owner replay mints the current credential epoch.
const MANAGER_CREDENTIAL_CLAIMS_V10: &str = "CREATE TABLE manager_credential_claims (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  credential_epoch INTEGER NOT NULL CHECK(credential_epoch>=1)
) STRICT";

// Only the trusted host may register a kernel-attested peer after the owner claim.
const MANAGER_PEER_BINDINGS_V11: &str = "CREATE TABLE manager_peer_bindings (
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  credential_epoch INTEGER NOT NULL CHECK(credential_epoch>=1),
  peer_schema TEXT NOT NULL CHECK(peer_schema='podbay.attested-peer/1'),
  os_identity TEXT NOT NULL CHECK(length(os_identity) BETWEEN 1 AND 256),
  process_identity TEXT NOT NULL CHECK(length(process_identity) BETWEEN 1 AND 256),
  boot_identity TEXT NOT NULL CHECK(length(boot_identity) BETWEEN 1 AND 256),
  birth_identity TEXT NOT NULL CHECK(length(birth_identity) BETWEEN 1 AND 256),
  containment_identity TEXT NOT NULL CHECK(length(containment_identity) BETWEEN 1 AND 4096),
  PRIMARY KEY(store_lineage,owner_epoch,credential_epoch)
) STRICT";

// A prior observation is a trusted-host record of a pod's Active checkpoint.
// The store validates association and durable fences, not OS peer.
const MANAGER_REBIND_PRIOR_OBSERVATIONS_V13: &str =
    "CREATE TABLE manager_rebind_prior_observations (
  rebind_rowid INTEGER PRIMARY KEY REFERENCES manager_rebinds(rebind_rowid),
  schema_version TEXT NOT NULL CHECK(schema_version='podbay.prior-checkpoint/1'),
  checkpoint_digest TEXT NOT NULL CHECK(length(checkpoint_digest)=64
    AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'),
  supervisor_pid INTEGER NOT NULL CHECK(supervisor_pid>=1),
  supervisor_start_ticks INTEGER NOT NULL CHECK(supervisor_start_ticks>=1),
  boot_id TEXT NOT NULL CHECK(length(boot_id) BETWEEN 1 AND 256),
  unit_name TEXT NOT NULL CHECK(length(unit_name) BETWEEN 1 AND 256),
  cgroup_path TEXT NOT NULL CHECK(length(cgroup_path) BETWEEN 1 AND 4096)
) STRICT";

// Schema creation never invents an actor credential. A trusted host registers one
// public verifier only after the exact actor generation and birth are known.
const ACTOR_VERIFIERS_V14: &str = "CREATE TABLE actor_verifiers (
  actor_id TEXT PRIMARY KEY REFERENCES authority_actors(actor_id),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  credential_generation INTEGER NOT NULL CHECK(credential_generation>=1),
  verifier_version TEXT NOT NULL CHECK(verifier_version='podbay.ed25519/1'),
  public_key BLOB NOT NULL CHECK(length(public_key)=32),
  binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32),
  revoked INTEGER NOT NULL CHECK(revoked IN (0,1))
) STRICT";

// One committed key/digest receipt also retains the revoked old verifier.
// The current verifier table keeps only the latest generation.
const OWNER_ACTOR_ROTATIONS_V15: &str = "CREATE TABLE owner_actor_rotations (
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  actor_id TEXT NOT NULL REFERENCES authority_actors(actor_id),
  rotation_key TEXT NOT NULL CHECK(length(rotation_key)>0),
  intent_digest TEXT NOT NULL CHECK(length(intent_digest)=64),
  prior_generation INTEGER NOT NULL CHECK(prior_generation>=1),
  next_generation INTEGER NOT NULL CHECK(next_generation=prior_generation+1),
  prior_binding_digest BLOB NOT NULL CHECK(length(prior_binding_digest)=32),
  prior_public_key BLOB NOT NULL CHECK(length(prior_public_key)=32),
  next_binding_digest BLOB NOT NULL CHECK(length(next_binding_digest)=32),
  next_public_key BLOB NOT NULL CHECK(length(next_public_key)=32),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  authority_revision INTEGER NOT NULL CHECK(authority_revision>=1),
  prior_revoked INTEGER NOT NULL CHECK(prior_revoked=1),
  PRIMARY KEY(scope_id,actor_id,rotation_key),
  UNIQUE(actor_id,next_generation)
) STRICT";

/// SQLite's 100-byte database header stores user_version as a big-endian
/// integer at offset 60. Reading it directly cannot create WAL/SHM sidecars
/// while refusing a retired on-disk schema.
fn database_header_version(path: &Path) -> Result<i64, StoreError> {
    let mut file = std::fs::File::open(path)?;
    let mut header = [0_u8; 100];
    file.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0" {
        return Err(StoreError::Conflict("database header is not SQLite"));
    }
    Ok(u32::from_be_bytes(header[60..64].try_into().unwrap()) as i64)
}

#[cfg(unix)]
fn private_placeholder_identity(
    path: &Path,
    expected: Option<(u64, u64)>,
) -> Result<(u64, u64), StoreError> {
    let metadata = std::fs::symlink_metadata(path)?;
    let parent = path.parent().ok_or(StoreError::InvalidInput(
        "empty database placeholder has no parent",
    ))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    // The manager caller acquires its separate lifetime lock before this
    // check. This generic store API validates the file and directory, while
    // the caller remains responsible for proving that lock.
    let uid = nix::unistd::geteuid().as_raw();
    let identity = (metadata.dev(), metadata.ino());
    if !metadata.is_file()
        || metadata.len() != 0
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.mode() & 0o7777 != 0o700
        || std::fs::canonicalize(path)? != path
        || expected.is_some_and(|prior| prior != identity)
    {
        return Err(StoreError::Conflict(
            "empty database placeholder is not private and stable",
        ));
    }
    Ok(identity)
}

/// One connection is the one writer. SQLite's IMMEDIATE transaction locks fence other writers.
pub struct PodBayStore {
    pub(crate) connection: Connection,
    pub(crate) store_lineage: String,
}

impl PodBayStore {
    /// Open an existing current-schema store for a pod-side witness without
    /// becoming a writer or creating a database. Mutating methods on this
    /// handle still fail at SQLite's read-only boundary.
    pub fn open_existing_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(StoreError::InvalidInput(
                "read-only database path must be absolute",
            ));
        }
        let header_version = database_header_version(path)?;
        if header_version != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(header_version));
        }
        let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema(version));
        }
        verify_authority_schema(&transaction)?;
        verify_runtime_schema(&transaction)?;
        verify_writer_lease_schema(&transaction)?;
        verify_codex_bootstrap_schema(&transaction)?;
        verify_rebind_schema(&transaction)?;
        verify_manager_credential_schema(&transaction)?;
        verify_manager_peer_schema(&transaction)?;
        verify_prior_observation_schema(&transaction)?;
        verify_actor_verifier_schema(&transaction)?;
        verify_owner_rotation_schema(&transaction)?;
        verify_current_scope_schema(&transaction)?;
        verify_policy_fence_schema(&transaction)?;
        verify_supersession_schema(&transaction)?;
        verify_codex_later_turn_schema(&transaction)?;
        verify_codex_native_schema(&transaction)?;
        let store_lineage: String = transaction.query_row(
            "SELECT lineage FROM store_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        Ok(Self {
            connection,
            store_lineage,
        })
    }

    /// Open only the current schema. An existing older database is inspected
    /// through a read-only connection and refused before any WAL or DDL write.
    /// A new file is initialized to the current schema in one transaction.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Err(StoreError::InvalidInput("database path is empty"));
        }
        let existing_metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        // The trusted manager precreates a private 0600 file under its
        // lifetime lock. A regular zero-byte file has no SQLite schema yet;
        // every nonempty file must already have the exact current version.
        let precreated_empty = existing_metadata
            .as_ref()
            .is_some_and(|metadata| metadata.is_file() && metadata.len() == 0);
        #[cfg(unix)]
        let placeholder_identity = if precreated_empty {
            Some(private_placeholder_identity(path, None)?)
        } else {
            None
        };
        #[cfg(not(unix))]
        if precreated_empty {
            return Err(StoreError::InvalidInput(
                "precreated database placeholder is unsupported on this platform",
            ));
        }
        let fresh = existing_metadata.is_none() || precreated_empty;
        if existing_metadata.is_some() && !precreated_empty {
            let header_version = database_header_version(path)?;
            if header_version != SCHEMA_VERSION {
                return Err(StoreError::UnsupportedSchema(header_version));
            }
            let probe = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let version: i64 = probe.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            if version != SCHEMA_VERSION {
                return Err(StoreError::UnsupportedSchema(version));
            }
        } else if existing_metadata.is_none() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        #[cfg(unix)]
        if let Some(identity) = placeholder_identity {
            private_placeholder_identity(path, Some(identity))?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | if existing_metadata.is_some() {
                OpenFlags::empty()
            } else {
                OpenFlags::SQLITE_OPEN_CREATE
            };
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        // Recheck after opening for writing, before changing journal mode or
        // entering a write transaction. A replacement file cannot be upgraded.
        let before_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let expected_version = if fresh { 0 } else { SCHEMA_VERSION };
        if before_version != expected_version {
            return Err(StoreError::UnsupportedSchema(before_version));
        }
        #[cfg(unix)]
        if let Some(identity) = placeholder_identity {
            private_placeholder_identity(path, Some(identity))?;
        }
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let behavior = if fresh {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        };
        let transaction = connection.transaction_with_behavior(behavior)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version != expected_version {
            return Err(StoreError::UnsupportedSchema(version));
        }
        if fresh {
            transaction.execute_batch(include_str!("schema_v23.sql"))?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        verify_authority_schema(&transaction)?;
        verify_runtime_schema(&transaction)?;
        verify_writer_lease_schema(&transaction)?;
        verify_codex_bootstrap_schema(&transaction)?;
        verify_rebind_schema(&transaction)?;
        verify_manager_credential_schema(&transaction)?;
        verify_manager_peer_schema(&transaction)?;
        verify_prior_observation_schema(&transaction)?;
        verify_actor_verifier_schema(&transaction)?;
        verify_owner_rotation_schema(&transaction)?;
        verify_current_scope_schema(&transaction)?;
        verify_policy_fence_schema(&transaction)?;
        verify_supersession_schema(&transaction)?;
        verify_codex_later_turn_schema(&transaction)?;
        verify_codex_native_schema(&transaction)?;
        let store_lineage: String = transaction.query_row(
            "SELECT lineage FROM store_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        transaction.commit()?;
        // For a new file, commit user_version to its main header before WAL
        // mode. Future read-only version probes can reject older files without
        // opening SQLite or creating a sidecar.
        connection.execute_batch("PRAGMA journal_mode=WAL;")?;
        Ok(Self { connection, store_lineage })
    }

    pub fn owner_epoch(&self) -> Result<u64, StoreError> {
        let value: i64 = self.connection.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        Ok(value as u64)
    }

    /// Positive policy invalidation fence, independent of the global
    /// authority write/CAS revision. No V2 manifest may reinterpret this as
    /// its historical `authority_revision`.
    pub fn policy_fence_epoch(&self) -> Result<u64, StoreError> {
        let value: i64 = self.connection.query_row(
            "SELECT value FROM metadata WHERE key='policy_fence_epoch'",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(value)
            .ok()
            .filter(|value| *value > 0)
            .ok_or(StoreError::Conflict("v20 policy fence epoch is invalid"))
    }

    pub fn advance_owner_epoch(&mut self, expected: u64, next: u64) -> Result<(), StoreError> {
        let (expected, next) = successive_epochs(expected, next)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE metadata SET value=?1 WHERE key='owner_epoch' AND value=?2",
            params![next, expected],
        )?;
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        // This legacy owner transition has no v10 manager claim, but it must
        // still invalidate every policy-bound future launch.
        advance_policy_fence_epoch(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn target_epoch(&self, scope_id: &str, target_id: &str) -> Result<u64, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![scope_id, target_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0) as u64)
    }

    pub fn advance_target_epoch(
        &mut self,
        scope_id: &str,
        target_id: &str,
        expected: u64,
        next: u64,
    ) -> Result<(), StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        let (expected, next) = successive_epochs(expected, next)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = if expected == 0 {
            transaction.execute(
                "INSERT OR IGNORE INTO target_epochs(scope_id,target_id,epoch) VALUES(?1,?2,?3)",
                params![scope_id, target_id, next],
            )?
        } else {
            transaction.execute(
                "UPDATE target_epochs SET epoch=?1 WHERE scope_id=?2 AND target_id=?3 AND epoch=?4",
                params![next, scope_id, target_id, expected],
            )?
        };
        if changed != 1 {
            return Err(StoreError::StaleEpoch);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Commits command intent, one event, one outbox row, and their receipt together.
    pub fn admit(&mut self, request: &CommandRequest) -> Result<Admission, StoreError> {
        validate_request(request)?;
        let digest = digest_request(request);
        let effect_digest = sha256_hex(&request.effect_payload);
        let command_id = stable_command_id(request);
        let owner_epoch = integer(request.expected_owner_epoch)?;
        let target_epoch = integer(request.expected_target_epoch)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT command_id,scope_id,target_id,digest_version,request_digest,
                        canonical_request,owner_epoch,target_epoch,event_sequence,outbox_id
                 FROM commands WHERE principal=?1 AND namespace=?2 AND command_key=?3",
                params![
                    request.principal.as_str(),
                    request.namespace,
                    request.command_key
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?;
        if let Some((
            id,
            scope,
            target,
            version,
            prior_digest,
            bytes,
            prior_owner,
            prior_target,
            event,
            outbox,
        )) = existing
        {
            if scope != request.scope_id || target != request.target_id {
                return Err(StoreError::WrongScope);
            }
            if version != DIGEST_VERSION
                || prior_digest != digest
                || bytes != request.canonical_request
                || prior_owner != owner_epoch
                || prior_target != target_epoch
            {
                return Err(StoreError::Conflict(
                    "command key changed canonical content",
                ));
            }
            return Ok(Admission::Duplicate(Receipt {
                command_id: id,
                event_sequence: event.ok_or(StoreError::Conflict("incomplete committed event"))?,
                outbox_id: outbox.ok_or(StoreError::Conflict("incomplete committed outbox"))?,
                digest_version: DIGEST_VERSION,
                request_digest: digest,
            }));
        }
        if !supported_effect_kind(&request.effect_kind) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        let actual_owner: i64 = transaction.query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )?;
        let actual_target: Option<i64> = transaction
            .query_row(
                "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
                params![request.scope_id, request.target_id],
                |row| row.get(0),
            )
            .optional()?;
        if actual_owner != owner_epoch || actual_target.unwrap_or(0) != target_epoch {
            return Err(StoreError::StaleEpoch);
        }
        if request.effect_kind == "pod.offer" {
            let occupied: Option<i64> = transaction
                .query_row(
                    "SELECT command_rowid FROM launch_slots
                     WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                    params![request.scope_id, request.target_id, target_epoch],
                    |row| row.get(0),
                )
                .optional()?;
            if occupied.is_some() {
                return Err(StoreError::Conflict(
                    "launch slot already admitted for pod incarnation",
                ));
            }
        }
        transaction.execute(
            "INSERT INTO commands(command_id,principal,namespace,command_key,scope_id,target_id,
              digest_version,request_digest,canonical_request,owner_epoch,target_epoch)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                command_id,
                request.principal.as_str(),
                request.namespace,
                request.command_key,
                request.scope_id,
                request.target_id,
                DIGEST_VERSION,
                digest,
                request.canonical_request,
                owner_epoch,
                target_epoch
            ],
        )?;
        let command_rowid = transaction.last_insert_rowid();
        if request.effect_kind == "pod.offer" {
            transaction.execute(
                "INSERT INTO launch_slots(scope_id,pod_id,pod_incarnation,command_rowid)
                 VALUES(?1,?2,?3,?4)",
                params![
                    request.scope_id,
                    request.target_id,
                    target_epoch,
                    command_rowid
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO events(
               event_id,schema_version,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,source_id,source_kind,source_epoch,
               source_sequence,source_digest,source_order,kind,payload,recorded_at,
               provenance,causation_id)
             VALUES('event.pb07.' || lower(hex(randomblob(16))),1,?1,?2,?3,
                    ?4,?5,?6,'manager.admission',?4,1,?7,'contiguous',?8,?9,
                    strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                    'authenticated.manager.admission',?6)",
            params![
                command_rowid,
                request.scope_id,
                request.target_id,
                owner_epoch,
                target_epoch,
                command_id,
                digest,
                request.event_kind,
                request.event_payload
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO outbox(command_rowid,scope_id,target_id,owner_epoch,target_epoch,
              kind,payload,effect_digest,state)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'prepared')",
            params![
                command_rowid,
                request.scope_id,
                request.target_id,
                owner_epoch,
                target_epoch,
                request.effect_kind,
                request.effect_payload,
                effect_digest
            ],
        )?;
        let outbox_id = transaction.last_insert_rowid();
        transaction.execute(
            "UPDATE commands SET event_sequence=?1,outbox_id=?2 WHERE command_rowid=?3",
            params![event_sequence, outbox_id, command_rowid],
        )?;
        transaction.commit()?;
        Ok(Admission::Committed(Receipt {
            command_id,
            event_sequence,
            outbox_id,
            digest_version: DIGEST_VERSION,
            request_digest: digest,
        }))
    }

    /// Inspect an admitted command by opaque ID or caller key. The principal
    /// and authorised scope must come from the authenticated read boundary.
    /// Foreign and absent rows are indistinguishable; a key used in more than
    /// one namespace within this principal/scope is explicitly ambiguous.
    /// This one-snapshot read never admits, replays, claims, or dispatches.
    pub fn lookup_command(
        &mut self,
        scope_id: &str,
        principal: &VerifiedPrincipal,
        selector: &CommandLookupSelector,
    ) -> Result<CommandInspection, StoreError> {
        valid_id(scope_id)?;
        let (column, value) = match selector {
            CommandLookupSelector::Id { command_id } => ("command_id", command_id.as_str()),
            CommandLookupSelector::Key { key } => ("command_key", key.as_str()),
        };
        valid_id(value)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rows = {
            let sql = format!(
                "SELECT command_rowid,command_id,namespace,command_key,target_id,
                        digest_version,request_digest,canonical_request,owner_epoch,
                        target_epoch,event_sequence,outbox_id
                 FROM commands WHERE principal=?1 AND scope_id=?2 AND {column}=?3
                 ORDER BY command_rowid LIMIT 2"
            );
            let mut statement = transaction.prepare(&sql)?;
            statement
                .query_map(params![principal.as_str(), scope_id, value], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Vec<u8>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, Option<i64>>(11)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let [row] = rows.as_slice() else {
            return if rows.is_empty() {
                Err(StoreError::NotFound)
            } else {
                Err(StoreError::Conflict(
                    "command key is ambiguous across namespaces",
                ))
            };
        };
        let (
            command_rowid,
            command_id,
            namespace,
            command_key,
            target_id,
            version,
            request_digest,
            canonical_request,
            owner_epoch,
            target_epoch,
            event_sequence,
            outbox_id,
        ) = row;
        if *command_rowid <= 0 || *owner_epoch < 0 || *target_epoch < 0 || version != DIGEST_VERSION
        {
            return Err(StoreError::Conflict(
                "command admission lineage is malformed",
            ));
        }
        let event_sequence = event_sequence
            .filter(|sequence| *sequence > 0)
            .ok_or(StoreError::Conflict("incomplete committed event"))?;
        let outbox_id = outbox_id
            .filter(|id| *id > 0)
            .ok_or(StoreError::Conflict("incomplete committed outbox"))?;
        let admission_event: Option<(String, Vec<u8>, String, String, i64, i64)> = transaction
            .query_row(
                "SELECT kind,payload,scope_id,target_id,owner_epoch,target_epoch
                 FROM events WHERE sequence=?1 AND command_rowid=?2",
                params![event_sequence, command_rowid],
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
        let (event_kind, event_payload, event_scope, event_target, event_owner, event_epoch) =
            admission_event.ok_or(StoreError::Conflict("admission event is missing"))?;
        if event_scope != scope_id
            || event_target != *target_id
            || event_owner != *owner_epoch
            || event_epoch != *target_epoch
        {
            return Err(StoreError::Conflict("admission event lineage differs"));
        }
        let effect = transaction
            .query_row(
                "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                        o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                        o.claim_owner_epoch,o.observation_key,o.observation_payload,
                        o.observation_stage,o.observation_event_sequence,o.effect_digest
                 FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
                 WHERE o.outbox_id=?1 AND o.command_rowid=?2",
                params![outbox_id, command_rowid],
                stored_effect_from_row,
            )
            .optional()?
            .ok_or(StoreError::Conflict("admitted outbox effect is missing"))?;
        if effect.command_id != *command_id
            || effect.scope_id != scope_id
            || effect.target_id != *target_id
            || effect.admission_owner_epoch != *owner_epoch as u64
            || effect.admission_target_epoch != *target_epoch as u64
        {
            return Err(StoreError::Conflict("outbox command lineage differs"));
        }
        let reconstructed = CommandRequest {
            principal: principal.clone(),
            namespace: namespace.clone(),
            command_key: command_key.clone(),
            scope_id: scope_id.to_owned(),
            target_id: target_id.clone(),
            expected_owner_epoch: *owner_epoch as u64,
            expected_target_epoch: *target_epoch as u64,
            canonical_request: canonical_request.clone(),
            event_kind,
            event_payload,
            effect_kind: effect.kind.clone(),
            effect_payload: effect.payload.clone(),
        };
        validate_request(&reconstructed)?;
        if stable_command_id(&reconstructed) != *command_id
            || digest_request(&reconstructed) != *request_digest
        {
            return Err(StoreError::Conflict(
                "stored command identity or digest changed",
            ));
        }
        let claim = effect
            .claim_key
            .as_deref()
            .is_some_and(|key| valid_id(key).is_ok())
            && effect
                .claim_owner_epoch
                .is_some_and(|epoch| epoch > 0 && epoch <= i64::MAX as u64);
        let observation = effect
            .observation_key
            .as_deref()
            .is_some_and(|key| valid_id(key).is_ok())
            && effect
                .observation_payload
                .as_ref()
                .is_some_and(|payload| !payload.is_empty() && payload.len() <= MAX_BYTES)
            && effect.observed_stage.is_some()
            && effect
                .observation_event_sequence
                .is_some_and(|sequence| sequence > 0);
        match effect.state {
            EffectState::Prepared
                if effect.claim_key.is_some()
                    || effect.claim_owner_epoch.is_some()
                    || effect.observation_key.is_some()
                    || effect.observation_payload.is_some()
                    || effect.observed_stage.is_some()
                    || effect.observation_event_sequence.is_some() =>
            {
                return Err(StoreError::Conflict("prepared effect has later evidence"));
            }
            EffectState::ClaimedUncertain
                if !claim
                    || effect.observation_key.is_some()
                    || effect.observation_payload.is_some()
                    || effect.observed_stage.is_some()
                    || effect.observation_event_sequence.is_some() =>
            {
                return Err(StoreError::Conflict(
                    "claimed effect evidence is incomplete",
                ));
            }
            EffectState::Observed if !claim || !observation => {
                return Err(StoreError::Conflict(
                    "observed effect evidence is incomplete",
                ));
            }
            _ => {}
        }
        if let Some(sequence) = effect.observation_event_sequence {
            let observed: Option<(i64, String, String)> = transaction
                .query_row(
                    "SELECT command_rowid,kind,provenance FROM events WHERE sequence=?1
                       AND scope_id=?2 AND target_id=?3",
                    params![sequence, scope_id, target_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let (observed_command, kind, provenance) =
                observed.ok_or(StoreError::Conflict("observation event is missing"))?;
            if observed_command != *command_rowid
                || (effect.observed_stage == Some(ObservedStage::HostAccepted)
                    && (kind != "effect.host_accepted"
                        || provenance != "authenticated.host.acceptance"))
            {
                return Err(StoreError::Conflict("observation event lineage differs"));
            }
        }
        let launch_dispatch_status = if namespace == "podbay.launch" && effect.kind == "pod.offer" {
            let outcome: Option<(String, Option<String>, String)> = transaction
                .query_row(
                    "SELECT stage,receipt_ref,claim_key FROM launch_dispatch_outcomes
                     WHERE outbox_id=?1",
                    [outbox_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let status = match (effect.state, outcome) {
                (EffectState::Prepared, None) if effect.claim_key.is_none() => {
                    LaunchDispatchStatus {
                        stage: LaunchDispatchStage::Prepared,
                        receipt_ref: None,
                    }
                }
                (EffectState::ClaimedUncertain | EffectState::Observed, None)
                    if effect.claim_key.is_some() =>
                {
                    LaunchDispatchStatus {
                        stage: LaunchDispatchStage::ClaimedUncertain,
                        receipt_ref: None,
                    }
                }
                (
                    EffectState::ClaimedUncertain | EffectState::Observed,
                    Some((stage, reference, claim)),
                ) if effect.claim_key.as_deref() == Some(claim.as_str()) => {
                    if let Some(reference) = &reference {
                        valid_id(reference)?;
                    }
                    LaunchDispatchStatus {
                        stage: crate::launch::decode_stage(&stage)?,
                        receipt_ref: reference,
                    }
                }
                _ => return Err(StoreError::Conflict("launch dispatch readback differs")),
            };
            Some(status)
        } else {
            None
        };
        let result = CommandInspection {
            receipt: Receipt {
                command_id: command_id.clone(),
                event_sequence,
                outbox_id,
                digest_version: DIGEST_VERSION,
                request_digest: request_digest.clone(),
            },
            effect_state: effect.state,
            observed_stage: effect.observed_stage,
            observation_event_sequence: effect.observation_event_sequence,
            launch_dispatch_status,
        };
        transaction.commit()?;
        Ok(result)
    }

    /// Inspection-only duplicate lookup. It performs SELECTs in one deferred
    /// snapshot, never resolves today's profile, advances an epoch, claims an
    /// outbox item, or calls a host port. Every schema-v7 result is explicitly
    /// historical/unbound and cannot itself authorize dispatch.
    pub fn lookup_admitted_launch(
        &mut self,
        request: &LaunchLookupRequest,
    ) -> Result<AdmittedLaunchInspection, StoreError> {
        for value in [
            &request.namespace,
            &request.command_key,
            &request.scope_id,
            &request.target_id,
        ] {
            valid_id(value)?;
        }
        if request.namespace != "podbay.launch" {
            return Err(StoreError::NotFound);
        }
        if request.canonical_intent.is_empty() || request.canonical_intent.len() > MAX_BYTES {
            return Err(StoreError::InvalidInput(
                "canonical caller intent size is invalid",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row: Option<(
            i64,
            String,
            String,
            String,
            Vec<u8>,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
        )> = transaction
            .query_row(
                "SELECT command_rowid,command_id,digest_version,request_digest,
                        canonical_request,owner_epoch,target_epoch,event_sequence,outbox_id
                 FROM commands WHERE principal=?1 AND namespace=?2 AND command_key=?3
                   AND scope_id=?4 AND target_id=?5",
                params![
                    request.principal.as_str(),
                    request.namespace,
                    request.command_key,
                    request.scope_id,
                    request.target_id
                ],
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
                    ))
                },
            )
            .optional()?;
        let (
            command_rowid,
            command_id,
            version,
            request_digest,
            canonical,
            owner,
            target_epoch,
            event,
            outbox,
        ) = row.ok_or(StoreError::NotFound)?;
        if canonical != request.canonical_intent {
            return Err(StoreError::Conflict(
                "command key changed canonical caller intent",
            ));
        }
        if version != DIGEST_VERSION || owner < 0 || target_epoch <= 0 {
            return Err(StoreError::Conflict(
                "launch admission lineage is malformed",
            ));
        }
        let event_sequence = event
            .filter(|id| *id > 0)
            .ok_or(StoreError::Conflict("incomplete committed event"))?;
        let outbox_id = outbox
            .filter(|id| *id > 0)
            .ok_or(StoreError::Conflict("incomplete committed outbox"))?;
        let reserved: Option<i64> = transaction
            .query_row(
                "SELECT command_rowid FROM launch_slots
             WHERE scope_id=?1 AND pod_id=?2 AND pod_incarnation=?3",
                params![request.scope_id, request.target_id, target_epoch],
                |row| row.get(0),
            )
            .optional()?;
        if reserved != Some(command_rowid) {
            return Err(StoreError::Conflict(
                "launch slot does not bind admitted command",
            ));
        }
        let admission_event: Option<(String, Vec<u8>, String, String, i64, i64)> = transaction
            .query_row(
                "SELECT kind,payload,scope_id,target_id,owner_epoch,target_epoch
                 FROM events WHERE sequence=?1 AND command_rowid=?2",
                params![event_sequence, command_rowid],
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
        let (event_kind, event_payload, event_scope, event_target, event_owner, event_target_epoch) =
            admission_event.ok_or(StoreError::Conflict("admission event is missing"))?;
        if event_scope != request.scope_id
            || event_target != request.target_id
            || event_owner != owner
            || event_target_epoch != target_epoch
        {
            return Err(StoreError::Conflict("admission event lineage differs"));
        }
        let raw_effect: Option<(Vec<u8>, String)> = transaction
            .query_row(
                "SELECT payload,effect_digest FROM outbox
             WHERE outbox_id=?1 AND command_rowid=?2",
                params![outbox_id, command_rowid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (effect_payload, effect_digest) =
            raw_effect.ok_or(StoreError::Conflict("admitted outbox effect is missing"))?;
        if sha256_hex(&effect_payload) != effect_digest {
            return Err(StoreError::Conflict("outbox effect digest changed"));
        }
        let effect = transaction.query_row(
            "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                    o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                    o.claim_owner_epoch,o.observation_key,o.observation_payload,
                    o.observation_stage,o.observation_event_sequence,o.effect_digest
             FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
             WHERE o.outbox_id=?1 AND o.command_rowid=?2",
            params![outbox_id, command_rowid],
            stored_effect_from_row,
        )?;
        if effect.kind != "pod.offer" {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if effect.command_id != command_id
            || effect.scope_id != request.scope_id
            || effect.target_id != request.target_id
            || effect.admission_owner_epoch != owner as u64
            || effect.admission_target_epoch != target_epoch as u64
        {
            return Err(StoreError::Conflict("outbox launch lineage differs"));
        }
        let reconstructed = CommandRequest {
            principal: request.principal.clone(),
            namespace: request.namespace.clone(),
            command_key: request.command_key.clone(),
            scope_id: request.scope_id.clone(),
            target_id: request.target_id.clone(),
            expected_owner_epoch: owner as u64,
            expected_target_epoch: target_epoch as u64,
            canonical_request: canonical,
            event_kind,
            event_payload,
            effect_kind: effect.kind.clone(),
            effect_payload,
        };
        if digest_request(&reconstructed) != request_digest {
            return Err(StoreError::Conflict("stored launch request digest changed"));
        }
        let outcome: (String, Option<String>, Option<String>) = transaction.query_row(
            "SELECT o.state,d.stage,d.receipt_ref FROM outbox o
             LEFT JOIN launch_dispatch_outcomes d ON d.outbox_id=o.outbox_id
             WHERE o.outbox_id=?1",
            [outbox_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let status = match (outcome.0.as_str(), outcome.1.as_deref()) {
            ("prepared", None) => LaunchDispatchStatus {
                stage: LaunchDispatchStage::Prepared,
                receipt_ref: None,
            },
            ("claimed_uncertain" | "observed", None) => LaunchDispatchStatus {
                stage: LaunchDispatchStage::ClaimedUncertain,
                receipt_ref: None,
            },
            ("claimed_uncertain" | "observed", Some(stage)) => LaunchDispatchStatus {
                stage: match stage {
                    "refused_before_effect" => LaunchDispatchStage::RefusedBeforeEffect,
                    "uncertain_after_possible_effect" => {
                        LaunchDispatchStage::UncertainAfterPossibleEffect
                    }
                    "host_accepted" => LaunchDispatchStage::HostAccepted,
                    "port_settled" => LaunchDispatchStage::PortSettled,
                    _ => return Err(StoreError::Conflict("unknown launch dispatch stage")),
                },
                receipt_ref: outcome.2,
            },
            _ => return Err(StoreError::Conflict("launch dispatch state is malformed")),
        };
        let has_binding: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM launch_bindings WHERE command_rowid=?1",
                [command_rowid],
                |row| row.get(0),
            )
            .optional()?;
        let binding = if has_binding.is_some() {
            read_bound_record(&transaction, command_rowid)?;
            LaunchIntentBinding::BoundV8
        } else {
            LaunchIntentBinding::HistoricalUnbound
        };
        transaction.commit()?;
        Ok(AdmittedLaunchInspection {
            receipt: Receipt {
                command_id,
                event_sequence,
                outbox_id,
                digest_version: DIGEST_VERSION,
                request_digest,
            },
            effect,
            status,
            binding,
        })
    }

    /// A claimed effect may already have happened. Reopen must not dispatch it again.
    /// A new Prepared claim additionally CAS-checks the authority revision so
    /// grant/policy changes between review and claim cannot authorize effect.
    pub fn claim_effect(
        &mut self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
        expected_owner_epoch: u64,
        expected_target_epoch: u64,
        expected_authority_revision: u64,
        claim_key: &str,
    ) -> Result<EffectClaim, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        valid_id(claim_key)?;
        let owner_epoch = integer(expected_owner_epoch)?;
        let target_epoch = integer(expected_target_epoch)?;
        let authority_revision = integer(expected_authority_revision)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT scope_id,target_id,target_epoch,state,claim_key,kind,
                        payload,effect_digest,command_rowid
                 FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if row.0 != scope_id || row.1 != target_id {
            return Err(StoreError::WrongScope);
        }
        if current_owner(&transaction)? != owner_epoch
            || current_target(&transaction, scope_id, target_id)? != target_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        if !supported_effect_kind(&row.5) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if sha256_hex(&row.6) != row.7 {
            return Err(StoreError::Conflict("outbox effect digest changed"));
        }
        if row.5 == "pod.offer" {
            // Generic legacy admissions remain inspectable, but no unbound
            // offer may cross the effect-claim boundary in schema eight.
            let bound = read_bound_record(&transaction, row.8)?;
            if row.3 == "prepared" {
                ensure_current_dispatch_eligible(&transaction, &bound)?;
            }
        }
        let result = match row.3.as_str() {
            "prepared" => {
                let current_authority_revision: i64 = transaction.query_row(
                    "SELECT value FROM metadata WHERE key='authority_revision'",
                    [],
                    |row| row.get(0),
                )?;
                if current_authority_revision != authority_revision {
                    return Err(StoreError::StaleEpoch);
                }
                if row.2 != target_epoch {
                    return Err(StoreError::TargetReconciliationRequired);
                }
                transaction.execute(
                    "UPDATE outbox SET state='claimed_uncertain',claim_key=?1,
                     claim_owner_epoch=?2 WHERE outbox_id=?3 AND state='prepared'",
                    params![claim_key, owner_epoch, outbox_id],
                )?;
                EffectClaim::NewClaim
            }
            "claimed_uncertain" if row.4.as_deref() == Some(claim_key) => {
                EffectClaim::ExistingUncertain
            }
            "observed" if row.4.as_deref() == Some(claim_key) => EffectClaim::AlreadyObserved,
            _ => return Err(StoreError::Conflict("effect claim identity changed")),
        };
        transaction.commit()?;
        Ok(result)
    }

    pub fn effect_state(&self, outbox_id: i64) -> Result<EffectState, StoreError> {
        let state: Option<String> = self
            .connection
            .query_row(
                "SELECT state FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| row.get(0),
            )
            .optional()?;
        match state.as_deref() {
            Some("prepared") => Ok(EffectState::Prepared),
            Some("claimed_uncertain") => Ok(EffectState::ClaimedUncertain),
            Some("observed") => Ok(EffectState::Observed),
            Some(_) => Err(StoreError::Conflict("unknown outbox state")),
            None => Err(StoreError::NotFound),
        }
    }

    /// Reads durable dispatch material only within the caller's chosen scope and target.
    pub fn load_effect(
        &self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
    ) -> Result<StoredEffect, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        let effect = self
            .connection
            .query_row(
                "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                        o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                        o.claim_owner_epoch,o.observation_key,o.observation_payload,
                        o.observation_stage,o.observation_event_sequence,o.effect_digest
                 FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
                 WHERE o.outbox_id=?1",
                [outbox_id],
                stored_effect_from_row,
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if effect.scope_id != scope_id || effect.target_id != target_id {
            return Err(StoreError::WrongScope);
        }
        Ok(effect)
    }

    /// Enumerates unobserved effects for a known authorised scope after restart.
    /// Unknown kinds remain visible for reconciliation, but cannot be claimed.
    pub fn pending_effects(
        &self,
        scope_id: &str,
        after_outbox_id: i64,
        limit: usize,
    ) -> Result<Vec<StoredEffect>, StoreError> {
        valid_id(scope_id)?;
        if after_outbox_id < 0 || !(1..=512).contains(&limit) {
            return Err(StoreError::InvalidInput(
                "effect cursor or page limit is invalid",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                    o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                    o.claim_owner_epoch,o.observation_key,o.observation_payload,
                    o.observation_stage,o.observation_event_sequence,o.effect_digest
             FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
             WHERE o.scope_id=?1 AND o.outbox_id>?2 AND o.state!='observed'
             ORDER BY o.outbox_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![scope_id, after_outbox_id, limit as i64],
            stored_effect_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Records host acceptance, never provider insertion or task completion.
    /// The authenticated host boundary must validate the proof before construction.
    pub fn observe_effect(
        &mut self,
        outbox_id: i64,
        scope_id: &str,
        target_id: &str,
        expected_owner_epoch: u64,
        expected_target_epoch: u64,
        claim_key: &str,
        proof: &HostAcceptanceProof,
    ) -> Result<EffectObservation, StoreError> {
        valid_id(scope_id)?;
        valid_id(target_id)?;
        valid_id(claim_key)?;
        let owner_epoch = integer(expected_owner_epoch)?;
        let target_epoch = integer(expected_target_epoch)?;
        let source_epoch = integer(proof.source_epoch)?;
        let source_sequence = integer(proof.source_sequence)?;
        let source_digest = digest_host_proof(outbox_id, scope_id, target_id, claim_key, proof);
        let public_payload = host_event_payload(proof);
        let store_lineage = self.store_lineage.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = transaction
            .query_row(
                "SELECT command_rowid,scope_id,target_id,kind,state,claim_key,
                        observation_key,observation_payload,observation_stage,
                        observation_event_sequence FROM outbox WHERE outbox_id=?1",
                [outbox_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if row.1 != scope_id || row.2 != target_id {
            return Err(StoreError::WrongScope);
        }
        if current_owner(&transaction)? != owner_epoch
            || current_target(&transaction, scope_id, target_id)? != target_epoch
        {
            return Err(StoreError::StaleEpoch);
        }
        if !supported_effect_kind(&row.3) {
            return Err(StoreError::UnsupportedEffectKind);
        }
        if row.5.as_deref() != Some(claim_key) {
            return Err(StoreError::Conflict("effect claim identity changed"));
        }
        let existing: Option<(String, i64, String)> = transaction
            .query_row(
                "SELECT event_id,sequence,source_digest FROM events
                 WHERE scope_id=?1 AND source_id=?2 AND source_epoch=?3
                   AND source_sequence=?4",
                params![scope_id, proof.source_id, source_epoch, source_sequence],
                |event| Ok((event.get(0)?, event.get(1)?, event.get(2)?)),
            )
            .optional()?;
        if let Some((event_id, event_sequence, prior_digest)) = existing {
            if prior_digest != source_digest {
                transaction.execute(
                    "INSERT OR IGNORE INTO event_quarantine(
                       scope_id,source_id,source_epoch,source_sequence,
                       existing_event_id,incoming_digest,incoming_payload,
                       incoming_evidence,recorded_at)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,
                       strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    params![
                        scope_id,
                        proof.source_id,
                        source_epoch,
                        source_sequence,
                        event_id,
                        source_digest,
                        public_payload,
                        proof.evidence,
                    ],
                )?;
                transaction.commit()?;
                return Err(StoreError::SourceIdentityQuarantined);
            }
            if row.4 != "observed"
                || row.6.as_deref() != Some(proof.host_receipt_id.as_str())
                || row.7.as_deref() != Some(proof.evidence.as_slice())
                || row.8.as_deref() != Some("host_accepted")
                || row.9 != Some(event_sequence)
            {
                return Err(StoreError::Conflict(
                    "source identity belongs to another effect",
                ));
            }
            transaction.commit()?;
            return Ok(EffectObservation::AlreadyObserved(EventReference {
                event_id,
                cursor: EventCursor {
                    store_lineage,
                    scope_id: scope_id.to_owned(),
                    sequence: event_sequence,
                },
            }));
        }
        if row.4 != "claimed_uncertain" {
            return Err(StoreError::Conflict("effect observation identity changed"));
        }
        let highest_seen: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(source_sequence),0) FROM events
             WHERE scope_id=?1 AND source_id=?2 AND source_epoch=?3",
            params![scope_id, proof.source_id, source_epoch],
            |event| event.get(0),
        )?;
        let (source_order, order_reference) = if source_sequence == highest_seen + 1 {
            ("contiguous", None)
        } else if source_sequence > highest_seen + 1 {
            ("gap", Some(highest_seen + 1))
        } else {
            ("out_of_order", Some(highest_seen))
        };
        transaction.execute(
            "INSERT INTO events(
               event_id,schema_version,command_rowid,scope_id,target_id,
               owner_epoch,target_epoch,source_id,source_kind,source_epoch,
               source_sequence,source_digest,source_order,source_order_reference,
               kind,payload,recorded_at,occurred_at,provenance,correlation_id,
               causation_id)
             VALUES('event.pb07.' || lower(hex(randomblob(16))),1,?1,?2,?3,
                    ?4,?5,?6,'host',?7,?8,?9,?10,?11,
                    'effect.host_accepted',?12,
                    strftime('%Y-%m-%dT%H:%M:%fZ','now'),?13,
                    'authenticated.host.acceptance',?14,?15)",
            params![
                row.0,
                scope_id,
                target_id,
                owner_epoch,
                target_epoch,
                proof.source_id,
                source_epoch,
                source_sequence,
                source_digest,
                source_order,
                order_reference,
                public_payload,
                proof.occurred_at,
                proof.correlation_id,
                proof.causation_id,
            ],
        )?;
        let event_sequence = transaction.last_insert_rowid();
        let event_id: String = transaction.query_row(
            "SELECT event_id FROM events WHERE sequence=?1",
            [event_sequence],
            |event| event.get(0),
        )?;
        let changed = transaction.execute(
            "UPDATE outbox SET state='observed',observation_key=?1,
             observation_payload=?2,observation_stage='host_accepted',
             observation_event_sequence=?3
             WHERE outbox_id=?4 AND state='claimed_uncertain'",
            params![
                proof.host_receipt_id,
                proof.evidence,
                event_sequence,
                outbox_id
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "effect changed while recording observation",
            ));
        }
        transaction.commit()?;
        Ok(EffectObservation::NewObservation(EventReference {
            event_id,
            cursor: EventCursor {
                store_lineage,
                scope_id: scope_id.to_owned(),
                sequence: event_sequence,
            },
        }))
    }

    pub fn quarantined_events(
        &self,
        scope_id: &str,
        after_quarantine_id: i64,
        limit: usize,
    ) -> Result<Vec<QuarantinedSourceEvent>, StoreError> {
        valid_id(scope_id)?;
        if after_quarantine_id < 0 || !(1..=512).contains(&limit) {
            return Err(StoreError::InvalidInput(
                "quarantine cursor or limit is invalid",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT quarantine_id,scope_id,source_id,source_epoch,source_sequence,
                    existing_event_id,incoming_digest,incoming_payload,incoming_evidence,
                    recorded_at
             FROM event_quarantine WHERE scope_id=?1 AND quarantine_id>?2
             ORDER BY quarantine_id LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![scope_id, after_quarantine_id, limit as i64],
            |row| {
                Ok(QuarantinedSourceEvent {
                    quarantine_id: row.get(0)?,
                    scope_id: row.get(1)?,
                    source_id: row.get(2)?,
                    source_epoch: row.get::<_, i64>(3)? as u64,
                    source_sequence: row.get::<_, i64>(4)? as u64,
                    existing_event_id: row.get(5)?,
                    incoming_digest: row.get(6)?,
                    incoming_payload: row.get(7)?,
                    incoming_evidence: row.get(8)?,
                    recorded_at: row.get(9)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Snapshot and cursor are read from one SQLite transaction; events after cursor cannot vanish.
    pub fn scope_snapshot(&mut self, scope_id: &str) -> Result<ScopeSnapshot, StoreError> {
        valid_id(scope_id)?;
        let store_lineage = self.store_lineage.clone();
        let transaction = self.connection.transaction()?;
        let cursor: i64 =
            transaction.query_row("SELECT COALESCE(MAX(sequence),0) FROM events", [], |row| {
                row.get(0)
            })?;
        let receipts = {
            let mut statement = transaction.prepare(
                "SELECT command_id,event_sequence,outbox_id,request_digest,digest_version
                 FROM commands WHERE scope_id=?1 ORDER BY command_rowid",
            )?;
            let rows = statement.query_map([scope_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            rows.map(|row| {
                let (command_id, event, outbox, digest, version) = row?;
                if version != DIGEST_VERSION {
                    return Err(StoreError::Conflict("unknown committed digest version"));
                }
                Ok(Receipt {
                    command_id,
                    event_sequence: event.ok_or(StoreError::Conflict("missing event lineage"))?,
                    outbox_id: outbox.ok_or(StoreError::Conflict("missing outbox lineage"))?,
                    request_digest: digest,
                    digest_version: DIGEST_VERSION,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?
        };
        let effects = {
            let mut statement = transaction.prepare(
                "SELECT o.outbox_id,c.command_id,o.scope_id,o.target_id,o.owner_epoch,
                        o.target_epoch,o.kind,o.payload,o.state,o.claim_key,
                        o.claim_owner_epoch,o.observation_key,o.observation_payload,
                        o.observation_stage,o.observation_event_sequence,o.effect_digest
                 FROM outbox o JOIN commands c ON c.command_rowid=o.command_rowid
                 WHERE o.scope_id=?1 ORDER BY o.outbox_id",
            )?;
            statement
                .query_map([scope_id], stored_effect_from_row)?
                .collect::<Result<Vec<_>, _>>()?
        };
        let source_anomalies = {
            let mut statement = transaction.prepare(
                "SELECT event_id,source_id,source_epoch,source_sequence,
                        source_order,source_order_reference
                 FROM events WHERE scope_id=?1 AND source_order!='contiguous'
                 ORDER BY sequence",
            )?;
            statement
                .query_map([scope_id], |row| {
                    let order: String = row.get(4)?;
                    let reference: Option<i64> = row.get(5)?;
                    Ok(SourceAnomaly {
                        event_id: row.get(0)?,
                        source_id: row.get(1)?,
                        source_epoch: row.get::<_, i64>(2)? as u64,
                        source_sequence: row.get::<_, i64>(3)? as u64,
                        order: source_order_from_row(&order, reference)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit()?;
        Ok(ScopeSnapshot {
            cursor: EventCursor {
                store_lineage,
                scope_id: scope_id.to_owned(),
                sequence: cursor,
            },
            receipts,
            effects,
            source_anomalies,
        })
    }

    pub fn initial_cursor(&self, scope_id: &str) -> Result<EventCursor, StoreError> {
        valid_id(scope_id)?;
        Ok(EventCursor {
            store_lineage: self.store_lineage.clone(),
            scope_id: scope_id.to_owned(),
            sequence: 0,
        })
    }

    pub fn events_after(
        &self,
        scope_id: &str,
        after: &EventCursor,
        limit: usize,
    ) -> Result<Vec<CommittedEvent>, StoreError> {
        valid_id(scope_id)?;
        if after.store_lineage != self.store_lineage || after.scope_id != scope_id {
            return Err(StoreError::WrongCursor);
        }
        if after.sequence < 0 || !(1..=512).contains(&limit) {
            return Err(StoreError::InvalidInput(
                "event cursor or page limit is invalid",
            ));
        }
        let current_max: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(sequence),0) FROM events",
            [],
            |row| row.get(0),
        )?;
        if after.sequence > current_max {
            return Err(StoreError::WrongCursor);
        }
        let mut statement = self.connection.prepare(
            "SELECT e.sequence,e.event_id,e.schema_version,c.command_id,e.target_id,
                    e.source_id,e.source_kind,e.source_epoch,e.source_sequence,
                    e.source_order,e.source_order_reference,e.recorded_at,e.occurred_at,
                    e.provenance,e.correlation_id,e.causation_id,e.kind,e.payload
             FROM events e
             JOIN commands c ON c.command_rowid=e.command_rowid
             WHERE e.scope_id=?1 AND e.sequence>?2 ORDER BY e.sequence LIMIT ?3",
        )?;
        let rows = statement.query_map(params![scope_id, after.sequence, limit as i64], |row| {
            committed_event_from_row(row, &self.store_lineage, scope_id)
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }
}

pub(crate) fn validate_request(request: &CommandRequest) -> Result<(), StoreError> {
    for value in [
        &request.namespace,
        &request.command_key,
        &request.scope_id,
        &request.target_id,
        &request.event_kind,
        &request.effect_kind,
    ] {
        valid_id(value)?;
    }
    if request.effect_kind == "pod.offer" && request.expected_target_epoch == 0 {
        return Err(StoreError::InvalidInput(
            "launch pod incarnation must be positive",
        ));
    }
    for bytes in [
        &request.canonical_request,
        &request.event_payload,
        &request.effect_payload,
    ] {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(StoreError::InvalidInput(
                "canonical or effect payload size is invalid",
            ));
        }
    }
    integer(request.expected_owner_epoch)?;
    integer(request.expected_target_epoch)?;
    Ok(())
}

fn supported_effect_kind(kind: &str) -> bool {
    matches!(kind, "pod.offer")
}

pub(crate) fn valid_id(value: &str) -> Result<(), StoreError> {
    if value.len() < 3 || value.len() > 160 || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput(
            "identity length or content is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn integer(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput("epoch exceeds SQLite range"))
}

fn successive_epochs(expected: u64, next: u64) -> Result<(i64, i64), StoreError> {
    if next
        != expected
            .checked_add(1)
            .ok_or(StoreError::InvalidInput("epoch overflow"))?
    {
        return Err(StoreError::InvalidInput("epoch must advance exactly once"));
    }
    Ok((integer(expected)?, integer(next)?))
}

fn current_owner(transaction: &rusqlite::Transaction<'_>) -> Result<i64, StoreError> {
    transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='owner_epoch'",
            [],
            |row| row.get(0),
        )
        .map_err(StoreError::from)
}

fn current_target(
    transaction: &rusqlite::Transaction<'_>,
    scope: &str,
    target: &str,
) -> Result<i64, StoreError> {
    Ok(transaction
        .query_row(
            "SELECT epoch FROM target_epochs WHERE scope_id=?1 AND target_id=?2",
            params![scope, target],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

fn stored_effect_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEffect> {
    let state = match row.get::<_, String>(8)?.as_str() {
        "prepared" => EffectState::Prepared,
        "claimed_uncertain" => EffectState::ClaimedUncertain,
        "observed" => EffectState::Observed,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let observed_stage = match row.get::<_, Option<String>>(13)?.as_deref() {
        Some("host_accepted") => Some(ObservedStage::HostAccepted),
        Some("legacy_unverified") => Some(ObservedStage::LegacyUnverified),
        None => None,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let payload: Vec<u8> = row.get(7)?;
    let effect_digest: String = row.get(15)?;
    if sha256_hex(&payload) != effect_digest {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(StoredEffect {
        outbox_id: row.get(0)?,
        command_id: row.get(1)?,
        scope_id: row.get(2)?,
        target_id: row.get(3)?,
        admission_owner_epoch: row.get::<_, i64>(4)? as u64,
        admission_target_epoch: row.get::<_, i64>(5)? as u64,
        kind: row.get(6)?,
        payload,
        effect_digest,
        state,
        claim_key: row.get(9)?,
        claim_owner_epoch: row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
        observation_key: row.get(11)?,
        observation_payload: row.get(12)?,
        observed_stage,
        observation_event_sequence: row.get(14)?,
    })
}

fn source_order_from_row(value: &str, reference: Option<i64>) -> rusqlite::Result<SourceOrder> {
    match (value, reference) {
        ("contiguous", None) => Ok(SourceOrder::Contiguous),
        ("gap", Some(expected_next)) if expected_next >= 1 => Ok(SourceOrder::Gap {
            expected_next: expected_next as u64,
        }),
        ("out_of_order", Some(highest_seen)) if highest_seen >= 1 => Ok(SourceOrder::OutOfOrder {
            highest_seen: highest_seen as u64,
        }),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn committed_event_from_row(
    row: &rusqlite::Row<'_>,
    store_lineage: &str,
    scope_id: &str,
) -> rusqlite::Result<CommittedEvent> {
    let sequence: i64 = row.get(0)?;
    let order: String = row.get(9)?;
    let reference: Option<i64> = row.get(10)?;
    Ok(CommittedEvent {
        sequence,
        event_id: row.get(1)?,
        cursor: EventCursor {
            store_lineage: store_lineage.to_owned(),
            scope_id: scope_id.to_owned(),
            sequence,
        },
        schema_version: row.get::<_, i64>(2)? as u32,
        command_id: row.get(3)?,
        target_id: row.get(4)?,
        source_id: row.get(5)?,
        source_kind: row.get(6)?,
        source_epoch: row.get::<_, i64>(7)? as u64,
        source_sequence: row.get::<_, i64>(8)? as u64,
        source_order: source_order_from_row(&order, reference)?,
        recorded_at: row.get(11)?,
        occurred_at: row.get(12)?,
        provenance: row.get(13)?,
        correlation_id: row.get(14)?,
        causation_id: row.get(15)?,
        kind: row.get(16)?,
        payload: row.get(17)?,
    })
}

fn digest_host_proof(
    outbox_id: i64,
    scope_id: &str,
    target_id: &str,
    claim_key: &str,
    proof: &HostAcceptanceProof,
) -> String {
    let mut digest = Sha256::new();
    let outbox_bytes = outbox_id.to_be_bytes();
    let source_epoch_bytes = proof.source_epoch.to_be_bytes();
    let source_sequence_bytes = proof.source_sequence.to_be_bytes();
    for field in [
        b"podbay-host-acceptance/1".as_slice(),
        outbox_bytes.as_slice(),
        scope_id.as_bytes(),
        target_id.as_bytes(),
        claim_key.as_bytes(),
        proof.source_id.as_bytes(),
        source_epoch_bytes.as_slice(),
        source_sequence_bytes.as_slice(),
        proof.host_receipt_id.as_bytes(),
        proof.evidence.as_slice(),
        proof.occurred_at.as_deref().unwrap_or("").as_bytes(),
        proof.correlation_id.as_bytes(),
        proof.causation_id.as_deref().unwrap_or("").as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn host_event_payload(proof: &HostAcceptanceProof) -> Vec<u8> {
    let evidence_digest = Sha256::digest(&proof.evidence)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{{\"kind\":\"delivery_changed\",\"observedStage\":\"host_accepted\",\
         \"hostReceiptId\":\"{}\",\"evidenceDigest\":\"{}\"}}",
        proof.host_receipt_id, evidence_digest
    )
    .into_bytes()
}

pub(crate) fn digest_request(request: &CommandRequest) -> String {
    let mut digest = Sha256::new();
    for field in [
        DIGEST_VERSION.as_bytes(),
        request.principal.as_str().as_bytes(),
        request.namespace.as_bytes(),
        request.command_key.as_bytes(),
        request.scope_id.as_bytes(),
        request.target_id.as_bytes(),
        request.canonical_request.as_slice(),
        request.event_kind.as_bytes(),
        request.event_payload.as_slice(),
        request.effect_kind.as_bytes(),
        request.effect_payload.as_slice(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.update(request.expected_owner_epoch.to_be_bytes());
    digest.update(request.expected_target_epoch.to_be_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn stable_command_id(request: &CommandRequest) -> String {
    let mut digest = Sha256::new();
    for field in [
        b"podbay-command-id/1".as_slice(),
        request.principal.as_str().as_bytes(),
        request.namespace.as_bytes(),
        request.command_key.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    format!(
        "command.pb04.{}",
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn verify_authority_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    for (table, expected) in [
        ("authority_pods", &["pod_id", "scope_id", "incarnation"][..]),
        (
            "authority_resources",
            &[
                "resource_id",
                "scope_id",
                "pod_id",
                "pod_incarnation",
                "resource_epoch",
                "input_epoch",
            ][..],
        ),
        (
            "authority_actors",
            &[
                "actor_id",
                "scope_id",
                "role",
                "origin",
                "parent_actor_id",
                "pod_id",
                "pod_incarnation",
                "credential_generation",
                "platform",
                "os_identity",
                "process_identity",
                "start_identity",
                "containment_identity",
            ][..],
        ),
        (
            "authority_grants",
            &[
                "grant_id",
                "scope_id",
                "actor_id",
                "credential_generation",
                "mode",
                "remaining_depth",
            ][..],
        ),
        (
            "authority_grant_rights",
            &["grant_id", "operation", "target_kind", "target_id"][..],
        ),
        (
            "launch_dispatch_outcomes",
            &[
                "outbox_id",
                "claim_key",
                "stage",
                "receipt_ref",
                "recorded_at",
            ][..],
        ),
        (
            "launch_slots",
            &["scope_id", "pod_id", "pod_incarnation", "command_rowid"][..],
        ),
    ] {
        let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        if columns.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(StoreError::Conflict(
                "authority schema columns do not match",
            ));
        }
    }
    Ok(())
}

fn verify_runtime_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    verify_runtime_schema_v8(transaction)?;
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='run_child_budgets'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(RUN_CHILD_BUDGETS_V16) {
        return Err(StoreError::Conflict("v16 run budget schema differs"));
    }
    Ok(())
}

fn verify_writer_lease_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='native_writer_leases'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(NATIVE_WRITER_LEASES_V17) {
        return Err(StoreError::Conflict("v17 writer lease schema differs"));
    }
    Ok(())
}

fn verify_codex_bootstrap_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='codex_bootstrap_sends'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(CODEX_BOOTSTRAP_SENDS_V18) {
        return Err(StoreError::Conflict("v18 bootstrap schema differs"));
    }
    Ok(())
}

fn verify_runtime_schema_v8(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    for (name, kind, expected) in [
        ("runtime_sessions", "table", RUNTIME_SESSIONS_V8),
        ("runtime_runs", "table", RUNTIME_RUNS_V8),
        ("launch_bindings", "table", LAUNCH_BINDINGS_V8),
        ("launch_resources", "table", LAUNCH_RESOURCES_V8),
        (
            "launch_slots_binding_identity",
            "index",
            LAUNCH_SLOT_BINDING_INDEX_V8,
        ),
    ] {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(StoreError::Conflict("v8 runtime schema differs"));
        }
    }
    Ok(())
}

fn verify_current_scope_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    for (name, expected) in [
        (
            "runtime_sessions_open_scope_v19",
            CURRENT_SCOPE_SESSIONS_INDEX_V19,
        ),
        (
            "authority_resources_pod_v19",
            CURRENT_SCOPE_RESOURCES_INDEX_V19,
        ),
    ] {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(StoreError::Conflict("v19 current scope index differs"));
        }
    }
    Ok(())
}

fn verify_policy_fence_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='launch_policy_fences'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(LAUNCH_POLICY_FENCES_V20) {
        return Err(StoreError::Conflict(
            "v20 launch policy fence schema differs",
        ));
    }
    let epoch: Option<i64> = transaction
        .query_row(
            "SELECT value FROM metadata WHERE key='policy_fence_epoch'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if epoch.is_none_or(|value| value < 1) {
        return Err(StoreError::Conflict(
            "v20 policy fence epoch is absent or invalid",
        ));
    }
    Ok(())
}

fn verify_supersession_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    for (kind, name, expected) in [
        ("table", "rebind_supersession_attempts", REBIND_SUPERSESSION_ATTEMPTS_V21),
        ("table", "rebind_supersession_resources", REBIND_SUPERSESSION_RESOURCES_V21),
        ("index", "rebind_supersession_latest_v21", REBIND_SUPERSESSION_LATEST_INDEX_V21),
    ] {
        let actual: Option<String> = transaction.query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        ).optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(StoreError::Conflict("v21 supersession schema differs"));
        }
    }
    Ok(())
}

fn verify_codex_later_turn_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    for (kind, name, expected) in [
        ("table", "codex_later_turns", CODEX_LATER_TURNS_V22),
        (
            "index",
            "codex_later_turns_session_v22",
            CODEX_LATER_TURNS_SESSION_V22,
        ),
    ] {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(StoreError::Conflict("v22 later turn schema differs"));
        }
    }
    Ok(())
}

fn verify_codex_native_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    for (name, expected) in [
        ("codex_native_sources", CODEX_NATIVE_SOURCES_V23),
        ("codex_native_evidence", CODEX_NATIVE_EVIDENCE_V23),
        ("codex_native_conflicts", CODEX_NATIVE_CONFLICTS_V23),
    ] {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(StoreError::Conflict("v23 Codex native evidence schema differs"));
        }
    }
    Ok(())
}

fn verify_rebind_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let parent = manager_rebinds_v12();
    let child = manager_rebind_resources_v12();
    verify_rebind_tables(transaction, &parent, &child, "v12 rebind schema differs")
}

fn verify_rebind_tables(
    transaction: &rusqlite::Transaction<'_>,
    parent: &str,
    child: &str,
    error: &'static str,
) -> Result<(), StoreError> {
    for (name, expected) in [
        ("manager_rebinds", parent),
        ("manager_rebind_resources", child),
    ] {
        let actual: Option<String> = transaction
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(StoreError::Conflict(error));
        }
    }
    Ok(())
}

fn verify_manager_credential_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='manager_credential_claims'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(MANAGER_CREDENTIAL_CLAIMS_V10) {
        return Err(StoreError::Conflict(
            "v10 manager credential schema differs",
        ));
    }
    Ok(())
}

fn verify_manager_peer_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='manager_peer_bindings'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(MANAGER_PEER_BINDINGS_V11) {
        return Err(StoreError::Conflict("v11 manager peer schema differs"));
    }
    Ok(())
}

fn verify_prior_observation_schema(
    transaction: &rusqlite::Transaction<'_>,
) -> Result<(), StoreError> {
    let actual: Option<String> = transaction.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='manager_rebind_prior_observations'",
        [], |row| row.get(0),
    ).optional()?;
    if actual.as_deref() != Some(MANAGER_REBIND_PRIOR_OBSERVATIONS_V13) {
        return Err(StoreError::Conflict("v13 prior observation schema differs"));
    }
    Ok(())
}

fn verify_actor_verifier_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='actor_verifiers'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(ACTOR_VERIFIERS_V14) {
        return Err(StoreError::Conflict("v14 actor verifier schema differs"));
    }
    Ok(())
}

fn verify_owner_rotation_schema(transaction: &rusqlite::Transaction<'_>) -> Result<(), StoreError> {
    let actual: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_actor_rotations'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if actual.as_deref() != Some(OWNER_ACTOR_ROTATIONS_V15) {
        return Err(StoreError::Conflict("v15 owner rotation schema differs"));
    }
    Ok(())
}
