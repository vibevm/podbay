-- Canonical fresh schema for PodBay user_version 23. No historical rows are
-- copied or inferred. Keep exact DDL aligned with store.rs schema verifiers.
-- table metadata
CREATE TABLE metadata (
               key TEXT PRIMARY KEY, value INTEGER NOT NULL CHECK(value >= 0)
             ) STRICT;
-- table target_epochs
CREATE TABLE target_epochs (
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               epoch INTEGER NOT NULL CHECK(epoch >= 0),
               PRIMARY KEY(scope_id,target_id)
             ) STRICT;
-- table commands
CREATE TABLE commands (
               command_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
               command_id TEXT NOT NULL UNIQUE,
               principal TEXT NOT NULL, namespace TEXT NOT NULL, command_key TEXT NOT NULL,
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               digest_version TEXT NOT NULL, request_digest TEXT NOT NULL,
               canonical_request BLOB NOT NULL,
               owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
               event_sequence INTEGER, outbox_id INTEGER,
               UNIQUE(principal,namespace,command_key)
             ) STRICT;
-- table outbox
CREATE TABLE outbox (
               outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
               command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
               scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
               owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
               kind TEXT NOT NULL, payload BLOB NOT NULL,
               state TEXT NOT NULL CHECK(state IN ('prepared','claimed_uncertain','observed')),
               claim_key TEXT,
               claim_owner_epoch INTEGER
             , observation_key TEXT, observation_payload BLOB, observation_stage TEXT, observation_event_sequence INTEGER
                   REFERENCES events(sequence), effect_digest TEXT) STRICT;
-- table store_identity
CREATE TABLE store_identity (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               lineage TEXT NOT NULL UNIQUE
             ) STRICT;
-- table events
CREATE TABLE "events" (
                   sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                   event_id TEXT NOT NULL UNIQUE,
                   schema_version INTEGER NOT NULL CHECK(schema_version >= 1),
                   command_rowid INTEGER NOT NULL REFERENCES commands(command_rowid),
                   scope_id TEXT NOT NULL, target_id TEXT NOT NULL,
                   owner_epoch INTEGER NOT NULL, target_epoch INTEGER NOT NULL,
                   source_id TEXT NOT NULL, source_kind TEXT NOT NULL,
                   source_epoch INTEGER NOT NULL, source_sequence INTEGER NOT NULL,
                   source_digest TEXT NOT NULL,
                   source_order TEXT NOT NULL CHECK(source_order IN
                     ('contiguous','gap','out_of_order')),
                   source_order_reference INTEGER,
                   kind TEXT NOT NULL, payload BLOB NOT NULL,
                   recorded_at TEXT NOT NULL, occurred_at TEXT,
                   provenance TEXT NOT NULL, correlation_id TEXT, causation_id TEXT,
                   UNIQUE(scope_id,source_id,source_epoch,source_sequence)
                 ) STRICT;
-- table event_quarantine
CREATE TABLE event_quarantine (
               quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
               scope_id TEXT NOT NULL, source_id TEXT NOT NULL,
               source_epoch INTEGER NOT NULL, source_sequence INTEGER NOT NULL,
               existing_event_id TEXT NOT NULL, incoming_digest TEXT NOT NULL,
               incoming_payload BLOB NOT NULL, incoming_evidence BLOB NOT NULL,
               recorded_at TEXT NOT NULL,
               UNIQUE(scope_id,source_id,source_epoch,source_sequence,incoming_digest)
             ) STRICT;
-- table authority_pods
CREATE TABLE authority_pods (
                   pod_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                   incarnation INTEGER NOT NULL CHECK(incarnation >= 1)
                 ) STRICT;
-- table authority_resources
CREATE TABLE authority_resources (
                   resource_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                   pod_id TEXT NOT NULL REFERENCES authority_pods(pod_id),
                   pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation >= 1),
                   resource_epoch INTEGER NOT NULL CHECK(resource_epoch >= 1),
                   input_epoch INTEGER NOT NULL CHECK(input_epoch >= 1)
                 ) STRICT;
-- table authority_actors
CREATE TABLE authority_actors (
                   actor_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL,
                   role TEXT NOT NULL, origin TEXT NOT NULL,
                   parent_actor_id TEXT, pod_id TEXT REFERENCES authority_pods(pod_id),
                   pod_incarnation INTEGER, credential_generation INTEGER NOT NULL
                     CHECK(credential_generation >= 1),
                   platform TEXT NOT NULL, os_identity TEXT NOT NULL,
                   process_identity TEXT NOT NULL,
                   start_identity INTEGER NOT NULL CHECK(start_identity >= 1),
                   containment_identity TEXT NOT NULL
                 ) STRICT;
-- table authority_grants
CREATE TABLE authority_grants (
                   grant_id INTEGER PRIMARY KEY CHECK(grant_id >= 1),
                   scope_id TEXT NOT NULL,
                   actor_id TEXT NOT NULL REFERENCES authority_actors(actor_id),
                   credential_generation INTEGER NOT NULL CHECK(credential_generation >= 1),
                   mode TEXT NOT NULL,
                   remaining_depth INTEGER NOT NULL CHECK(remaining_depth BETWEEN 0 AND 255)
                 ) STRICT;
-- table authority_grant_rights
CREATE TABLE authority_grant_rights (
                   grant_id INTEGER NOT NULL REFERENCES authority_grants(grant_id)
                     ON DELETE CASCADE,
                   operation TEXT NOT NULL, target_kind TEXT NOT NULL,
                   target_id TEXT NOT NULL,
                   PRIMARY KEY(grant_id,operation,target_kind,target_id)
                 ) STRICT;
-- table launch_dispatch_outcomes
CREATE TABLE launch_dispatch_outcomes (
                   outbox_id INTEGER PRIMARY KEY REFERENCES outbox(outbox_id),
                   claim_key TEXT NOT NULL,
                   stage TEXT NOT NULL CHECK(stage IN
                     ('refused_before_effect','uncertain_after_possible_effect',
                      'host_accepted','port_settled')),
                   receipt_ref TEXT,
                   recorded_at TEXT NOT NULL
                 ) STRICT;
-- table launch_slots
CREATE TABLE launch_slots (
                   scope_id TEXT NOT NULL,pod_id TEXT NOT NULL,
                   pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
                   command_rowid INTEGER NOT NULL UNIQUE REFERENCES commands(command_rowid),
                   PRIMARY KEY(scope_id,pod_id,pod_incarnation)
                 ) STRICT;
-- table runtime_sessions
CREATE TABLE runtime_sessions (
  session_id TEXT PRIMARY KEY CHECK(length(session_id)>0),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  actor_id TEXT NOT NULL CHECK(length(actor_id)>0),
  revision INTEGER NOT NULL CHECK(revision>=0),
  state TEXT NOT NULL CHECK(length(state)>0),
  current_run_id TEXT CHECK(current_run_id IS NULL OR length(current_run_id)>0),
  UNIQUE(session_id,scope_id)
) STRICT;
-- table runtime_runs
CREATE TABLE runtime_runs (
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
) STRICT;
-- table launch_bindings
CREATE TABLE launch_bindings (
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
) STRICT;
-- table launch_resources
CREATE TABLE launch_resources (
  command_rowid INTEGER NOT NULL REFERENCES launch_bindings(command_rowid),
  resource_ordinal INTEGER NOT NULL CHECK(resource_ordinal>=0),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  resource_kind TEXT NOT NULL CHECK(length(resource_kind)>0),
  resource_epoch INTEGER NOT NULL CHECK(resource_epoch>=1),
  PRIMARY KEY(command_rowid,resource_ordinal),
  UNIQUE(command_rowid,resource_id)
) STRICT;
-- table manager_credential_claims
CREATE TABLE manager_credential_claims (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  owner_epoch INTEGER NOT NULL CHECK(owner_epoch>=1),
  credential_epoch INTEGER NOT NULL CHECK(credential_epoch>=1)
) STRICT;
-- table manager_peer_bindings
CREATE TABLE manager_peer_bindings (
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
) STRICT;
-- table manager_rebinds
CREATE TABLE manager_rebinds (
  rebind_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  expected_owner_epoch INTEGER NOT NULL CHECK(expected_owner_epoch>=1),
  next_owner_epoch INTEGER NOT NULL CHECK(next_owner_epoch>expected_owner_epoch),
  expected_credential_epoch INTEGER NOT NULL CHECK(expected_credential_epoch>=1),
  next_credential_epoch INTEGER NOT NULL
    CHECK(next_credential_epoch>expected_credential_epoch),
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
) STRICT;
-- table manager_rebind_resources
CREATE TABLE manager_rebind_resources (
  rebind_rowid INTEGER NOT NULL REFERENCES manager_rebinds(rebind_rowid),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  expected_input_epoch INTEGER NOT NULL CHECK(expected_input_epoch>=1),
  next_input_epoch INTEGER NOT NULL CHECK(next_input_epoch>expected_input_epoch),
  PRIMARY KEY(rebind_rowid,resource_id)
) STRICT;
-- table manager_rebind_prior_observations
CREATE TABLE manager_rebind_prior_observations (
  rebind_rowid INTEGER PRIMARY KEY REFERENCES manager_rebinds(rebind_rowid),
  schema_version TEXT NOT NULL CHECK(schema_version='podbay.prior-checkpoint/1'),
  checkpoint_digest TEXT NOT NULL CHECK(length(checkpoint_digest)=64
    AND checkpoint_digest NOT GLOB '*[^0-9a-f]*'),
  supervisor_pid INTEGER NOT NULL CHECK(supervisor_pid>=1),
  supervisor_start_ticks INTEGER NOT NULL CHECK(supervisor_start_ticks>=1),
  boot_id TEXT NOT NULL CHECK(length(boot_id) BETWEEN 1 AND 256),
  unit_name TEXT NOT NULL CHECK(length(unit_name) BETWEEN 1 AND 256),
  cgroup_path TEXT NOT NULL CHECK(length(cgroup_path) BETWEEN 1 AND 4096)
) STRICT;
-- table actor_verifiers
CREATE TABLE actor_verifiers (
  actor_id TEXT PRIMARY KEY REFERENCES authority_actors(actor_id),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  credential_generation INTEGER NOT NULL CHECK(credential_generation>=1),
  verifier_version TEXT NOT NULL CHECK(verifier_version='podbay.ed25519/1'),
  public_key BLOB NOT NULL CHECK(length(public_key)=32),
  binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32),
  revoked INTEGER NOT NULL CHECK(revoked IN (0,1))
) STRICT;
-- table owner_actor_rotations
CREATE TABLE owner_actor_rotations (
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
) STRICT;
-- table run_child_budgets
CREATE TABLE run_child_budgets (
  run_id TEXT NOT NULL PRIMARY KEY REFERENCES runtime_runs(run_id) CHECK(length(run_id)>0),
  max_children INTEGER NOT NULL DEFAULT 0 CHECK(max_children>=0 AND max_children<=4294967295),
  reserved_children INTEGER NOT NULL DEFAULT 0 CHECK(reserved_children>=0 AND reserved_children<=max_children)
) STRICT;
-- table native_writer_leases
CREATE TABLE native_writer_leases (
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
) STRICT;
-- table codex_bootstrap_sends
CREATE TABLE codex_bootstrap_sends (
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
) STRICT;
-- table launch_policy_fences
CREATE TABLE launch_policy_fences (
  command_rowid INTEGER NOT NULL PRIMARY KEY REFERENCES launch_bindings(command_rowid),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  policy_fence_epoch INTEGER NOT NULL CHECK(policy_fence_epoch>=1),
  admission_authority_revision INTEGER NOT NULL CHECK(admission_authority_revision>=1)
) STRICT;
-- table rebind_supersession_attempts
CREATE TABLE rebind_supersession_attempts (
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
) STRICT;
-- table rebind_supersession_resources
CREATE TABLE rebind_supersession_resources (
  supersession_rowid INTEGER NOT NULL REFERENCES rebind_supersession_attempts(supersession_rowid),
  resource_id TEXT NOT NULL CHECK(length(resource_id)>0),
  abandoned_input_epoch INTEGER NOT NULL CHECK(abandoned_input_epoch>=1),
  recovering_input_epoch INTEGER NOT NULL CHECK(recovering_input_epoch>abandoned_input_epoch),
  PRIMARY KEY(supersession_rowid,resource_id)
) STRICT;
-- table codex_later_turns
CREATE TABLE codex_later_turns (
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
) STRICT;
-- Private Codex native observations are independent of command/outbox rows.
-- The raw JSONL is never selected by generic event/history/snapshot queries.
-- table codex_native_sources
CREATE TABLE codex_native_sources (
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
) STRICT;
-- table codex_native_evidence
CREATE TABLE codex_native_evidence (
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
  raw_jsonl BLOB NOT NULL CHECK(length(raw_jsonl) BETWEEN 1 AND 262144),
  PRIMARY KEY(resource_id,source_sequence)
) STRICT;
-- table codex_native_conflicts
CREATE TABLE codex_native_conflicts (
  resource_id TEXT NOT NULL REFERENCES codex_native_sources(resource_id),
  source_sequence INTEGER NOT NULL CHECK(source_sequence>=1),
  incoming_digest TEXT NOT NULL CHECK(length(incoming_digest)=64),
  raw_jsonl BLOB NOT NULL CHECK(length(raw_jsonl) BETWEEN 1 AND 262144),
  PRIMARY KEY(resource_id,source_sequence,incoming_digest)
) STRICT;
-- index events_scope_sequence
CREATE INDEX events_scope_sequence ON events(scope_id,sequence);
-- index quarantine_scope_id
CREATE INDEX quarantine_scope_id
               ON event_quarantine(scope_id,quarantine_id);
-- index launch_slots_binding_identity
CREATE UNIQUE INDEX launch_slots_binding_identity
  ON launch_slots(scope_id,pod_id,pod_incarnation,command_rowid);
-- index runtime_sessions_open_scope_v19
CREATE INDEX runtime_sessions_open_scope_v19
  ON runtime_sessions(scope_id,session_id) WHERE state='open';
-- index authority_resources_pod_v19
CREATE INDEX authority_resources_pod_v19
  ON authority_resources(pod_id,resource_id);
-- index rebind_supersession_latest_v21
CREATE INDEX rebind_supersession_latest_v21
  ON rebind_supersession_attempts(abandoned_rebind_rowid,supersession_rowid DESC);
-- index codex_later_turns_session_v22
CREATE INDEX codex_later_turns_session_v22
  ON codex_later_turns(session_id,command_rowid);
INSERT INTO metadata(key,value) VALUES('authority_revision',0);
INSERT INTO metadata(key,value) VALUES('owner_epoch',0);
INSERT INTO metadata(key,value) VALUES('policy_fence_epoch',1);
INSERT INTO store_identity(singleton,lineage) VALUES(1,lower(hex(randomblob(16))));
