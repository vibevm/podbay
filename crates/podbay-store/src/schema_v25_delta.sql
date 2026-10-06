-- Additive schema-25 recovery facts. Migration inserts no recovery record.
CREATE TABLE external_death_pending (
  pending_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  recovery_key TEXT NOT NULL UNIQUE CHECK(length(recovery_key) BETWEEN 1 AND 256),
  store_lineage TEXT NOT NULL REFERENCES store_identity(lineage),
  scope_id TEXT NOT NULL CHECK(length(scope_id)>0),
  pod_id TEXT NOT NULL CHECK(length(pod_id)>0),
  pod_incarnation INTEGER NOT NULL CHECK(pod_incarnation>=1),
  launch_command_rowid INTEGER NOT NULL REFERENCES launch_bindings(command_rowid),
  activated_rebind_rowid INTEGER NOT NULL UNIQUE
    REFERENCES manager_rebinds(rebind_rowid),
  preparing_owner_epoch INTEGER NOT NULL CHECK(preparing_owner_epoch>=1),
  preparing_authority_revision INTEGER NOT NULL CHECK(preparing_authority_revision>=1),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64
    AND request_digest NOT GLOB '*[^0-9a-f]*'),
  FOREIGN KEY(scope_id,pod_id,pod_incarnation,launch_command_rowid)
    REFERENCES launch_slots(scope_id,pod_id,pod_incarnation,command_rowid),
  FOREIGN KEY(activated_rebind_rowid)
    REFERENCES manager_rebind_prior_observations(rebind_rowid),
  UNIQUE(scope_id,pod_id,pod_incarnation,recovery_key)
) STRICT;

CREATE TABLE external_death_final (
  final_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
  pending_rowid INTEGER NOT NULL UNIQUE
    REFERENCES external_death_pending(pending_rowid),
  proof_digest TEXT NOT NULL CHECK(length(proof_digest)=64
    AND proof_digest NOT GLOB '*[^0-9a-f]*'),
  native_outcome TEXT NOT NULL CHECK(native_outcome='uncertain')
) STRICT;

-- SQLite foreign keys bind the durable scalar rows above. Prepare/finalize
-- transactions must additionally prove that store_lineage is current, that
-- activated_rebind_rowid names an activated row for the exact launch subject,
-- and that the preparing epochs still equal current authority state.
