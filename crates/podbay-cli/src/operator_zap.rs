//! One installed Linux operator command for a fixed headless Zap service Pod.
//! The CLI is the trusted local manager. No caller supplies native launch
//! fields after the private policy has been loaded and pinned.

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use ed25519_compact::{KeyPair, Seed};
use podbay_core::{
    ActorId, Attempt, AttemptId, Epoch, LaunchBinding, Pod, PodId, Resource, ResourceId,
    ResourceKind, Role, Run, RunId, ScopeId, Session, SessionId, WorkKind,
};
use podbay_host::{
    AuthenticatedPeer, AuthenticatedProcessSubject, AuthenticatedTransport,
    BoundHostLaunchProposal, BoundLaunchPodRequest, CredentialGeneration, DurableAuthority,
    DurableAuthorityError, ExecutionMode, GuardSet, HostAction, HostError, HostRequest,
    LaunchSelection, ManagerEpoch, PodIncarnation, RebindCompletionStage, RegisteredLaunchProfile,
    TrustedDriverTemplate, TrustedInitialOwnerPolicy, TrustedLaunchProfileInput,
    TrustedNativeHostConfig, WorkspaceAccess, WorkspaceSelection,
};
use podbay_launch_linux::{
    LinuxLaunchPort, OperatorArtifactDigest, TrustedLinuxLaunchConfig, TrustedOperatorArtifact,
    TrustedOperatorProcessProfile,
};
use podbay_pod::{
    LinuxPeerEvidence, OPERATOR_PROCESS_CAPABILITY, OPERATOR_PROCESS_PROFILE_REF, PodClient,
    manifest_path_for_identity,
};
use podbay_store::{CommandLookupSelector, LaunchDispatchStage, StoreError};
use podbay_wire::ResourceDriver;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const POLICY_SCHEMA: &str = "podbay.operator-zap-policy/1";
const KEY_SCHEMA: &str = "podbay.operator-owner-key/1";
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPolicy {
    schema: String,
    state_directory: PathBuf,
    pod_executable: PathBuf,
    pod_executable_sha256: String,
    node_executable: PathBuf,
    node_executable_sha256: String,
    zap_root: PathBuf,
    zap_artifact_sha256: String,
    zap_state_directory: PathBuf,
    headless_config: Option<PathBuf>,
    headless_config_sha256: Option<String>,
    actor_id: String,
    scope_id: String,
    pod_id: String,
    session_id: String,
    run_id: String,
    attempt_id: String,
    resource_id: String,
    workspace_basis_ref: String,
    host_id: String,
    command_key: String,
    wall_seconds: u64,
}

struct Policy {
    raw: RawPolicy,
    policy_digest: String,
    actor: ActorId,
    scope: ScopeId,
    pod: PodId,
    session: SessionId,
    run: RunId,
    attempt: AttemptId,
    resource: ResourceId,
    pod_directory: PathBuf,
    database: PathBuf,
    arguments: Vec<String>,
    artifact: TrustedOperatorArtifact,
    artifact_receipt: OperatorArtifactDigest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyCustody {
    schema: String,
    actor_id: String,
    scope_id: String,
    policy_digest: String,
    generation: u64,
    seed_hex: String,
    public_key_hex: String,
}

struct SelfTransport {
    peer: AuthenticatedPeer,
    generation: CredentialGeneration,
}

impl AuthenticatedTransport for SelfTransport {
    fn verified_peer(&self) -> Result<AuthenticatedPeer, HostError> {
        let process = current_process().map_err(|_| HostError::Unauthenticated)?;
        let current =
            AuthenticatedPeer::owner_cli_from_authenticated_transport(process, self.generation);
        if current == self.peer {
            Ok(current)
        } else {
            Err(HostError::Unauthenticated)
        }
    }
}

pub(crate) fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("podbay operator zap: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args_os().collect::<Vec<_>>();
    if args.len() == 6
        && args[1] == "operator"
        && args[2] == "zap"
        && args[3] == "hash"
        && args[4] == "--root"
    {
        let root = PathBuf::from(&args[5]);
        let proof = TrustedOperatorArtifact::inspect_tree(&root)
            .map_err(|error| format!("Zap artifact hash refused: {error}"))?;
        println!(
            "{}",
            serde_json::json!({
                "protocol": "podbay.operator-artifact/1",
                "root": root,
                "sha256": proof.sha256,
                "entries": proof.entries,
                "bytes": proof.bytes,
                "hashMillis": proof.elapsed.as_millis(),
            })
        );
        return Ok(());
    }
    if args.len() != 6
        || args[1] != "operator"
        || args[2] != "zap"
        || args[3] != "launch"
        || args[4] != "--policy"
    {
        return Err("usage: podbay operator zap hash --root ABSOLUTE_PRIVATE_DIRECTORY | podbay operator zap launch --policy ABSOLUTE_PRIVATE_JSON".into());
    }
    let policy_path = PathBuf::from(&args[5]);
    let policy = Policy::load(&policy_path)?;
    launch(policy)
}

impl Policy {
    fn load(path: &Path) -> Result<Self, String> {
        let peer = LinuxPeerEvidence::for_current_process()
            .map_err(|error| format!("operator process evidence unavailable: {error}"))?;
        let state_directory = path.parent().ok_or("policy has no parent directory")?;
        private_directory(state_directory, peer.uid())?;
        let bytes = private_file(path, state_directory, peer.uid(), MAX_POLICY_BYTES)?;
        let policy_digest = hex_digest(&bytes);
        let raw: RawPolicy = serde_json::from_slice(&bytes)
            .map_err(|_| "operator policy JSON is invalid".to_owned())?;
        if raw.schema != POLICY_SCHEMA
            || raw.state_directory != state_directory
            || path
                .file_name()
                .is_none_or(|name| name != "operator-zap-policy.json")
            || !(30..=3600).contains(&raw.wall_seconds)
            || !valid_token(&raw.workspace_basis_ref)
            || !valid_token(&raw.host_id)
            || !valid_token(&raw.command_key)
            || raw.headless_config.is_some() != raw.headless_config_sha256.is_some()
        {
            return Err("operator policy shape or fixed budget differs".into());
        }
        let actor =
            ActorId::try_from(raw.actor_id.as_str()).map_err(|_| "operator actor ID is invalid")?;
        let scope =
            ScopeId::try_from(raw.scope_id.as_str()).map_err(|_| "operator scope ID is invalid")?;
        let pod = PodId::try_from(raw.pod_id.as_str()).map_err(|_| "operator Pod ID is invalid")?;
        let session = SessionId::try_from(raw.session_id.as_str())
            .map_err(|_| "operator Session ID is invalid")?;
        let run = RunId::try_from(raw.run_id.as_str()).map_err(|_| "operator Run ID is invalid")?;
        let attempt = AttemptId::try_from(raw.attempt_id.as_str())
            .map_err(|_| "operator Attempt ID is invalid")?;
        let resource = ResourceId::try_from(raw.resource_id.as_str())
            .map_err(|_| "operator Resource ID is invalid")?;
        private_directory(&raw.zap_state_directory, peer.uid())?;
        if !canonical_disjoint(state_directory, &raw.zap_state_directory)
            || !canonical_disjoint(&raw.zap_root, state_directory)
            || !canonical_disjoint(&raw.zap_root, &raw.zap_state_directory)
        {
            return Err("outer PodBay state, Zap artifact and Zap state must be disjoint".into());
        }
        checked_executable(&raw.pod_executable, &raw.pod_executable_sha256)?;
        checked_executable(&raw.node_executable, &raw.node_executable_sha256)?;
        if let (Some(config), Some(digest)) = (&raw.headless_config, &raw.headless_config_sha256) {
            if config.parent() != Some(raw.zap_state_directory.as_path())
                || !valid_digest(digest)
                || hex_digest(&private_file(
                    config,
                    &raw.zap_state_directory,
                    peer.uid(),
                    MAX_CONFIG_BYTES,
                )?) != *digest
            {
                return Err("private Zap headless config differs from policy".into());
            }
        }
        let (artifact, artifact_receipt) =
            TrustedOperatorArtifact::from_trusted_policy_with_receipt(
                raw.zap_root.clone(),
                raw.zap_artifact_sha256.clone(),
            )
            .map_err(|error| format!("Zap artifact proof failed: {error}"))?;
        let pod_directory = state_directory.join("pods");
        create_or_check_private_directory(&pod_directory, peer.uid())?;
        let socket =
            manifest_path_for_identity(&pod_directory, &pod, &attempt, Epoch::new(1).unwrap())
                .with_extension("sock");
        if socket.as_os_str().as_bytes().len() > 100 {
            return Err("operator Pod socket path exceeds Linux bound".into());
        }
        let database = state_directory.join("podbay.sqlite");
        let mut arguments = vec![
            "--experimental-strip-types".into(),
            "src/zap-server.ts".into(),
            "--state-dir".into(),
            raw.zap_state_directory.to_string_lossy().into_owned(),
        ];
        if let Some(config) = &raw.headless_config {
            arguments.push("--podbay-config".into());
            arguments.push(config.to_string_lossy().into_owned());
        }
        Ok(Self {
            raw,
            policy_digest,
            actor,
            scope,
            pod,
            session,
            run,
            attempt,
            resource,
            pod_directory,
            database,
            arguments,
            artifact,
            artifact_receipt,
        })
    }

    fn recheck_config(&self) -> Result<(), String> {
        if let (Some(config), Some(digest)) =
            (&self.raw.headless_config, &self.raw.headless_config_sha256)
        {
            let uid = LinuxPeerEvidence::for_current_process()
                .map_err(|_| "operator identity changed")?
                .uid();
            if hex_digest(&private_file(
                config,
                &self.raw.zap_state_directory,
                uid,
                MAX_CONFIG_BYTES,
            )?) != *digest
            {
                return Err("private Zap headless config changed before launch".into());
            }
        }
        Ok(())
    }
}

fn valid_token(value: &str) -> bool {
    (3..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_disjoint(left: &Path, right: &Path) -> bool {
    left.is_absolute()
        && right.is_absolute()
        && fs::canonicalize(left).ok().as_deref() == Some(left)
        && fs::canonicalize(right).ok().as_deref() == Some(right)
        && !left.starts_with(right)
        && !right.starts_with(left)
}

fn private_directory(path: &Path, uid: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("private directory unavailable: {error}"))?;
    if !path.is_absolute()
        || fs::canonicalize(path).ok().as_deref() != Some(path)
        || !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err("private directory is not canonical, owned and mode 0700".into());
    }
    Ok(())
}

fn create_or_check_private_directory(path: &Path, uid: u32) -> Result<(), String> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("private pod directory permissions failed: {error}"))?;
            File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(|error| format!("private pod directory sync failed: {error}"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("private pod directory creation failed: {error}")),
    }
    private_directory(path, uid)
}

fn private_file(path: &Path, directory: &Path, uid: u32, max: u64) -> Result<Vec<u8>, String> {
    if !path.is_absolute()
        || path.parent() != Some(directory)
        || fs::canonicalize(path).ok().as_deref() != Some(path)
    {
        return Err("private file path is not canonical inside its directory".into());
    }
    private_directory(directory, uid)?;
    let before =
        fs::symlink_metadata(path).map_err(|error| format!("private file unavailable: {error}"))?;
    if !before.is_file()
        || before.uid() != uid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
        || !(1..=max).contains(&before.len())
    {
        return Err("private file ownership, mode or size differs".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("private file open failed: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("private file stat failed: {error}"))?;
    if (
        opened.dev(),
        opened.ino(),
        opened.len(),
        opened.mtime(),
        opened.mtime_nsec(),
    ) != (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
    ) {
        return Err("private file changed before read".into());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("private file read failed: {error}"))?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("private file changed after read: {error}"))?;
    if bytes.len() as u64 != before.len()
        || (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
        ) != (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
        )
    {
        return Err("private file changed during read".into());
    }
    Ok(bytes)
}

fn checked_executable(path: &Path, digest: &str) -> Result<(), String> {
    if !valid_digest(digest)
        || !path.is_absolute()
        || fs::canonicalize(path).ok().as_deref() != Some(path)
    {
        return Err("trusted executable path or digest is invalid".into());
    }
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("trusted executable unavailable: {error}"))?;
    if !before.is_file() || before.mode() & 0o111 == 0 {
        return Err("trusted executable is not a regular executable".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("trusted executable open failed: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("trusted executable stat failed: {error}"))?;
    if (opened.dev(), opened.ino(), opened.len()) != (before.dev(), before.ino(), before.len()) {
        return Err("trusted executable changed before read".into());
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 16_384];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|error| format!("trusted executable read failed: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("trusted executable changed after read: {error}"))?;
    if (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
    ) != (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
    ) || hex(&hash.finalize()) != digest
    {
        return Err("trusted executable hash or identity differs".into());
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<[u8; 32], String> {
    if !valid_digest(value) {
        return Err("owner key encoding is invalid".into());
    }
    let mut result = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
            .map_err(|_| "owner key encoding is invalid")?;
    }
    Ok(result)
}

fn key_path(policy: &Policy, generation: u64) -> PathBuf {
    policy
        .raw
        .state_directory
        .join(format!("owner-key.{generation}.json"))
}

fn owner_key(policy: &Policy, generation: u64, create: bool) -> Result<KeyPair, String> {
    let path = key_path(policy, generation);
    if !path.exists() {
        if !create {
            return Err("recorded owner key custody is missing".into());
        }
        let mut seed = [0u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut seed))
            .map_err(|error| format!("owner key entropy unavailable: {error}"))?;
        let pair = KeyPair::from_seed(Seed::new(seed));
        let custody = KeyCustody {
            schema: KEY_SCHEMA.into(),
            actor_id: policy.actor.as_str().into(),
            scope_id: policy.scope.as_str().into(),
            policy_digest: policy.policy_digest.clone(),
            generation,
            seed_hex: hex(&seed),
            public_key_hex: hex(pair.pk.as_ref()),
        };
        let bytes =
            serde_json::to_vec(&custody).map_err(|_| "owner key custody encoding failed")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("owner key custody creation failed: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("owner key custody sync failed: {error}"))?;
        File::open(&policy.raw.state_directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|error| format!("owner key directory sync failed: {error}"))?;
    }
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator process identity changed")?
        .uid();
    let bytes = private_file(&path, &policy.raw.state_directory, uid, 4096)?;
    let custody: KeyCustody =
        serde_json::from_slice(&bytes).map_err(|_| "owner key custody is malformed".to_owned())?;
    if custody.schema != KEY_SCHEMA
        || custody.actor_id != policy.actor.as_str()
        || custody.scope_id != policy.scope.as_str()
        || custody.policy_digest != policy.policy_digest
        || custody.generation != generation
    {
        return Err("owner key custody differs from policy".into());
    }
    let seed = decode_hex(&custody.seed_hex)?;
    let pair = KeyPair::from_seed(Seed::new(seed));
    if hex(pair.pk.as_ref()) != custody.public_key_hex {
        return Err("owner key custody public key differs".into());
    }
    Ok(pair)
}

fn current_process() -> Result<AuthenticatedProcessSubject, String> {
    let peer = LinuxPeerEvidence::for_current_process()
        .map_err(|error| format!("operator process evidence unavailable: {error}"))?;
    let pid = u32::try_from(peer.pid()).map_err(|_| "operator PID is invalid")?;
    AuthenticatedProcessSubject::linux_from_verified_peercred_cgroup(
        peer.uid(),
        pid,
        peer.start_ticks(),
        peer.cgroup(),
    )
    .map_err(|_| "operator process subject is invalid".into())
}

fn launch(policy: Policy) -> Result<(), String> {
    let port_config = TrustedLinuxLaunchConfig::from_trusted_policy(
        policy.raw.pod_executable.clone(),
        policy.raw.pod_executable_sha256.clone(),
        policy.pod_directory.clone(),
    )
    .map_err(|error| format!("trusted Pod executable refused: {error}"))?;
    let mut port = LinuxLaunchPort::new(port_config);
    let process_profile = TrustedOperatorProcessProfile::from_trusted_policy(
        1,
        policy.raw.node_executable.clone(),
        policy.raw.node_executable_sha256.clone(),
        policy.raw.zap_root.clone(),
        policy.arguments.clone(),
        policy.raw.zap_state_directory.clone(),
        policy.raw.wall_seconds,
    )
    .and_then(|profile| profile.with_verified_artifact(policy.artifact.clone()))
    .map_err(|error| format!("trusted Zap process profile refused: {error}"))?;
    port.register_operator_process_from_trusted_policy(process_profile)
        .map_err(|error| format!("Zap process registration refused: {error}"))?;
    let mut host = DurableAuthority::open(&policy.database, port)
        .map_err(|error| format!("outer PodBay store could not open: {error:?}"))?;
    let owner_policy = TrustedInitialOwnerPolicy::for_operator_pod(
        policy.actor.clone(),
        policy.scope.clone(),
        policy.pod.clone(),
    )
    .map_err(|error| format!("operator owner policy refused: {error:?}"))?;
    let observed = current_process()?;
    let recorded_actors = &host.recorded_snapshot().actors;
    let generation = if recorded_actors.is_empty() {
        let key = owner_key(&policy, 1, true)?;
        let pending = host
            .begin_initial_owner_enrollment(owner_policy.clone(), observed.clone(), *key.pk)
            .map_err(|error| format!("operator owner enrollment refused: {error:?}"))?;
        let signature = key.sk.sign(pending.challenge_bytes(), None);
        let proof = pending
            .verify(signature.as_ref())
            .map_err(|error| format!("operator owner signature refused: {error:?}"))?;
        host.commit_initial_owner_enrollment(proof, &current_process()?)
            .map_err(|error| format!("operator owner enrollment commit failed: {error:?}"))?;
        1
    } else {
        if recorded_actors.len() != 1
            || recorded_actors[0].actor_id != policy.actor.as_str()
            || recorded_actors[0].scope_id != policy.scope.as_str()
            || recorded_actors[0].origin != "owner_cli"
        {
            return Err("outer store owner differs from the exact operator policy".into());
        }
        let prior_generation = recorded_actors[0].credential_generation;
        let next_generation = prior_generation
            .checked_add(1)
            .ok_or("operator credential generation exhausted")?;
        let old_key = owner_key(&policy, prior_generation, false)?;
        let next_key = owner_key(&policy, next_generation, true)?;
        let pending = host
            .begin_owner_recovery(&owner_policy, observed.clone(), *old_key.pk, *next_key.pk)
            .map_err(|error| format!("operator owner recovery refused: {error:?}"))?;
        let old_signature = old_key.sk.sign(pending.challenge_bytes(), None);
        let next_signature = next_key.sk.sign(pending.challenge_bytes(), None);
        let proof = pending
            .verify(old_signature.as_ref(), next_signature.as_ref())
            .map_err(|error| format!("operator dual-key proof refused: {error:?}"))?;
        let receipt = host
            .commit_owner_recovery(proof, &current_process()?)
            .map_err(|error| format!("operator owner recovery commit failed: {error:?}"))?;
        if receipt.next_generation != next_generation {
            return Err("operator owner recovery generation differs".into());
        }
        next_generation
    };
    let generation = CredentialGeneration::new(generation)
        .map_err(|_| "operator credential generation is invalid")?;
    let transport = SelfTransport {
        peer: AuthenticatedPeer::owner_cli_from_authenticated_transport(observed, generation),
        generation,
    };
    let grant = host
        .current_owner_grant_from_trusted_policy(&owner_policy)
        .map_err(|error| format!("exact operator Pod grant unavailable: {error:?}"))?;
    register_operator_policy(&mut host, &policy)?;
    let selector = CommandLookupSelector::Key {
        key: policy.raw.command_key.clone(),
    };
    let existing = match host.lookup_command(&transport, &policy.scope, &selector) {
        Ok(inspection) => Some(inspection),
        Err(DurableAuthorityError::Store(StoreError::NotFound)) => None,
        Err(error) => return Err(format!("operator command readback failed: {error:?}")),
    };
    let request = bound_request(&policy, grant, host.owner_epoch(), generation)?;
    let duplicate = existing.is_some();
    match existing.and_then(|inspection| inspection.launch_dispatch_status) {
        None => {
            let prepared = host
                .admit_bound_operator_process(&transport, request.clone())
                .map_err(|error| format!("operator root admission failed: {error:?}"))?;
            if prepared.status.stage != LaunchDispatchStage::Prepared {
                return Err("new operator root is not Prepared; inspect original key".into());
            }
            policy.recheck_config()?;
            let accepted = host
                .resume_prepared_bound_operator_process(&transport, request.clone())
                .map_err(|error| {
                    format!("operator launch uncertain; inspect original key: {error:?}")
                })?;
            if accepted.status.stage != LaunchDispatchStage::HostAccepted {
                return Err(format!(
                    "operator launch is {:?}, not HostAccepted; inspect original key",
                    accepted.status.stage
                ));
            }
        }
        Some(status) if status.stage == LaunchDispatchStage::Prepared => {
            policy.recheck_config()?;
            let accepted = host
                .resume_prepared_bound_operator_process(&transport, request.clone())
                .map_err(|error| {
                    format!("prepared operator launch uncertain; inspect original key: {error:?}")
                })?;
            if accepted.status.stage != LaunchDispatchStage::HostAccepted {
                return Err("prepared operator launch lacks HostAccepted proof".into());
            }
        }
        Some(status)
            if status.stage == LaunchDispatchStage::HostAccepted
                || status.stage == LaunchDispatchStage::PortSettled =>
        {
            let key = format!("rebind.operator.owner.{}", host.owner_epoch().get());
            host.prepare_current_operator_process_rebind(&policy.scope, &policy.pod, &key)
                .map_err(|error| {
                    format!("existing Zap Pod rebind preparation failed: {error:?}")
                })?;
            let active = host
                .complete_current_operator_process_rebind(&policy.scope, &policy.pod, &key)
                .map_err(|error| format!("existing Zap Pod rebind failed: {error:?}"))?;
            if active.stage != RebindCompletionStage::PodActive {
                return Err(format!(
                    "existing Zap Pod is not Active: {:?}",
                    active.stage
                ));
            }
        }
        Some(status) => {
            return Err(format!(
                "operator command is {:?}; refusing a second OS launch; inspect original key",
                status.stage,
            ));
        }
    }
    let inspected = host
        .lookup_command(&transport, &policy.scope, &selector)
        .map_err(|error| format!("original operator receipt unavailable: {error:?}"))?;
    if inspected
        .launch_dispatch_status
        .as_ref()
        .is_none_or(|status| {
            status.stage != LaunchDispatchStage::HostAccepted
                && status.stage != LaunchDispatchStage::PortSettled
        })
    {
        return Err("operator launch receipt is not HostAccepted".into());
    }
    let reviewed = host
        .inspect_committed_operator_process(&policy.scope, &policy.pod)
        .map_err(|error| format!("current Zap Pod proof unavailable: {error:?}"))?;
    if reviewed.committed_record().receipt != inspected.receipt
        || reviewed.committed_record().session_id != policy.session.as_str()
        || reviewed.committed_record().run_id != policy.run.as_str()
        || reviewed.committed_record().attempt_id != policy.attempt.as_str()
        || reviewed.committed_record().resources.len() != 1
        || reviewed.committed_record().resources[0].id != policy.resource.as_str()
    {
        return Err("current Zap Pod differs from exact operator root".into());
    }
    let manifest = manifest_path_for_identity(
        &policy.pod_directory,
        &policy.pod,
        &policy.attempt,
        Epoch::new(1).unwrap(),
    );
    let client = PodClient::connect(&manifest)
        .map_err(|error| format!("current Zap Pod connection failed: {error}"))?;
    let status = client
        .attested_status()
        .map_err(|error| format!("current Zap Pod status failed: {error}"))?;
    if !status.child_running
        || status.pod_id != policy.pod.as_str()
        || status.bound.as_ref().is_none_or(|bound| {
            bound.capability != OPERATOR_PROCESS_CAPABILITY
                || bound.resource_id != policy.resource.as_str()
        })
    {
        return Err("current Zap Pod attestation differs".into());
    }
    let output = serde_json::json!({
        "protocol": "podbay.operator-zap/1",
        "commandKey": policy.raw.command_key,
        "commandId": inspected.receipt.command_id,
        "duplicate": duplicate,
        "scopeId": policy.scope.as_str(),
        "podId": policy.pod.as_str(),
        "supervisorPid": status.supervisor_pid,
        "supervisorStartTicks": status.supervisor_start_ticks,
        "childPid": status.child_pid,
        "childStartTicks": status.child_start_ticks,
        "artifactEntries": policy.artifact_receipt.entries,
        "artifactBytes": policy.artifact_receipt.bytes,
        "artifactHashMillis": policy.artifact_receipt.elapsed.as_millis(),
        "wallSeconds": policy.raw.wall_seconds,
    });
    println!("{output}");
    Ok(())
}

fn register_operator_policy(
    host: &mut DurableAuthority<LinuxLaunchPort>,
    policy: &Policy,
) -> Result<(), String> {
    let profile = RegisteredLaunchProfile::from_trusted_policy(TrustedLaunchProfileInput {
        profile_ref: OPERATOR_PROCESS_PROFILE_REF.into(),
        profile_generation: 1,
        executable: policy.raw.node_executable.to_string_lossy().into_owned(),
        binary_generation: format!("sha256:{}", policy.raw.node_executable_sha256),
        executable_sha256: policy.raw.node_executable_sha256.clone(),
        workspace_root: policy.raw.zap_root.clone(),
        resource_layout: vec![TrustedDriverTemplate {
            kind: ResourceKind::Auxiliary,
            driver: ResourceDriver::Auxiliary {
                driver_ref: "process.exec".into(),
            },
        }],
        execution_mode: ExecutionMode::LinuxCooperative,
        fixed_arguments: policy.arguments.clone(),
        permitted_extra_arguments: BTreeSet::new(),
        default_model: "none".into(),
        allowed_models: BTreeSet::from(["none".into()]),
        default_effort: "none".into(),
        allowed_efforts: BTreeSet::from(["none".into()]),
        workspace_scope: policy.scope.clone(),
        workspace_basis_ref: policy.raw.workspace_basis_ref.clone(),
        allowed_cwd_prefix: ".".into(),
        allow_write: true,
        allowed_tool_bundle_refs: BTreeSet::new(),
        environment_refs: vec![],
        credential_refs: vec![],
        max_wall_seconds: policy.raw.wall_seconds,
        max_children: 0,
        allow_fallback: false,
    })
    .map_err(|error| format!("operator launch profile refused: {error:?}"))?;
    host.register_launch_profile_from_trusted_policy(profile)
        .map_err(|error| format!("operator launch profile registration failed: {error:?}"))?;
    host.register_native_host_from_trusted_policy(
        TrustedNativeHostConfig::for_compiled_backend(policy.raw.host_id.clone())
            .and_then(|host| host.with_auxiliary_driver("process.exec".into()))
            .map_err(|error| format!("operator native host refused: {error:?}"))?,
    )
    .map_err(|error| format!("operator native host registration failed: {error:?}"))?;
    Ok(())
}

fn bound_request(
    policy: &Policy,
    grant: podbay_host::GrantId,
    manager_epoch: ManagerEpoch,
    generation: CredentialGeneration,
) -> Result<BoundLaunchPodRequest, String> {
    let mut session = Session::new(
        policy.session.clone(),
        policy.actor.clone(),
        policy.scope.clone(),
    );
    let run = Run::new(
        policy.run.clone(),
        &session,
        Role::Coordinator,
        WorkKind::Service,
        None,
    );
    session
        .bind_run(session.revision(), &run)
        .map_err(|_| "operator Session/Run association failed")?;
    let mut attempt = Attempt::new(
        policy.attempt.clone(),
        run.id().clone(),
        1,
        Epoch::new(1).unwrap(),
    )
    .map_err(|_| "operator first Attempt is invalid")?;
    let mut pod = Pod::new(
        policy.pod.clone(),
        attempt.id().clone(),
        Epoch::new(1).unwrap(),
    );
    attempt
        .attach_pod(attempt.revision(), &pod)
        .map_err(|_| "operator Attempt/Pod association failed")?;
    let resource = Resource::new(
        policy.resource.clone(),
        pod.id().clone(),
        ResourceKind::Auxiliary,
        Epoch::new(1).unwrap(),
    );
    pod.attach_resource(pod.revision(), &resource)
        .map_err(|_| "operator Pod/Resource association failed")?;
    let binding = LaunchBinding::plan_first_root(&session, &run, &attempt, &pod, &[resource])
        .map_err(|_| "operator root plan is invalid")?
        .identity()
        .clone();
    let mut canonical_request = b"podbay.operator-zap/1\0".to_vec();
    canonical_request.extend_from_slice(policy.policy_digest.as_bytes());
    Ok(BoundLaunchPodRequest {
        host_request: HostRequest {
            scope_id: policy.scope.clone(),
            grant_id: grant,
            guards: GuardSet {
                manager_epoch,
                pod_incarnation: PodIncarnation::new(1).unwrap(),
                resource_epoch: None,
                credential_generation: generation,
            },
            command_key: policy.raw.command_key.clone(),
            correlation_id: format!("correlation.operator.zap.{}", &policy.policy_digest[..24]),
            deadline: Instant::now() + Duration::from_secs(45),
            action: HostAction::LaunchPod {
                pod_id: policy.pod.clone(),
                role: Role::Coordinator,
                credential: None,
            },
        },
        canonical_request,
        proposal: Some(BoundHostLaunchProposal {
            session,
            run,
            binding,
            selection: LaunchSelection {
                profile_ref: OPERATOR_PROCESS_PROFILE_REF.into(),
                profile_generation: 1,
                model_id: None,
                reasoning_effort: None,
                fallback_approved: false,
                workspace: WorkspaceSelection {
                    scope_id: policy.scope.clone(),
                    basis_ref: policy.raw.workspace_basis_ref.clone(),
                    relative_cwd: ".".into(),
                    access: WorkspaceAccess::ReadWrite,
                },
                arguments: vec![],
                tool_bundle_refs: vec![],
                authority_ref: format!("grant.{}", grant.get()),
                wall_seconds: policy.raw.wall_seconds,
                max_children: 0,
                parent_run_id: None,
            },
        }),
    })
}
