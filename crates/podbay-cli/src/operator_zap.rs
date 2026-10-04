//! One installed Linux operator command for a fixed headless Zap service Pod.
//! The CLI is the trusted local manager. No caller supplies native launch
//! fields after the private policy has been loaded and pinned.

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
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
    PodManifest, manifest_path_for_identity,
};
use podbay_store::{CommandLookupSelector, LaunchDispatchStage, StoreError};
use podbay_wire::{LifetimeLimit, ResourceDriver};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const POLICY_SCHEMA: &str = "podbay.operator-zap-policy/1";
const KEY_SCHEMA: &str = "podbay.operator-owner-key/1";
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const STOP_INTENT_SCHEMA: &str = "podbay.operator-zap-stop-intent/1";
const STOP_TERMINAL_SCHEMA: &str = "podbay.operator-zap-stop-terminal/1";

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
    lifetime: LifetimeLimit,
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopIntent {
    schema: String,
    policy_digest: String,
    stop_key: String,
    actor_id: String,
    scope_id: String,
    pod_id: String,
    launch_command_id: String,
    manifest_digest: String,
    unit_name: String,
    socket_dev: u64,
    socket_ino: u64,
    supervisor_pid: u32,
    supervisor_birth: u64,
    child_pid: u32,
    child_birth: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopTerminal {
    schema: String,
    policy_digest: String,
    stop_key: String,
    launch_command_id: String,
    intent_digest: String,
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
        || (args[3] != "launch" && args[3] != "stop")
        || args[4] != "--policy"
    {
        return Err("usage: podbay operator zap hash --root ABSOLUTE_PRIVATE_DIRECTORY | podbay operator zap launch|stop --policy ABSOLUTE_PRIVATE_JSON".into());
    }
    let policy_path = PathBuf::from(&args[5]);
    let policy = Policy::load(&policy_path)?;
    if args[3] == "stop" {
        stop(policy)
    } else {
        launch(policy)
    }
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
            || !matches!(raw.lifetime,
                LifetimeLimit::UntilStopped | LifetimeLimit::Finite { seconds: 30..=3600 })
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
    repair_private_publication(&path, &policy.raw.state_directory)?;
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
        write_private_once(&path, &policy.raw.state_directory, &bytes)?;
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

fn stop_key(policy: &Policy) -> String {
    format!("stop.operator.{}", &policy.policy_digest[..24])
}

fn stop_intent_path(policy: &Policy) -> PathBuf {
    policy
        .raw
        .state_directory
        .join("operator-zap-stop-intent.json")
}

fn stop_terminal_path(policy: &Policy) -> PathBuf {
    policy
        .raw
        .state_directory
        .join("operator-zap-stop-terminal.json")
}

fn operator_manifest_path(policy: &Policy) -> PathBuf {
    manifest_path_for_identity(
        &policy.pod_directory,
        &policy.pod,
        &policy.attempt,
        Epoch::new(1).unwrap(),
    )
}

fn pending_publication_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("private publication filename is invalid")?;
    Ok(path.with_file_name(format!(".{name}.pending")))
}

fn publication_metadata(path: &Path, uid: u32) -> Result<Option<fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o600 {
                return Err("private publication file identity differs".into());
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("private publication stat failed: {error}")),
    }
}

/// A temp-only crash preceded publication and therefore any signed/effectful
/// step. A two-link final/temp pair is the post-link, pre-unlink crash shape.
/// Every other shape fails closed rather than replacing a possible intent.
fn repair_private_publication(path: &Path, directory: &Path) -> Result<(), String> {
    if path.parent() != Some(directory) {
        return Err("private publication directory differs".into());
    }
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator identity changed")?
        .uid();
    private_directory(directory, uid)?;
    let pending = pending_publication_path(path)?;
    let final_meta = publication_metadata(path, uid)?;
    let pending_meta = publication_metadata(&pending, uid)?;
    match (final_meta, pending_meta) {
        (None, None) => Ok(()),
        (None, Some(temp)) if temp.nlink() == 1 => {
            fs::remove_file(&pending)
                .map_err(|error| format!("prepublication temp removal failed: {error}"))?;
            File::open(directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| format!("prepublication directory sync failed: {error}"))
        }
        (Some(final_meta), Some(temp))
            if final_meta.nlink() == 2
                && temp.nlink() == 2
                && (final_meta.dev(), final_meta.ino()) == (temp.dev(), temp.ino()) =>
        {
            fs::remove_file(&pending)
                .map_err(|error| format!("published temp removal failed: {error}"))?;
            File::open(directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| format!("published directory sync failed: {error}"))?;
            let after =
                publication_metadata(path, uid)?.ok_or("published private file vanished")?;
            if after.nlink() != 1
                || (after.dev(), after.ino()) != (final_meta.dev(), final_meta.ino())
            {
                return Err("published private file changed during repair".into());
            }
            Ok(())
        }
        (Some(final_meta), None) if final_meta.nlink() == 1 => Ok(()),
        _ => Err("private publication links are ambiguous".into()),
    }
}

fn write_private_once(path: &Path, directory: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.parent() != Some(directory) || bytes.is_empty() || bytes.len() > 16_384 {
        return Err("private operator receipt path or size differs".into());
    }
    repair_private_publication(path, directory)?;
    if path.exists() {
        return Err("private operator receipt already exists".into());
    }
    let pending = pending_publication_path(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pending)
        .map_err(|error| format!("private operator temp creation failed: {error}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("private operator temp sync failed: {error}"))?;
    drop(file);
    fs::hard_link(&pending, path)
        .map_err(|error| format!("private operator publication failed: {error}"))?;
    fs::remove_file(&pending)
        .map_err(|error| format!("private operator temp unlink failed: {error}"))?;
    File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| format!("private operator directory sync failed: {error}"))?;
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator identity changed")?
        .uid();
    if private_file(path, directory, uid, 16_384)? != bytes {
        return Err("published private operator receipt changed".into());
    }
    Ok(())
}

fn checked_stop_intent(
    policy: &Policy,
    original_command_id: &str,
) -> Result<Option<(StopIntent, String)>, String> {
    let path = stop_intent_path(policy);
    repair_private_publication(&path, &policy.raw.state_directory)?;
    if !path.exists() {
        return Ok(None);
    }
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator identity changed")?
        .uid();
    let bytes = private_file(&path, &policy.raw.state_directory, uid, 16_384)?;
    let intent: StopIntent = serde_json::from_slice(&bytes)
        .map_err(|_| "operator stop intent is malformed".to_owned())?;
    let manifest = operator_manifest_path(policy);
    let stem = manifest
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or("operator manifest slot is invalid")?;
    if intent.schema != STOP_INTENT_SCHEMA
        || intent.policy_digest != policy.policy_digest
        || intent.stop_key != stop_key(policy)
        || intent.actor_id != policy.actor.as_str()
        || intent.scope_id != policy.scope.as_str()
        || intent.pod_id != policy.pod.as_str()
        || intent.launch_command_id != original_command_id
        || intent.unit_name != format!("podbay-pod-{stem}.service")
        || intent.supervisor_pid == 0
        || intent.supervisor_birth == 0
        || intent.child_pid == 0
        || intent.child_birth == 0
        || intent.socket_dev == 0
        || intent.socket_ino == 0
        || !valid_digest(&intent.manifest_digest)
    {
        return Err("operator stop intent differs from exact launch".into());
    }
    Ok(Some((intent, hex_digest(&bytes))))
}

fn checked_stop_terminal(
    policy: &Policy,
    intent: &StopIntent,
    intent_digest: &str,
) -> Result<bool, String> {
    let path = stop_terminal_path(policy);
    repair_private_publication(&path, &policy.raw.state_directory)?;
    if !path.exists() {
        return Ok(false);
    }
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator identity changed")?
        .uid();
    let bytes = private_file(&path, &policy.raw.state_directory, uid, 4096)?;
    let terminal: StopTerminal = serde_json::from_slice(&bytes)
        .map_err(|_| "operator terminal receipt is malformed".to_owned())?;
    if terminal.schema != STOP_TERMINAL_SCHEMA
        || terminal.policy_digest != policy.policy_digest
        || terminal.stop_key != intent.stop_key
        || terminal.launch_command_id != intent.launch_command_id
        || terminal.intent_digest != intent_digest
    {
        return Err("operator terminal receipt differs from stop intent".into());
    }
    Ok(true)
}

fn process_birth_still_matches(pid: u32, birth: u64) -> Result<bool, String> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("operator process observation unavailable: {error}")),
    };
    let observed = stat
        .rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or("operator process birth observation is malformed")?;
    Ok(observed == birth)
}

fn unit_load_and_pid(unit: &str) -> Result<(String, u32), String> {
    let output = Command::new("systemctl")
        .args([
            "--user",
            "show",
            "--property=LoadState",
            "--property=MainPID",
            unit,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("operator unit observation failed: {error}"))?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err("operator unit observation is unavailable".into());
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| "operator unit observation is malformed")?;
    let mut load = None;
    let mut pid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("LoadState=") {
            if load.replace(value.to_owned()).is_some() {
                return Err("duplicate LoadState".into());
            }
        } else if let Some(value) = line.strip_prefix("MainPID=") {
            if pid
                .replace(value.parse::<u32>().map_err(|_| "invalid MainPID")?)
                .is_some()
            {
                return Err("duplicate MainPID".into());
            }
        } else {
            return Err("operator unit observation has unknown field".into());
        }
    }
    Ok((
        load.ok_or("unit LoadState is missing")?,
        pid.ok_or("unit MainPID is missing")?,
    ))
}

/// This is observation only. It never sends another stop after an intent is
/// fsynced, even if the original Pod reply was lost.
fn terminal_stop_observed(policy: &Policy, intent: &StopIntent) -> Result<bool, String> {
    let manifest_path = operator_manifest_path(policy);
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator identity changed")?
        .uid();
    let bytes = private_file(&manifest_path, &policy.pod_directory, uid, 65_536)?;
    let manifest: PodManifest =
        serde_json::from_slice(&bytes).map_err(|_| "operator manifest readback is malformed")?;
    let socket = manifest_path.with_extension("sock");
    if manifest.digest != intent.manifest_digest
        || manifest.unit_name != intent.unit_name
        || manifest.socket_path != socket
        || manifest.descriptor.pod_id != policy.pod.as_str()
        || manifest.descriptor.attempt_id != policy.attempt.as_str()
        || manifest
            .peer_binding
            .as_ref()
            .is_none_or(|binding| binding.capability != OPERATOR_PROCESS_CAPABILITY)
    {
        return Err("operator manifest changed since stop intent".into());
    }
    let (load, main_pid) = unit_load_and_pid(&intent.unit_name)?;
    if load != "not-found" {
        if main_pid == 0 {
            return Ok(false);
        }
        if main_pid != intent.supervisor_pid
            || !process_birth_still_matches(main_pid, intent.supervisor_birth)?
        {
            return Err("operator unit was substituted while stop was pending".into());
        }
        return Ok(false);
    }
    if main_pid != 0
        || process_birth_still_matches(intent.supervisor_pid, intent.supervisor_birth)?
        || process_birth_still_matches(intent.child_pid, intent.child_birth)?
    {
        return Ok(false);
    }
    if socket.exists() {
        let metadata = fs::symlink_metadata(&socket)
            .map_err(|error| format!("operator socket observation failed: {error}"))?;
        if !metadata.file_type().is_socket()
            || (metadata.dev(), metadata.ino()) != (intent.socket_dev, intent.socket_ino)
        {
            return Err("operator socket was substituted while stop was pending".into());
        }
        fs::remove_file(&socket)
            .map_err(|error| format!("stale operator socket removal failed: {error}"))?;
        File::open(&policy.pod_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("operator Pod directory sync failed: {error}"))?;
    }
    Ok(!socket.exists())
}

fn await_terminal_stop(policy: &Policy, intent: &StopIntent) -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if terminal_stop_observed(policy, intent)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn record_terminal_stop(policy: &Policy, intent: &StopIntent, digest: &str) -> Result<(), String> {
    let terminal = StopTerminal {
        schema: STOP_TERMINAL_SCHEMA.into(),
        policy_digest: policy.policy_digest.clone(),
        stop_key: intent.stop_key.clone(),
        launch_command_id: intent.launch_command_id.clone(),
        intent_digest: digest.into(),
    };
    let bytes =
        serde_json::to_vec(&terminal).map_err(|_| "operator terminal receipt encoding failed")?;
    write_private_once(
        &stop_terminal_path(policy),
        &policy.raw.state_directory,
        &bytes,
    )
}

fn print_terminal_stop(policy: &Policy, intent: &StopIntent, digest: &str, duplicate: bool) {
    println!(
        "{}",
        serde_json::json!({
            "protocol": "podbay.operator-zap-stop/1",
            "stopKey": intent.stop_key,
            "launchCommandId": intent.launch_command_id,
            "intentDigest": digest,
            "podId": policy.pod.as_str(),
            "unitName": intent.unit_name,
            "terminal": true,
            "duplicate": duplicate,
        })
    );
}

fn open_operator(
    policy: &Policy,
) -> Result<
    (
        DurableAuthority<LinuxLaunchPort>,
        TrustedInitialOwnerPolicy,
        SelfTransport,
        podbay_host::GrantId,
    ),
    String,
> {
    let port_config = TrustedLinuxLaunchConfig::from_trusted_policy(
        policy.raw.pod_executable.clone(),
        policy.raw.pod_executable_sha256.clone(),
        policy.pod_directory.clone(),
    )
    .map_err(|error| format!("trusted Pod executable refused: {error}"))?;
    let mut port = LinuxLaunchPort::new(port_config);
    let process_profile = match policy.raw.lifetime {
        LifetimeLimit::Finite { seconds } => TrustedOperatorProcessProfile::from_trusted_policy(
            1, policy.raw.node_executable.clone(), policy.raw.node_executable_sha256.clone(),
            policy.raw.zap_root.clone(), policy.arguments.clone(),
            policy.raw.zap_state_directory.clone(), seconds,
        ),
        LifetimeLimit::UntilStopped => TrustedOperatorProcessProfile::from_trusted_policy_until_stopped(
            1, policy.raw.node_executable.clone(), policy.raw.node_executable_sha256.clone(),
            policy.raw.zap_root.clone(), policy.arguments.clone(),
            policy.raw.zap_state_directory.clone(),
        ),
    }
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
    register_operator_policy(&mut host, policy)?;
    Ok((host, owner_policy, transport, grant))
}

fn launch(policy: Policy) -> Result<(), String> {
    let (mut host, _owner_policy, transport, grant) = open_operator(&policy)?;
    let selector = CommandLookupSelector::Key {
        key: policy.raw.command_key.clone(),
    };
    let existing = match host.lookup_command(&transport, &policy.scope, &selector) {
        Ok(inspection) => Some(inspection),
        Err(DurableAuthorityError::Store(StoreError::NotFound)) => None,
        Err(error) => return Err(format!("operator command readback failed: {error:?}")),
    };
    let request = bound_request(&policy, grant, host.owner_epoch(), transport.generation)?;
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
        "lifetime": policy.raw.lifetime,
    });
    println!("{output}");
    Ok(())
}

fn stop(policy: Policy) -> Result<(), String> {
    let (mut host, _owner_policy, transport, grant) = open_operator(&policy)?;
    let selector = CommandLookupSelector::Key {
        key: policy.raw.command_key.clone(),
    };
    let original = host
        .lookup_command(&transport, &policy.scope, &selector)
        .map_err(|error| format!("original operator launch is unavailable: {error:?}"))?;
    if original
        .launch_dispatch_status
        .as_ref()
        .is_none_or(|status| {
            status.stage != LaunchDispatchStage::HostAccepted
                && status.stage != LaunchDispatchStage::PortSettled
        })
    {
        return Err("original operator Pod was not HostAccepted".into());
    }
    if let Some((intent, digest)) = checked_stop_intent(&policy, &original.receipt.command_id)? {
        let terminal_recorded = checked_stop_terminal(&policy, &intent, &digest)?;
        if !await_terminal_stop(&policy, &intent)? {
            return Err(format!(
                "operator stop {digest} is uncertain; no second stop sent"
            ));
        }
        if !terminal_recorded {
            record_terminal_stop(&policy, &intent, &digest)?;
        }
        print_terminal_stop(&policy, &intent, &digest, true);
        return Ok(());
    }

    let rebind_key = format!("rebind.operator.owner.{}", host.owner_epoch().get());
    host.prepare_current_operator_process_rebind(&policy.scope, &policy.pod, &rebind_key)
        .map_err(|error| format!("operator stop rebind preparation failed: {error:?}"))?;
    let active = host
        .complete_current_operator_process_rebind(&policy.scope, &policy.pod, &rebind_key)
        .map_err(|error| format!("operator stop rebind failed: {error:?}"))?;
    if active.stage != RebindCompletionStage::PodActive {
        return Err(format!(
            "operator Pod is not Active for stop: {:?}",
            active.stage
        ));
    }
    let checked = HostRequest {
        scope_id: policy.scope.clone(),
        grant_id: grant,
        guards: GuardSet {
            manager_epoch: host.owner_epoch(),
            pod_incarnation: PodIncarnation::new(1).unwrap(),
            resource_epoch: None,
            credential_generation: transport.generation,
        },
        command_key: stop_key(&policy),
        correlation_id: format!("correlation.operator.stop.{}", &policy.policy_digest[..24]),
        deadline: Instant::now() + Duration::from_secs(30),
        action: HostAction::StopPod {
            pod_id: policy.pod.clone(),
        },
    };
    host.authorise_current_operator_stop(&transport, &checked)
        .map_err(|error| format!("exact operator StopPod authority unavailable: {error:?}"))?;
    let reviewed = host
        .inspect_committed_operator_process(&policy.scope, &policy.pod)
        .map_err(|error| format!("current operator Pod proof unavailable: {error:?}"))?;
    if reviewed.committed_record().receipt != original.receipt
        || reviewed.committed_record().session_id != policy.session.as_str()
        || reviewed.committed_record().run_id != policy.run.as_str()
        || reviewed.committed_record().attempt_id != policy.attempt.as_str()
        || reviewed.committed_record().resources.len() != 1
        || reviewed.committed_record().resources[0].id != policy.resource.as_str()
    {
        return Err("operator stop target differs from original launch".into());
    }
    let manifest_path = operator_manifest_path(&policy);
    let uid = LinuxPeerEvidence::for_current_process()
        .map_err(|_| "operator identity changed")?
        .uid();
    let manifest_bytes = private_file(&manifest_path, &policy.pod_directory, uid, 65_536)?;
    let manifest: PodManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| "operator stop manifest is malformed")?;
    let client = PodClient::connect(&manifest_path)
        .map_err(|error| format!("operator Pod connection failed: {error}"))?;
    let status = client
        .attested_status()
        .map_err(|error| format!("operator Pod status failed: {error}"))?;
    if !status.child_running
        || status.pod_id != policy.pod.as_str()
        || status.unit_name != manifest.unit_name
        || status.bound.as_ref().is_none_or(|bound| {
            bound.capability != OPERATOR_PROCESS_CAPABILITY
                || bound.resource_id != policy.resource.as_str()
        })
        || manifest.descriptor.pod_id != policy.pod.as_str()
        || manifest.descriptor.attempt_id != policy.attempt.as_str()
        || manifest.socket_path != manifest_path.with_extension("sock")
    {
        return Err("operator stop Pod attestation differs".into());
    }
    let (load, main_pid) = unit_load_and_pid(&manifest.unit_name)?;
    if load != "loaded"
        || main_pid != status.supervisor_pid
        || !process_birth_still_matches(status.supervisor_pid, status.supervisor_start_ticks)?
        || !process_birth_still_matches(status.child_pid, status.child_start_ticks)?
    {
        return Err("operator stop systemd unit or process births differ".into());
    }
    let socket = fs::symlink_metadata(&manifest.socket_path)
        .map_err(|error| format!("operator stop socket unavailable: {error}"))?;
    if !socket.file_type().is_socket() || socket.uid() != uid {
        return Err("operator stop socket identity differs".into());
    }
    let intent = StopIntent {
        schema: STOP_INTENT_SCHEMA.into(),
        policy_digest: policy.policy_digest.clone(),
        stop_key: stop_key(&policy),
        actor_id: policy.actor.as_str().into(),
        scope_id: policy.scope.as_str().into(),
        pod_id: policy.pod.as_str().into(),
        launch_command_id: original.receipt.command_id,
        manifest_digest: manifest.digest,
        unit_name: manifest.unit_name,
        socket_dev: socket.dev(),
        socket_ino: socket.ino(),
        supervisor_pid: status.supervisor_pid,
        supervisor_birth: status.supervisor_start_ticks,
        child_pid: status.child_pid,
        child_birth: status.child_start_ticks,
    };
    let bytes = serde_json::to_vec(&intent).map_err(|_| "operator stop intent encoding failed")?;
    let digest = hex_digest(&bytes);
    write_private_once(
        &stop_intent_path(&policy),
        &policy.raw.state_directory,
        &bytes,
    )?;
    // The intent is durable now. Neither a lost reply nor another CLI birth
    // may issue this Pod stop again without explicit external reconciliation.
    let stop_result = client.stop();
    #[cfg(debug_assertions)]
    if env::var_os("PODBAY_TEST_OPERATOR_STOP_DROP_REPLY").is_some() {
        let _ = stop_result;
        return Err(format!(
            "test-only lost stop reply for {digest}; inspect original intent"
        ));
    }
    if !await_terminal_stop(&policy, &intent)? {
        return Err(format!(
            "operator stop {digest} is uncertain after one port call: {stop_result:?}"
        ));
    }
    record_terminal_stop(&policy, &intent, &digest)?;
    print_terminal_stop(&policy, &intent, &digest, false);
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
        max_wall_seconds: match policy.raw.lifetime {
            LifetimeLimit::Finite { seconds } => seconds,
            LifetimeLimit::UntilStopped => 30,
        },
        max_children: 0,
        allow_fallback: false,
    })
    .map_err(|error| format!("operator launch profile refused: {error:?}"))?;
    let profile = if policy.raw.lifetime == LifetimeLimit::UntilStopped {
        profile.with_until_stopped_operator_service()
            .map_err(|error| format!("operator Service lifetime refused: {error:?}"))?
    } else { profile };
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
                wall_seconds: match policy.raw.lifetime {
                    LifetimeLimit::Finite { seconds } => seconds,
                    LifetimeLimit::UntilStopped => 30,
                },
                max_children: 0,
                parent_run_id: None,
            },
        }),
    })
}
