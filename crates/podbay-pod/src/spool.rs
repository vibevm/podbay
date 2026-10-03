//! Pod-local protected WAL for PTY evidence and uncertain command input.
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::{PodError, hex};
use crate::terminal::{ScreenCheckpoint, TerminalEvent};

const MAX_FRAME: usize = 1_048_576;
const MAX_LOG: u64 = 64 * 1_048_576;
const MAX_COMMAND_RECORDS: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStage {
    Intent,
    BytesWritten,
    Uncertain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandRecord {
    version: u32,
    command_id: String,
    digest: String,
    resource_id: String,
    incarnation: u64,
    lease_epoch: u64,
    kind: String,
    stage: CommandStage,
}

pub struct PodSpool {
    event_path: PathBuf,
    checkpoint_path: PathBuf,
    event_file: File,
    command_file: File,
    events: VecDeque<TerminalEvent>,
    commands: HashMap<String, CommandRecord>,
    last_sequence: u64,
    checkpoint: Option<ScreenCheckpoint>,
    checkpoint_sequence: u64,
    retention: usize,
    integrity: bool,
    command_records: usize,
    event_log_bytes: u64,
    fresh: bool,
    #[cfg(test)]
    fail_next_sync: bool,
}

impl PodSpool {
    pub fn open(
        manifest_path: &Path,
        retention: usize,
        resource_id: &str,
        incarnation: u64,
    ) -> Result<Self, PodError> {
        if !(1..=4_096).contains(&retention) {
            return Err(PodError::Invalid("spool retention bound"));
        }
        let event_path = manifest_path.with_extension("events");
        let command_path = manifest_path.with_extension("commands");
        let checkpoint_path = manifest_path.with_extension("checkpoint");
        let event_exists = fs::symlink_metadata(&event_path).is_ok();
        let command_exists = fs::symlink_metadata(&command_path).is_ok();
        let checkpoint_exists = fs::symlink_metadata(&checkpoint_path).is_ok();
        let fresh = !event_exists && !command_exists && !checkpoint_exists;
        if !fresh && (!event_exists || !command_exists) {
            return Err(PodError::Uncertain(
                "incomplete pod spool; no automatic repair",
            ));
        }
        let event_file = private_append(&event_path)?;
        let command_file = private_append(&command_path)?;
        File::open(
            manifest_path
                .parent()
                .ok_or(PodError::Invalid("spool parent"))?,
        )?
        .sync_all()?;
        let (raw_events, event_valid) = read_frames(&event_path)?;
        let (raw_commands, command_valid) = read_frames(&command_path)?;
        let mut events = VecDeque::new();
        let mut last_sequence = 0;
        let event_log_bytes = event_file.metadata()?.len();
        let mut integrity = event_valid && command_valid;
        for raw in raw_events {
            match serde_json::from_slice::<TerminalEvent>(&raw) {
                Ok(event)
                    if event.resource_id == resource_id
                        && event.incarnation == incarnation
                        && (event.sequence == last_sequence + 1
                            || (last_sequence == 0 && event.sequence > 0)) =>
                {
                    last_sequence = event.sequence;
                    events.push_back(event);
                }
                _ => {
                    integrity = false;
                    break;
                }
            }
        }
        let mut commands = HashMap::new();
        let mut command_records = 0;
        for raw in raw_commands {
            match serde_json::from_slice::<CommandRecord>(&raw) {
                Ok(record)
                    if record.version == 1
                        && record.resource_id == resource_id
                        && record.incarnation == incarnation =>
                {
                    if let Some(previous) = commands.get(&record.command_id) {
                        let prior: &CommandRecord = previous;
                        if prior.digest != record.digest
                            || prior.resource_id != record.resource_id
                            || prior.incarnation != record.incarnation
                            || prior.lease_epoch != record.lease_epoch
                            || prior.kind != record.kind
                            || prior.stage != CommandStage::Intent
                            || record.stage == CommandStage::Intent
                        {
                            integrity = false;
                            break;
                        }
                    } else if record.stage != CommandStage::Intent {
                        integrity = false;
                        break;
                    }
                    commands.insert(record.command_id.clone(), record);
                    command_records += 1;
                }
                _ => {
                    integrity = false;
                    break;
                }
            }
        }
        let (checkpoint, checkpoint_valid) = read_checkpoint(&checkpoint_path)?;
        integrity &= checkpoint_valid;
        let checkpoint_sequence = checkpoint.as_ref().map_or(0, |value| value.through);
        if let Some(checkpoint) = &checkpoint
            && ((last_sequence != 0 && checkpoint.through > last_sequence)
                || checkpoint.parser_version != "vt100/0.16.2-pb06")
        {
            integrity = false;
        }
        if last_sequence == 0 {
            last_sequence = checkpoint_sequence;
        }
        if let Some(first) = events.front()
            && first.sequence > checkpoint_sequence.saturating_add(1)
        {
            integrity = false;
        }
        if events.front().is_some_and(|first| first.sequence > 1) && checkpoint.is_none() {
            integrity = false;
        }
        Ok(Self {
            event_path,
            checkpoint_path,
            event_file,
            command_file,
            events,
            commands,
            last_sequence,
            checkpoint,
            checkpoint_sequence,
            retention,
            integrity,
            command_records,
            event_log_bytes,
            fresh,
            #[cfg(test)]
            fail_next_sync: false,
        })
    }

    pub fn integrity(&self) -> bool {
        self.integrity
    }
    #[cfg(test)]
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
    #[cfg(test)]
    pub fn checkpoint(&self) -> Option<&ScreenCheckpoint> {
        self.checkpoint.as_ref()
    }
    pub fn events(&self) -> &VecDeque<TerminalEvent> {
        &self.events
    }
    pub fn has_history(&self) -> bool {
        !self.fresh
            || self.last_sequence != 0
            || self.checkpoint.is_some()
            || !self.commands.is_empty()
    }
    pub fn needs_checkpoint(&self) -> bool {
        self.events.len() > self.retention * 2
            || self.event_log_bytes > 16 * 1_048_576
            || self.last_sequence.saturating_sub(self.checkpoint_sequence) >= 256
    }

    pub fn append_event(&mut self, event: &TerminalEvent) -> Result<(), PodError> {
        self.healthy()?;
        if event.sequence != self.last_sequence + 1 {
            return Err(PodError::Invalid("spool event sequence is not contiguous"));
        }
        let fail_sync = self.fail_sync();
        append_synced(&mut self.event_file, event, fail_sync)
            .inspect_err(|_| self.integrity = false)?;
        self.last_sequence = event.sequence;
        self.event_log_bytes += serde_json::to_vec(event)?.len() as u64 + 36;
        self.events.push_back(event.clone());
        Ok(())
    }

    pub fn checkpoint_if_needed(&mut self, screen: &ScreenCheckpoint) -> Result<(), PodError> {
        self.healthy()?;
        if screen.through != self.last_sequence {
            return Err(PodError::Invalid("screen and spool watermark differ"));
        }
        let prune = self.events.len() > self.retention * 2 || self.event_log_bytes > 16 * 1_048_576;
        if !self.needs_checkpoint() {
            return Ok(());
        }
        write_checkpoint(&self.checkpoint_path, screen).inspect_err(|_| self.integrity = false)?;
        self.checkpoint = Some(screen.clone());
        self.checkpoint_sequence = screen.through;
        if prune {
            self.prune()
                .inspect_err(|_| self.integrity = false)
                .map_err(|_| PodError::Uncertain("pod event retention outcome unknown"))?;
        }
        Ok(())
    }

    pub fn lookup_command(&self, id: &str, digest: &str) -> Result<Option<CommandStage>, PodError> {
        self.healthy()?;
        match self.commands.get(id) {
            Some(record) if record.digest == digest => Ok(Some(record.stage)),
            Some(_) => Err(PodError::Conflict("pod command ID changed content")),
            None => Ok(None),
        }
    }

    pub fn record_command(
        &mut self,
        id: &str,
        digest: &str,
        resource_id: &str,
        incarnation: u64,
        lease_epoch: u64,
        kind: &str,
        stage: CommandStage,
    ) -> Result<(), PodError> {
        self.healthy()?;
        if id.len() < 3
            || id.len() > 160
            || digest.len() != 64
            || self.command_records >= MAX_COMMAND_RECORDS
        {
            return Err(PodError::Invalid("pod command identity or retention bound"));
        }
        if let Some(previous) = self.commands.get(id)
            && (previous.digest != digest
                || previous.resource_id != resource_id
                || previous.incarnation != incarnation
                || previous.lease_epoch != lease_epoch
                || previous.kind != kind)
        {
            return Err(PodError::Conflict("pod command identity changed"));
        }
        let record = CommandRecord {
            version: 1,
            command_id: id.into(),
            digest: digest.into(),
            resource_id: resource_id.into(),
            incarnation,
            lease_epoch,
            kind: kind.into(),
            stage,
        };
        let frame_bytes = serde_json::to_vec(&record)?.len() as u64 + 36;
        let reserved = if stage == CommandStage::Intent {
            frame_bytes * 2
        } else {
            frame_bytes
        };
        if self.command_file.metadata()?.len().saturating_add(reserved) > MAX_LOG {
            return Err(PodError::Refused(
                "pod command ledger retention bound reached",
            ));
        }
        match self.commands.get(id).map(|record| record.stage) {
            None if stage == CommandStage::Intent => {}
            Some(CommandStage::Intent) if stage != CommandStage::Intent => {}
            _ => return Err(PodError::Conflict("pod command stage transition refused")),
        }
        let fail_sync = self.fail_sync();
        append_synced(&mut self.command_file, &record, fail_sync)
            .inspect_err(|_| self.integrity = false)?;
        self.commands.insert(id.into(), record);
        self.command_records += 1;
        Ok(())
    }

    fn prune(&mut self) -> Result<(), PodError> {
        let mut retained_reverse = Vec::new();
        let mut retained_bytes = 0_usize;
        for event in self.events.iter().rev().take(self.retention) {
            let size = serde_json::to_vec(event)?.len() + 36;
            if !retained_reverse.is_empty() && retained_bytes + size > 8 * 1_048_576 {
                break;
            }
            retained_bytes += size;
            retained_reverse.push(event.clone());
        }
        let retained = retained_reverse.into_iter().rev().collect::<Vec<_>>();
        let temporary = self.event_path.with_extension("events.new");
        let mut output = private_new(&temporary)?;
        for event in &retained {
            write_frame(&mut output, event)?;
        }
        output.sync_all()?;
        fs::rename(&temporary, &self.event_path)?;
        File::open(self.event_path.parent().unwrap())?.sync_all()?;
        self.event_file = private_append(&self.event_path)?;
        self.event_log_bytes = self.event_file.metadata()?.len();
        self.events = retained.into();
        Ok(())
    }

    fn healthy(&self) -> Result<(), PodError> {
        if self.integrity {
            Ok(())
        } else {
            Err(PodError::Uncertain("pod spool integrity unknown"))
        }
    }

    fn fail_sync(&mut self) -> bool {
        #[cfg(test)]
        {
            let fail = self.fail_next_sync;
            self.fail_next_sync = false;
            fail
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    #[cfg(test)]
    pub fn fail_one_sync(&mut self) {
        self.fail_next_sync = true;
    }
}

pub fn digest_command<T: Serialize>(command: &T) -> Result<String, PodError> {
    let mut digest = Sha256::new();
    digest.update(b"podbay-pod-command/1\0");
    digest.update(serde_json::to_vec(command)?);
    Ok(hex(&digest.finalize()))
}

fn private_new(path: &Path) -> Result<File, PodError> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}
fn private_append(path: &Path) -> Result<File, PodError> {
    if !path.exists() {
        return private_new(path);
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(PodError::Invalid(
            "pod spool file is not private and regular",
        ));
    }
    Ok(file)
}
fn append_synced<T: Serialize>(
    file: &mut File,
    value: &T,
    fail_sync: bool,
) -> Result<(), PodError> {
    write_frame(file, value)
        .map_err(|_| PodError::Uncertain("pod spool append outcome unknown"))?;
    if fail_sync {
        return Err(PodError::Uncertain("synthetic spool fsync failure"));
    }
    file.sync_data()
        .map_err(|_| PodError::Uncertain("pod spool fsync outcome unknown"))?;
    Ok(())
}
fn write_frame<T: Serialize>(file: &mut File, value: &T) -> Result<(), PodError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME {
        return Err(PodError::Invalid("pod spool frame bound"));
    }
    file.write_all(&(bytes.len() as u32).to_be_bytes())?;
    file.write_all(&Sha256::digest(&bytes))?;
    file.write_all(&bytes)?;
    Ok(())
}
fn read_frames(path: &Path) -> Result<(Vec<Vec<u8>>, bool), PodError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(PodError::Invalid(
            "pod spool file is not private and regular",
        ));
    }
    if metadata.len() > MAX_LOG {
        return Ok((Vec::new(), false));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut result = Vec::new();
    loop {
        let mut length = [0_u8; 4];
        match file.read(&mut length)? {
            0 => return Ok((result, true)),
            4 => {}
            read => {
                if file.read_exact(&mut length[read..]).is_err() {
                    return Ok((result, false));
                }
            }
        }
        let size = u32::from_be_bytes(length) as usize;
        if size == 0 || size > MAX_FRAME {
            return Ok((result, false));
        }
        let mut checksum = [0_u8; 32];
        let mut bytes = vec![0_u8; size];
        if file.read_exact(&mut checksum).is_err()
            || file.read_exact(&mut bytes).is_err()
            || checksum.as_slice() != Sha256::digest(&bytes).as_slice()
        {
            return Ok((result, false));
        }
        result.push(bytes);
    }
}
fn write_checkpoint(path: &Path, screen: &ScreenCheckpoint) -> Result<(), PodError> {
    let temporary = path.with_extension("checkpoint.new");
    let mut file = private_new(&temporary)?;
    write_frame(&mut file, screen)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn read_checkpoint(path: &Path) -> Result<(Option<ScreenCheckpoint>, bool), PodError> {
    if !path.exists() {
        return Ok((None, true));
    }
    let (records, valid) = read_frames(path)?;
    if !valid || records.len() != 1 {
        return Ok((None, false));
    }
    match serde_json::from_slice::<ScreenCheckpoint>(&records[0]) {
        Ok(checkpoint) => Ok((Some(checkpoint), true)),
        Err(_) => Ok((None, false)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::{ScreenFidelity, TerminalEventKind};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture {
        directory: PathBuf,
        manifest: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory =
                std::env::temp_dir().join(format!("podbay-spool-{}-{unique}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let manifest = directory.join("pod.fixture.json");
            Self {
                directory,
                manifest,
            }
        }
        fn open(&self, retention: usize) -> PodSpool {
            PodSpool::open(&self.manifest, retention, "resource.fixture", 3).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    fn event(sequence: u64, bytes: Vec<u8>) -> TerminalEvent {
        TerminalEvent {
            sequence,
            resource_id: "resource.fixture".into(),
            incarnation: 3,
            value: TerminalEventKind::Output {
                bytes,
                source_byte_position: sequence * 4096,
            },
        }
    }
    fn screen(through: u64) -> ScreenCheckpoint {
        ScreenCheckpoint {
            parser_version: "vt100/0.16.2-pb06".into(),
            revision: through,
            through,
            source_byte_position: through * 4096,
            rows: 24,
            cols: 80,
            cursor_row: 0,
            cursor_col: 0,
            alternate_screen: false,
            plain_text: "partial screen".into(),
            formatted_bytes: vec![],
            fidelity: ScreenFidelity::Partial {
                reason: "snapshot only; parser cannot resume".into(),
            },
        }
    }

    #[test]
    fn high_output_prunes_with_checkpoint_and_reopen_has_exact_gap() {
        let fixture = Fixture::new();
        let mut spool = fixture.open(4);
        for sequence in 1..=12 {
            spool
                .append_event(&event(sequence, vec![b'X'; 4096]))
                .unwrap();
            if spool.needs_checkpoint() {
                spool.checkpoint_if_needed(&screen(sequence)).unwrap();
            }
        }
        assert_eq!(spool.last_sequence(), 12);
        assert_eq!(spool.events().front().unwrap().sequence, 6);
        assert_eq!(spool.checkpoint().unwrap().through, 9);
        drop(spool);
        let reopened = fixture.open(4);
        assert!(reopened.integrity());
        assert_eq!(reopened.last_sequence(), 12);
        assert_eq!(reopened.events().front().unwrap().sequence, 6);
        assert_eq!(reopened.checkpoint().unwrap().through, 9);
    }

    #[test]
    fn encoded_log_byte_bound_prunes_before_reopen_limit() {
        let fixture = Fixture::new();
        let mut spool = fixture.open(4_096);
        for sequence in 1..=1_200 {
            spool
                .append_event(&event(sequence, vec![255; 4_096]))
                .unwrap();
            if spool.needs_checkpoint() {
                spool.checkpoint_if_needed(&screen(sequence)).unwrap();
            }
        }
        let first = spool.events().front().unwrap().sequence;
        assert!(
            first > 1,
            "encoded bytes must trigger pruning before count bound"
        );
        assert!(
            fs::metadata(fixture.manifest.with_extension("events"))
                .unwrap()
                .len()
                < 16 * 1_048_576
        );
        drop(spool);
        let reopened = fixture.open(4_096);
        assert!(reopened.integrity());
        assert_eq!(reopened.events().front().unwrap().sequence, first);
        assert_eq!(reopened.last_sequence(), 1_200);
    }

    #[test]
    fn corrupt_tail_and_sync_failure_never_advance_trusted_sequence() {
        let fixture = Fixture::new();
        let mut spool = fixture.open(8);
        spool.append_event(&event(1, vec![1])).unwrap();
        spool.fail_one_sync();
        assert!(matches!(
            spool.append_event(&event(2, vec![2])),
            Err(PodError::Uncertain(_))
        ));
        assert_eq!(spool.last_sequence(), 1);
        assert!(!spool.integrity());
        drop(spool);
        let mut file = OpenOptions::new()
            .append(true)
            .open(fixture.manifest.with_extension("events"))
            .unwrap();
        file.write_all(b"bad tail").unwrap();
        file.sync_all().unwrap();
        let reopened = fixture.open(8);
        assert!(!reopened.integrity());
        assert_eq!(reopened.last_sequence(), 2);
    }

    #[test]
    fn command_intent_reopens_as_uncertain_and_completion_deduplicates() {
        let fixture = Fixture::new();
        let mut spool = fixture.open(8);
        let digest = "a".repeat(64);
        spool
            .record_command(
                "command.fixture",
                &digest,
                "resource.fixture",
                3,
                5,
                "write",
                CommandStage::Intent,
            )
            .unwrap();
        drop(spool);
        let mut reopened = fixture.open(8);
        assert_eq!(
            reopened.lookup_command("command.fixture", &digest).unwrap(),
            Some(CommandStage::Intent)
        );
        assert!(matches!(
            reopened.lookup_command("command.fixture", &"b".repeat(64)),
            Err(PodError::Conflict(_))
        ));
        reopened
            .record_command(
                "command.fixture",
                &digest,
                "resource.fixture",
                3,
                5,
                "write",
                CommandStage::BytesWritten,
            )
            .unwrap();
        drop(reopened);
        let reopened = fixture.open(8);
        assert_eq!(
            reopened.lookup_command("command.fixture", &digest).unwrap(),
            Some(CommandStage::BytesWritten)
        );
    }

    #[test]
    fn failed_command_receipt_sync_is_uncertain_and_never_replayed() {
        let fixture = Fixture::new();
        let mut spool = fixture.open(8);
        let digest = "c".repeat(64);
        spool
            .record_command(
                "command.failure",
                &digest,
                "resource.fixture",
                3,
                2,
                "write",
                CommandStage::Intent,
            )
            .unwrap();
        spool.fail_one_sync();
        assert!(matches!(
            spool.record_command(
                "command.failure",
                &digest,
                "resource.fixture",
                3,
                2,
                "write",
                CommandStage::BytesWritten
            ),
            Err(PodError::Uncertain(_))
        ));
        assert!(!spool.integrity());
        assert!(matches!(
            spool.lookup_command("command.failure", &digest),
            Err(PodError::Uncertain(_))
        ));
    }

    #[test]
    fn checkpoint_tail_gap_and_wrong_resource_are_untrusted() {
        let fixture = Fixture::new();
        let mut spool = fixture.open(8);
        spool.append_event(&event(1, vec![1])).unwrap();
        spool.checkpoint_if_needed(&screen(1)).unwrap(); // threshold not reached
        drop(spool);
        write_checkpoint(&fixture.manifest.with_extension("checkpoint"), &screen(1)).unwrap();
        let path = fixture.manifest.with_extension("events");
        fs::remove_file(&path).unwrap();
        let mut file = private_new(&path).unwrap();
        write_frame(&mut file, &event(3, vec![3])).unwrap();
        file.sync_all().unwrap();
        let reopened = fixture.open(8);
        assert!(!reopened.integrity());
        drop(reopened);
        fs::remove_file(&path).unwrap();
        let mut wrong = event(1, vec![1]);
        wrong.resource_id = "resource.other".into();
        let mut file = private_new(&path).unwrap();
        write_frame(&mut file, &wrong).unwrap();
        file.sync_all().unwrap();
        assert!(!fixture.open(8).integrity());
    }

    #[test]
    fn incomplete_spool_is_refused_without_creating_missing_file() {
        let fixture = Fixture::new();
        let event_path = fixture.manifest.with_extension("events");
        drop(private_new(&event_path).unwrap());
        assert!(matches!(
            PodSpool::open(&fixture.manifest, 8, "resource.fixture", 3),
            Err(PodError::Uncertain(_))
        ));
        assert!(!fixture.manifest.with_extension("commands").exists());
    }
}
