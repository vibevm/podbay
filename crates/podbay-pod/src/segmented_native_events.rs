//! Linux V2 pod-owned native observation source. Every native take has a
//! durable pending marker; each exact private frame is fsynced before its
//! redacted checkpoint becomes visible. A restart with an unresolved marker
//! loses fidelity explicitly instead of inventing a contiguous event stream.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::manifest::PodError;
use crate::native_events::{
    NativeEventAppend, NativeEventCursor, NativeEventIdentity, NativeEventKind, NativeEventRead,
    NativeEventStatus, public_event, validate_private_jsonl,
};
use crate::native_segment_checkpoint::{LinuxNativeSegmentDirectory, NativeSegmentCheckpoint};

pub(crate) struct SegmentedNativeEventSpool {
    files: LinuxNativeSegmentDirectory,
    checkpoint: NativeSegmentCheckpoint,
    poisoned: bool,
}

impl SegmentedNativeEventSpool {
    pub(crate) fn open(slot: PathBuf, identity: NativeEventIdentity) -> Result<Self, PodError> {
        let files = LinuxNativeSegmentDirectory::from_private_slot(slot)?;
        let mut checkpoint = files.open_or_initialize_writer(&identity)?;
        let _ = files.prune_durable_predecessor_after_reopen(&identity)?;
        let _ = files.discard_empty_successor_after_reopen(&identity)?;
        if checkpoint.pending_source_sequence.is_some() {
            let uncertain = checkpoint.mark_continuity_unknown()?;
            files.commit_checkpoint(&uncertain)?;
            checkpoint = uncertain;
        }
        Ok(Self {
            files,
            checkpoint,
            poisoned: false,
        })
    }

    /// Run before taking the native observation from the adapter queue. A
    /// rollover failure at this point has consumed no native evidence.
    pub(crate) fn reserve_native_take(&mut self) -> Result<u64, PodError> {
        if self.poisoned || self.checkpoint.redacted_snapshot.quarantined {
            return Err(PodError::Uncertain("native event source is uncertain"));
        }
        if !self.checkpoint.can_hold_max_frame() {
            self.rollover_before_take()?;
        }
        let next = self.checkpoint.reserve_native_take()?;
        if self.files.commit_checkpoint(&next).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "native take reservation outcome unknown",
            ));
        }
        let sequence = next.pending_source_sequence.expect("reserved sequence");
        self.checkpoint = next;
        Ok(sequence)
    }

    fn rollover_before_take(&mut self) -> Result<(), PodError> {
        let next_id = self
            .checkpoint
            .active()
            .id
            .checked_add(1)
            .ok_or(PodError::Invalid("native segment ID exhausted"))?;
        if self.files.create_empty_segment(next_id).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "native segment creation outcome unknown",
            ));
        }
        let plan = match self.checkpoint.rollover_plan() {
            Ok(plan) => plan,
            Err(_) => {
                self.poisoned = true;
                return Err(PodError::Uncertain(
                    "native rollover planning failed after segment creation",
                ));
            }
        };
        if self.files.commit_checkpoint(&plan.checkpoint).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "native rollover checkpoint outcome unknown",
            ));
        }
        self.checkpoint = plan.checkpoint;
        if let Some(removed) = &plan.prune
            && self
                .files
                .prune_after_checkpoint(removed, &self.checkpoint)
                .is_err()
        {
            self.poisoned = true;
            return Err(PodError::Uncertain("native segment prune outcome unknown"));
        }
        Ok(())
    }

    pub(crate) fn append_applied(
        &mut self,
        source_sequence: u64,
        private_jsonl: &[u8],
        kind: NativeEventKind,
        status: Option<NativeEventStatus>,
        external_conflict: bool,
    ) -> Result<NativeEventAppend, PodError> {
        if self.poisoned || self.checkpoint.redacted_snapshot.quarantined {
            return Err(PodError::Uncertain("native event source is uncertain"));
        }
        if self.checkpoint.pending_source_sequence != Some(source_sequence) {
            return Err(PodError::Conflict(
                "native source has no exact take reservation",
            ));
        }
        validate_private_jsonl(private_jsonl)?;
        let recorded_at_unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PodError::Invalid("native event clock unavailable"))?
            .as_millis()
            .try_into()
            .map_err(|_| PodError::Invalid("native event clock overflow"))?;
        let event = public_event(
            &self.checkpoint.identity,
            source_sequence,
            recorded_at_unix_millis,
            kind,
            status,
            external_conflict,
        );
        let receipt = match self
            .files
            .append_frame_synced(self.checkpoint.active(), private_jsonl)
        {
            Ok(receipt) => receipt,
            Err(_) => {
                self.poisoned = true;
                return Err(PodError::Uncertain("native segment append outcome unknown"));
            }
        };
        let next =
            match self
                .checkpoint
                .after_synced_append(source_sequence, event.clone(), &receipt)
            {
                Ok(next) => next,
                Err(_) => {
                    self.poisoned = true;
                    return Err(PodError::Uncertain(
                        "native segment checkpoint construction failed after append",
                    ));
                }
            };
        if self.files.commit_checkpoint(&next).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "native segment checkpoint outcome unknown",
            ));
        }
        self.checkpoint = next;
        Ok(NativeEventAppend::Committed(event))
    }

    pub(crate) fn mark_continuity_unknown(&mut self) -> Result<(), PodError> {
        if self.checkpoint.redacted_snapshot.quarantined {
            return Ok(());
        }
        if self.poisoned {
            return Err(PodError::Uncertain("native segment write outcome unknown"));
        }
        let next = self.checkpoint.mark_continuity_unknown()?;
        if self.files.commit_checkpoint(&next).is_err() {
            self.poisoned = true;
            return Err(PodError::Uncertain(
                "native continuity checkpoint outcome unknown",
            ));
        }
        self.checkpoint = next;
        Ok(())
    }

    pub(crate) fn read_after(
        &self,
        cursor: Option<&NativeEventCursor>,
        limit: usize,
    ) -> Result<NativeEventRead, PodError> {
        if self.poisoned
            || self.checkpoint.pending_source_sequence.is_some()
            || !(1..=64).contains(&limit)
        {
            return Err(PodError::Uncertain(
                "native segment snapshot is pending or unbounded",
            ));
        }
        if self.files.read_checkpoint_incremental(&self.checkpoint)? != self.checkpoint {
            return Err(PodError::Uncertain("held native checkpoint changed"));
        }
        self.checkpoint.redacted_read_after(cursor, limit)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    use podbay_core::{
        AttemptId, Epoch, PodId, ResourceId, RunId, ScopeId, SessionId, StoreLineageId,
    };

    use super::*;

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "podbay-segmented-native-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed),
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self { root }
        }
        fn open(&self) -> SegmentedNativeEventSpool {
            SegmentedNativeEventSpool::open(self.root.clone(), identity()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn identity() -> NativeEventIdentity {
        NativeEventIdentity::from_resource(
            &StoreLineageId::try_from("lineage.fixture").unwrap(),
            &ScopeId::try_from("scope.fixture").unwrap(),
            &SessionId::try_from("session.fixture").unwrap(),
            &RunId::try_from("run.fixture").unwrap(),
            &AttemptId::try_from("attempt.fixture").unwrap(),
            &PodId::try_from("pod.fixture").unwrap(),
            Epoch::new(1).unwrap(),
            &ResourceId::try_from("resource.fixture").unwrap(),
            Epoch::new(1).unwrap(),
        )
    }

    fn raw(text: &str) -> Vec<u8> {
        format!("{{\"method\":\"item/agentMessage/delta\",\"params\":{{\"delta\":\"{text}\"}}}}\n")
            .into_bytes()
    }

    fn raw_of_len(len: usize) -> Vec<u8> {
        let overhead = raw("").len();
        assert!(len >= overhead);
        raw(&"x".repeat(len - overhead))
    }

    #[test]
    fn fresh_append_reopen_and_public_projection_keep_private_frame_separate() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        let sequence = spool.reserve_native_take().unwrap();
        assert_eq!(sequence, 1);
        let secret = raw("private prompt and answer");
        assert!(matches!(
            spool
                .append_applied(sequence, &secret, NativeEventKind::Output, None, false)
                .unwrap(),
            NativeEventAppend::Committed(_)
        ));
        let cursor = NativeEventCursor {
            identity: identity(),
            sequence: 0,
        };
        let read = spool.read_after(Some(&cursor), 16).unwrap();
        assert_eq!(read.snapshot.watermark, 1);
        assert_eq!(read.events.len(), 1);
        assert!(
            !serde_json::to_string(&read)
                .unwrap()
                .contains("private prompt")
        );
        drop(spool);
        let reopened = fixture.open();
        let read = reopened.read_after(Some(&cursor), 16).unwrap();
        assert_eq!(read.events.len(), 1);
        let (private, gap) = reopened
            .files
            .read_indexed_page(&reopened.checkpoint, 0, 16)
            .unwrap();
        assert_eq!(gap, None);
        assert_eq!(private[0].private_payload(), secret);
    }

    #[test]
    fn large_bootstrap_notifications_replay_across_segments_without_gap() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        let private = raw_of_len(213_357);
        for sequence in 1..=15 {
            assert_eq!(spool.reserve_native_take().unwrap(), sequence);
            spool
                .append_applied(sequence, &private, NativeEventKind::Output, None, false)
                .unwrap();
        }
        assert!(spool.checkpoint.segments.len() > 1);
        drop(spool);

        let reopened = fixture.open();
        let mut after = 0;
        let mut count = 0;
        loop {
            let (page, gap) = reopened
                .files
                .read_indexed_page(&reopened.checkpoint, after, 4)
                .unwrap();
            assert_eq!(gap, None);
            if page.is_empty() {
                break;
            }
            for frame in &page {
                assert_eq!(frame.private_payload(), private);
            }
            count += page.len();
            after = page.last().unwrap().source_sequence();
        }
        assert_eq!(count, 15);
        assert_eq!(after, 15);
    }

    #[test]
    fn private_jsonl_accepts_exact_limit_and_rejects_one_byte_more() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        let sequence = spool.reserve_native_take().unwrap();
        spool
            .append_applied(
                sequence,
                &raw_of_len(262_144),
                NativeEventKind::Output,
                None,
                false,
            )
            .unwrap();
        let sequence = spool.reserve_native_take().unwrap();
        assert!(matches!(
            spool.append_applied(
                sequence,
                &raw_of_len(262_145),
                NativeEventKind::Output,
                None,
                false,
            ),
            Err(PodError::Invalid(_))
        ));
        spool.mark_continuity_unknown().unwrap();
        let reopened = fixture.open();
        assert!(reopened.checkpoint.redacted_snapshot.quarantined);
        assert_eq!(reopened.checkpoint.watermark, 1);
    }

    #[test]
    fn unresolved_native_take_reopens_with_durable_unknown_fidelity() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        assert_eq!(spool.reserve_native_take().unwrap(), 1);
        drop(spool);
        let mut reopened = fixture.open();
        assert_eq!(reopened.checkpoint.pending_source_sequence, None);
        assert!(reopened.checkpoint.redacted_snapshot.quarantined);
        assert_eq!(
            reopened.checkpoint.redacted_snapshot.fidelity,
            crate::native_events::NativeEventFidelity::Unknown
        );
        assert_eq!(reopened.read_after(None, 16).unwrap().snapshot.watermark, 0);
        assert!(reopened.reserve_native_take().is_err());
    }

    #[test]
    fn malformed_consumed_native_frame_quarantines_without_fabricated_event() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        let sequence = spool.reserve_native_take().unwrap();
        assert!(
            spool
                .append_applied(sequence, b"not JSONL", NativeEventKind::Output, None, false)
                .is_err()
        );
        spool.mark_continuity_unknown().unwrap();
        drop(spool);
        let reopened = fixture.open();
        let read = reopened.read_after(None, 16).unwrap();
        assert!(read.snapshot.quarantined);
        assert_eq!(read.snapshot.watermark, 0);
        assert!(read.events.is_empty());
    }

    #[test]
    fn fsynced_temporary_checkpoint_recovers_exact_appended_event() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        let sequence = spool.reserve_native_take().unwrap();
        let private = raw("private recovered output");
        let receipt = spool
            .files
            .append_frame_synced(spool.checkpoint.active(), &private)
            .unwrap();
        let event = public_event(
            &identity(),
            sequence,
            1,
            NativeEventKind::Output,
            None,
            false,
        );
        let candidate = spool
            .checkpoint
            .after_synced_append(sequence, event, &receipt)
            .unwrap();
        let temporary = fixture.root.join("native-events.checkpoint-new");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .unwrap();
        file.write_all(&candidate.encode().unwrap()).unwrap();
        file.sync_all().unwrap();
        fs::File::open(&fixture.root).unwrap().sync_all().unwrap();
        drop(file);
        drop(spool);
        let reopened = fixture.open();
        assert_eq!(reopened.checkpoint.watermark, 1);
        assert_eq!(reopened.checkpoint.pending_source_sequence, None);
        assert!(!temporary.exists());
        let cursor = NativeEventCursor {
            identity: identity(),
            sequence: 0,
        };
        assert_eq!(
            reopened.read_after(Some(&cursor), 16).unwrap().events.len(),
            1
        );
    }

    #[test]
    fn long_running_source_rolls_and_bounds_files_with_explicit_gap() {
        let fixture = Fixture::new();
        let mut spool = fixture.open();
        let body = raw(&"x".repeat(59_000));
        for expected in 1..=72 {
            let sequence = spool.reserve_native_take().unwrap();
            assert_eq!(sequence, expected);
            spool
                .append_applied(sequence, &body, NativeEventKind::Output, None, false)
                .unwrap();
        }
        let first = fixture.root.join("native-events-0000000000000001.segment");
        assert!(!first.exists());
        let count = fs::read_dir(&fixture.root)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.file_name().to_string_lossy().ends_with(".segment"))
            })
            .count();
        assert_eq!(count, 4);
        assert!(spool.checkpoint.redacted_snapshot.earliest_retained > 1);
        let cursor = NativeEventCursor {
            identity: identity(),
            sequence: 0,
        };
        let read = spool.read_after(Some(&cursor), 64).unwrap();
        assert!(read.gap.is_some());
        assert!(read.events.len() <= 64);
        assert_eq!(spool.checkpoint.redacted_snapshot.watermark, 72);
        assert_eq!(fs::metadata(&fixture.root).unwrap().mode() & 0o7777, 0o700);
        drop(spool);
        assert_eq!(fixture.open().checkpoint.watermark, 72);
    }
}
