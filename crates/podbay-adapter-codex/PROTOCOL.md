# Codex app-server protocol receipt

The local `codex --version` was `codex-cli 0.159.3`. Its
`codex app-server generate-json-schema --out <temporary-directory>` command
completed without starting an app-server session. The generated
`codex_app_server_protocol.v2.schemas.json` has SHA-256
`81a88c04ae4984b16d73080f4109d0477682bc76c8adbe483e371175ce54c054`.
The generated bundle is deliberately not committed. Regenerate it from this
exact CLI version before changing the typed boundary.

Selected non-experimental v2 shapes from that bundle:

| Method | Required request fields | Response fields used here |
| --- | --- | --- |
| `initialize` (v1) | `clientInfo` (`name`, `version`) | `codexHome`, `platformFamily`, `platformOs`, `userAgent` |
| `thread/start` | none in schema; this adapter sends `model`, `cwd`, `approvalPolicy`, `sandbox`, `config.model_reasoning_effort` | `thread`, `model`, `reasoningEffort`, `approvalPolicy`, `sandbox`, `cwd` |
| `thread/read` | `threadId`; metadata-only omits `includeTurns` | `thread` with `id`, `sessionId`, `cwd`, live `status`, empty `turns` metadata projection |
| `thread/turns/list` | `threadId`, optional `limit` and sort | Native page shape is documented; active-turn behavior remains unverified against a materialized real session |
| `thread/resume` | `threadId`; adapter requests `excludeTurns: true` | same effective fields as `thread/start` when native saved-session continuation is available |
| `turn/start` | `threadId`, `input` | `turn` with `id`, `status` |
| `turn/steer` | `threadId`, `expectedTurnId`, `input` | `turnId` |
| `turn/interrupt` | `threadId`, `turnId` | empty object receipt |

`turn/start` also accepts `model`, `effort`, and `clientUserMessageId`.
`Turn.status` is `inProgress`, `completed`, `interrupted`, or `failed`.
`ThreadStatus` is `notLoaded`, `idle`, `systemError`, or `active`; active
flags include `waitingOnApproval` and `waitingOnUserInput`.
`turn/completed` carries `threadId` and `turn`; `serverRequest/resolved`
carries `threadId` and `requestId`.

The generated 0.159.3 server-request shapes require `threadId`, `turnId` and
`itemId` for all four handled methods. Command, file and permission requests
also require `startedAtMs`; user-input requests require `isBlocking` and
`questions`. A response uses the server's exact string or int64 RPC `id` with
`result`: simple command/file `decision`, a `permissions` object, or a
question-ID keyed `answers` object. PodBay supports explicit simple decisions,
permissions deny-all (`{"permissions":{},"scope":"turn"}`), and exact
question-ID answer maps. Positive permission grants and command exec-policy or
network-policy amendments are explicitly unsupported in this slice.

The higher layer supplies an authorised answer permit bound to the complete
resource identity, current writer epoch, resource epoch, native thread/turn/item
and exact RPC request ID. The permit carries the answer bytes to be written;
the adapter validates their typed shape and writes at most one JSON-RPC result
frame. A write receipt is **not** native resolution. The request remains
pending until `serverRequest/resolved` and a later no-waiting native status
observation. Ambiguous writes remain uncertain and are never retried here.
Unsupported requests retain field names and encoded length as redacted
metadata; Debug formatting omits command, path, question and answer values.

PB10b turn control uses a local `WriterPermit` comparison over the complete
PodBay resource identity and a monotonically installed writer epoch. The
permit is supplied by an authenticated higher layer and is **not** durable
authority by itself. Every send or interrupt reads native thread state before
its turn RPC. The 0.159.3 path uses metadata-only `thread/read` for status.
`start_thread_without_turn` now returns the idle, unmaterialized native thread
after `thread/start` without sending `turn/start`. A fake transport test verifies
that this split writes no model input and leaves bootstrap NotStarted. It gives
the pod a checkpoint point for the native thread ID. The higher layer must
authorise and journal the thread-create intent before invoking it. No durable journal or
writer authority is supplied by this adapter method.
`submit_bootstrap_after_checkpoint` is the separate turn half. It checks a
caller-supplied `WriterPermit` against the installed local epoch, exact native
thread/session IDs and a fresh idle `thread/read` before one `turn/start`. A
lost or malformed reply returns an Uncertain receipt and blocks retry; a valid
in-progress reply retains the exact native turn ID for the pod journal. The
higher layer must fsync bootstrap intent before calling and fsync the receipt
afterward. The in-memory permit is not durable authority, and the adapter
cannot fence an uncontrolled external native writer on its own.
Idle chooses `turn/start`. An active turn permits `turn/steer` only when this
same adapter process owns the exact turn ID from its `turn/start` receipt and
the caller supplies that ID. Native `expectedTurnId` is the final compare-and-set
against a competing writer; a rejection blocks further input. Lifetime turn
history and its pagination do not gate steering. A cold resume with active
status has no locally owned turn ID and refuses. Native permission requests
remain pending and block new sends.
Every metadata-only read clears the reported observed turn ID because that
response contains no turn identity; it retains the separate local ownership
ID for the native compare-and-set.
`turn/interrupt` success is a request receipt; only a matching
`turn/completed` with `status: interrupted` settles it.

The adapter retains the exact most recent `clientUserMessageId` and refuses
its immediate reuse, including after an uncertain reply. It does **not**
deduplicate an older key after later submissions or across process restart.
PodBay's durable command ledger must provide caller-scoped idempotency before
turn control is exposed to a live provider.

`send_turn_after_checkpoint_checked` is an idle-only later-turn primitive. It
requires a local writer permit, the exact checkpointed native thread and
native Session IDs, a fresh metadata-only idle read, and a trusted read-only
preflight immediately before one `turn/start`. It returns the exact in-progress
turn ID or an uncertain attempted submission; an ambiguous reply poisons this
adapter instance. The separate pod-local `CodexLaterTurnJournal` anchors to a
fsynced BootstrapCompleted record and records multiple command keys, intents,
turn receipts, reported terminal notifications and fresh-idle settlement as
distinct facts. Neither primitive grants manager admission. A later store
version and authenticated pod control bridge are required before exposing
subsequent `session.send` to clients.

The pod-local `CodexCommandJournal` storage slice now records a fsynced
thread-create intent, exact native thread/session checkpoint, and separate
bootstrap intent, uncertain, submitted and completed facts. It uses bounded,
checksummed append frames through `DurableAppendLog`; a torn tail or unknown
transition refuses replay, and an intent without a receipt reopens as Unknown
without authorizing another RPC. This journal does not call Codex, authenticate
a writer, or prove a completion by itself. The future pod command bridge must
verify native completion and fresh idle state before recording that fact, and
must supply durable actor/writer authority before any turn is sent.

This is a codec and fake-transport slice. It does not launch Codex, make
approval decisions, or grant native permissions on its own. A native adapter
must reconcile a lost reply against the pod-owned process and hold a durable
native-session writer fence before submitting another turn or answer.

## Isolated 0.159.3 handshake probe

One disposable `codex app-server --listen stdio://` child ran with a fresh
temporary `HOME`, `CODEX_HOME` and empty config. No credentials were copied.
The only messages sent were `initialize` with `clientInfo`, `initialized` with
empty params, and read-only `model/list` with `limit: 5` and
`includeHidden: false`.

`initialize` returned `codexHome`, `platformFamily`, `platformOs` and
`userAgent`, all strings, matching the pinned handshake assumption.
`model/list` returned `data` (five entries) and `nextCursor`. Notifications
observed were `configWarning` and `remoteControl/status/changed`. Stderr
reported a Linux bubblewrap user-namespace requirement and a temporary
helper-binary warning. The child did not exit within three seconds of
SIGTERM, so it was SIGKILLed and reaped (exit code `-9`); the temporary home
was removed.

This probe establishes only the handshake and catalog response shapes. It
did not start, resume or read a thread; send a turn; exercise permissions;
verify account/model entitlement; or prove native lifecycle behavior.

The opt-in `isolated_real_app_server_handshake` fixture in
`tests/process_transport.rs` now repeats those same two RPCs through
`ProcessJsonlTransport` against an explicitly supplied absolute Codex 0.159.3
executable. It creates a fresh private HOME/CODEX_HOME, confirms the server
reports that CODEX_HOME, bounds notifications and I/O, and observes direct-child
reap. On 2026-10-04 it passed locally (one test, exit 0) with no credentials and
no thread or turn. Run it explicitly with
`PODBAY_CODEX_APP_SERVER_EXE=/absolute/path/to/codex cargo test -p podbay-adapter-codex --test process_transport isolated_real_app_server_handshake -- --ignored`.

The separate ignored `isolated_real_app_server_thread_start_without_turn`
fixture uses the same isolated, credential-free launch and checks only
`initialize` → `initialized` → `thread/start`. It requests `gpt-6-sol`,
`medium`, `never` approval and `danger-full-access` in a disposable empty
workspace, then verifies the returned thread ID/session, idle status, empty
turn list, cwd and effective selection. It sends **no** `turn/start` or model
input. Its first local run on 2026-10-04 passed every `thread/start` check but
then failed at an optional `thread/read` with RPC `-32601` and message
`list_turns is not supported yet`. The fixture no longer treats that
unsupported read as part of its thread-start gate. This does not establish
provider entitlement, a durable native writer, pod ownership, or turn success.
The focused rerun passed (one ignored test selected, exit 0), and the direct
child was reaped by the fixture's bounded disposal path.

An additional isolated no-turn probe against the same 0.159.3 binary found:
metadata-only `thread/read` returned the exact fresh thread as idle with
`turns=[]`; `thread/turns/list` returned RPC `-32600` because the thread was
not materialized before its first user message; `thread/resume` with
`excludeTurns: true` returned RPC `-32600` (`no rollout found for thread id`).
These are facts about an **unmaterialized no-turn thread**, not a verdict on
materialized session continuation or active-turn pagination. The focused
ignored probe asserts these results without sending a turn. The adapter no
longer requests unsupported full-history `thread/read`; it does not infer an
active turn ID from an empty metadata projection. This no-turn probe does not
establish whether `thread/turns/list` can reconcile active materialized sessions.

## Pod-side stdio transport boundary

The explicit child launcher takes a reviewed absolute executable, exact argv
and cwd, a private isolated HOME/CODEX_HOME, and a small allowlist of supplied
non-secret environment variables. It uses `Command` without a shell and
`env_clear`; no ambient account or HOME fallback is used. Linux and macOS use
nonblocking child pipes with bounded JSONL frames and finite per-frame I/O
deadlines. Other platforms refuse before spawn until a native bounded-pipe
backend exists. Timeout or disposal requests direct-child termination. After
a successful kill it waits up to three seconds for reap and reports an error
if reap is unobserved. Only a successful exit observation proves direct-child
reap; escaped-descendant containment is not established.

The current transport discards child stderr, limiting diagnostics. Its basic
birth timestamp is the parent's observation after spawn; a separate Linux
method rechecks PID/start ticks, boot ID and cgroup against `/proc` before
returning a point-in-time direct-child receipt. Neither value proves pod
membership or descendant containment. Fake child fixtures and isolated real
Codex probes have exercised this launcher; provider accounts, turn lifecycle
and pod ownership remain uncertified.
