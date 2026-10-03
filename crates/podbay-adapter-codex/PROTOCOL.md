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
| `thread/read` | `threadId` | `thread` with `id`, `sessionId`, `cwd`, `status`, `turns` |
| `thread/resume` | `threadId` | same effective fields as `thread/start` |
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
its turn RPC. Idle chooses `turn/start`; an active turn permits `turn/steer`
only when its ID matches both the locally owned turn and the caller's exact
expected ID. Native permission requests remain pending and block new sends.
`turn/interrupt` success is a request receipt; only a matching
`turn/completed` with `status: interrupted` settles it.

The adapter retains the exact most recent `clientUserMessageId` and refuses
its immediate reuse, including after an uncertain reply. It does **not**
deduplicate an older key after later submissions or across process restart.
PodBay's durable command ledger must provide caller-scoped idempotency before
turn control is exposed to a live provider.

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

The current transport discards child stderr, limiting diagnostics. Its child
birth timestamp is the parent's observation after spawn, not an OS process
start identity or ownership attestation. Only a disposable fake child has
exercised this launcher; real Codex, provider accounts and session lifecycle
remain uncertified.
