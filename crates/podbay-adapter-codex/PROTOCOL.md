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

`turn/start` also accepts `model`, `effort`, and `clientUserMessageId`.
`Turn.status` is `inProgress`, `completed`, `interrupted`, or `failed`.
`ThreadStatus` is `notLoaded`, `idle`, `systemError`, or `active`; active
flags include `waitingOnApproval` and `waitingOnUserInput`.
`turn/completed` carries `threadId` and `turn`; `serverRequest/resolved`
carries `threadId` and `requestId`.

This is a codec and fake-transport slice. It neither launches Codex nor
answers native permission requests. A native adapter must reconcile a lost
reply against the pod-owned process and hold a durable native-session writer
fence before submitting another turn.
