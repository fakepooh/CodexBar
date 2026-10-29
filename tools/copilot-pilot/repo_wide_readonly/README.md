# Repo-wide readonly diagnostic

`repo-wide-readonly-v1.0.0`, currently **DRAFT, NOT FROZEN, NOT LIVE READY**.
This new diagnostic uses the existing ten PUB historical cases, not a blind
holdout. Previous frozen methods, results, consumed grants and the paused holdout
search are separate and unchanged. No local VM, Docker or Copilot runtime is used.

PR6 delivered SDK persistence/bootstrap and mock JSON/SSE corrections. Full
exact-head ARM64 CI passed before merge; source/tests/original CI are unchanged.
The main no-AI acceptance run 40892017029 passed 56 Python/19 Node tests, all ten
complete trees/diffs, readonly CLI/mock transport, sessionless authentication,
remote fixture CAS and independent recipient artifact recovery.

## Production admission

The production implementation must pass its OWN hosted shared-session acceptance
before freezing. Prior prototype success is not proof of this changed adapter.
`review-session.mjs` is shared by the real CLI/mock probe and live entry. It
initializes and inspects the actual offered tool metadata before send. Only the
three unique broker read/search tools are accepted. Wrong routing, missing tools,
additional native tools or an unproved limit fail before inference. It exposes
one initial prompt handoff and never resets that gate after an error.

A real run is manual-only, on main, by fakepooh/4489850, first workflow attempt.
The writer verifies frozen code/workflow hashes, fresh account Free/paid-off
admission, nonce/case/release binding and full non-draft CI for this exact release
or its actual merged candidate (never the old base). It claims one create-only
remote ref per PUB in the dedicated experiment namespace. The reviewer can only
read that ref; it has no contents-write permission. There are at most ten refs,
no deletion/reset/update, no rerun authorization and no application/session retry.
A reserved case stays reserved even after a pre-inference technical failure.

Fresh admission is supplied in the dedicated private Actions secret
`COPILOT_REPO_WIDE_ADMISSION`; the dispatch nonce alone is not authorization.
It contains version, case, nonce, workflow_sha, freeze_sha256, observed_at,
account, owner_id, copilot_free, additional_paid_usage, included_display,
unknown_allowance_exception, budget_exception_sha256 and ci_run_id. The observed
Billing state expires after one hour and is rechecked after preparation. No
numerical allowance is invented from percentages. The owner's explicit
2026-10-29 exception applies only to this new series, max10/one per PUB. General
10%/30% policy and previous grants are not changed or reused. A 30-credit SDK
session ceiling is SOFT, not a hard account limit or proof of included allowance.

## Historical context and isolation

Every tracked reviewed-head blob and the complete cumulative diff are verified.
A 512MiB whole-tree cap or 262144-byte prompt cap blocks the case, never selects a
subset or truncates data. The fixed private task, historical identity, output
schema and full diff form one initial prompt. Source exploration uses bounded
view/literal-grep/glob with explicit pagination; no evaluator-selected files.
Repository instructions, history, future fixes, evaluator data, other repositories
and host credentials are not mounted or discovered by the reviewing model.

The real CLI and credential-free broker run in a nonroot container with readonly
root/source, no capabilities, no-new-privileges, noexec temporary storage, no host
home/.git/Docker socket. An identical network-none OS probe passes before token
handoff. The live CLI needs network for the official service; there is no model
network tool. The token and prompt enter through stdin, never command arguments.
Only the trusted CLI child receives its token environment; broker/Git/Docker and
encryption subprocess environments exclude it. SDK empty mode, exact tool filters,
deny-by-default permissions/hooks, disabled config/custom instructions/MCP/agents
and disabled remote sessions/export remain enforced. No historical code executes.

## Evidence and limitations

Full output/events/tool results remain private and recipient-encrypted before
upload. A redacted host-owned checkpoint supports timeout recovery. Public logs
contain allowlisted status/identity/hash/count receipts only. Failed or malformed
outputs are preserved without repair turns or another session. Container cleanup
is proved. Only encrypted-review.json, identity.json and receipt.json upload.
The private RSA key never reaches GitHub. Output validation is strict and offline;
evaluator/ground truth is loaded in Work only after corresponding generation ends.

Raw supported usage and Auto routing events are retained for offline measurement.
Do not derive included AI Credits from request counts, rounded percentages or
undocumented conversions. Offline mock proof demonstrates transport and tool
callbacks, not GitHub backend receipt or actual model comprehension.

Freeze only after tests, real CLI/shared-session mock acceptance and independent
exact-head review. `freeze.py create` is create-only; subsequent implementation,
policy, schema, prompt hash or workflow drift blocks admission. A needed semantic
change after freeze requires another methodology version.
