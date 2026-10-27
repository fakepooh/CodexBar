# Repo-wide readonly diagnostic candidate

This is the new `repo-wide-readonly-v1.0.0` namespace, not a modification of
frozen prompt-review v2.0.0, v2.1.0, v2.2.0 or v2.2.1. Status: **DRAFT,
NOT FROZEN, NOT LIVE READY**. No live entry point is enabled.

## Publication and execution are separate

PR 5 delivered the initial preparation foundation. Required ARM64 CI passed;
the existing application Sources, Tests and CI configuration are unchanged.
The first manual hosted run passed infrastructure tests but stopped in the
SDK constructor: empty mode requires an explicit persistence location even
when COPILOT_HOME is set. The shared client-options helper and constructor-only
tests correct this without starting a runtime, changing CLI version or adding
model permissions. Hosted authentication is still unproved until the next run.

This follow-up package adds the native isolation, historical snapshot, remote
CAS and encrypted recovery acceptance path. Local deterministic tests are not
presented as hosted proof. Existing CI and merge protections remain required.

## Source access

`snapshot.py` reconstructs every tracked blob at the exact reviewed commit,
with complete cumulative binary-capable diff and provenance. It never checks
out or executes historical code. Symlinks are inert bytes. A 512 MiB total-tree
limit blocks the entire case rather than removing source files.

`broker.py` exposes literal search, wildcard path listing and bounded exact
source reads, including explicit continuation cursors and base64 binary reads.
`sdk-tools.mjs` registers only unique `repo_view`, `repo_grep`, `repo_glob`
custom tools. Missing registration cannot fall back to native filesystem tools.
Native shell/read/write/delegation/network/memory tools are unavailable.
Model tool callbacks go to a separate credential-free network-none broker.
This Python broker alone is not the OS boundary: actual hosted Docker mounts,
UID/capabilities and isolation proof remain mandatory.

`native-probe.mjs` and `hosted_offline.py` prepare a credential-free real CLI
1.0.98 to local mock proof, including exact tool-result transport, large output,
blocked host path and finite stage deadlines. They have not run hosted yet.
No local Docker, VM or CLI execution is permitted for this experiment.
The workflow delivery template is manual-only and contains no live model route.

## Authentication, guards and evidence

`auth-preflight.mjs` performs sessionless hosted authentication only. It does
not establish available included allowance, Free plan, paid-off status or live
admissibility by itself. Actual hosted authentication remains unverified.
Empty-mode persistence is explicit in a fresh temporary home; diagnostics name
only the failed stage and never print raw exceptions or authentication responses.

`reservations.py` defines strict typed one-shot identities. `ledger.py` uses
create-only annotated Git refs, authenticated exact API endpoints, verified TLS,
no redirects and no mutation retries. Reviewer jobs must have no contents-write
permission. Actual remote CAS/rerun integration has not been proved.

`seal.mjs` uses recipient-only RSA4096/AES256-GCM encryption. Only the public
recipient may reach Actions. The exact approved generic prompt and public
recipient were provisioned in dedicated Actions secrets; the private key remains
in Work. `seal-file.mjs` pins the public recipient fingerprint. Actual hosted
artifact download/decryption validation is still required.

No old grant is reused. The new ten-case authorization is unconsumed. No live
sessions or reservations have been created. The numerical included AI Credit
allowance is unknown; no global budget policy or threshold was changed.
