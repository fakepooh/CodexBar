# Public historical pilot: offline only

This package reconstructs ten exact public historical revisions and validates
their inert snapshots and prompt-review-v2.1.0 payloads. It never installs or
invokes an AI CLI, reads a credential, runs historical code or loads evaluator
ground truth. The credential helper is deliberately blocked in this export.

The frozen v2.0.0 and v2.1.0 source files remain byte-identical to their original
freeze manifests. Some inert runtime sources are included solely because those
manifests hash them. They are not workflow entry points. No source tree, prompt,
ground truth or credential is uploaded as an artifact or cache.

Run **Copilot public historical pilot v2.1 (offline only)** manually from Actions.
The final job log contains `COPILOT_PILOT_OFFLINE_RECEIPT=` followed by only exact
case identities, input hashes, sizes and PASS statuses. The receipt binds the
published commit and run ID. Passing offline tests does not demonstrate model
consumption or review quality.

The live job is hard-disabled and has no model command or credential. Its named
approval environment is a placeholder, not an existing approval guarantee. Any
future live stage needs separately authorized secure admission and isolated
runtime verification.

The ten revisions are clustered in three PRs and two repositories. Prior series
and evaluator-only overlap information are maintained outside this public export.
