# Host validation correction 1.0.1

Offline-only correction alongside immutable repo-wide-readonly-v1.0.0. No model entrypoint, workflow dispatch or guard mutation. Original workflow conclusions remain unchanged.

Original host passes only view/grep paths, although the approved task permits inspected_paths from diff OR tools. This wrapper verifies canonical initial-input and artifact hashes, strict snapshot and session binding, and textual hunk completeness, then invokes the unchanged output schema validator with both supplied channels.

Missing/redacted tool events add no paths. Inventory/glob alone is never source delivery. Unverified base citations fail closed. No output repair, fuzzy matching or credential recovery. Caller must obtain expected artifact hash/session/binding from independently retained authenticated run receipts, not from an untrusted result itself. Byte hashes do not authenticate an attacker-controlled replacement manifest.

Run synthetic tests with PYTHONPATH=tools/copilot-pilot python3 -m unittest host_validation_v1_0_1.test_validate.

This does not patch the frozen live workflow or retroactively turn its FAIL into success. Before any future live run a separately authorized non-frozen orchestration would have to call this correction; no live authorization is provided here.
