# Context Completeness Contract 1.0.0

Scope: reproducible *static candidate coverage* of exact historical base/head,
not proof that all semantic dependencies of a program have been discovered.
A caller, config consumer or virtual target may be dynamically linked. Such
uncertainty must never be promoted to semantic completeness.

Inputs: a sealed, SHA-256-indexed inert snapshot, full Git blob identities,
exact base/head SHA and complete cumulative diff. No checkout execution, PR
comments, expected findings, future revisions, evaluator data or ambient files.
All UTF-8 source text is indexed within explicit scan limits. Symlinks,
submodules, binary, unsupported formats and scan-limit exclusions are explicit.

Selection rules, in deterministic order:

1. Parse exact changed line coordinates on both historical sides. Deliver
   containing declaration ranges on head; changed containing base ranges follow.
   Behavioral code and structured config precede supplemental documentation;
   changed documentation remains fully present in the complete diff.
   Complete removed/added lines always remain in the unmodified cumulative diff.
2. Python AST declaration extents; conservative offset-preserving brace matching
   for brace languages; deterministic logical ranges for other supported text.
   Strings/comments are masked for matching only; delivered source stays exact.
   Scanner uncertainty (macros, interpolation, generated/dynamic calls) is declared.
3. Breadth-first forward named calls and reverse symbol references; all candidate
   definitions retained for ambiguity, never pick a convenient overload.
4. Named property declarations, self/this member access, getter/setter bodies and
   reference consumers create state-transition candidates across files.
5. Type/interface declarations and their reference sites create implementation
   and consumer candidates. This is lexical linking, not a compiler type proof.
6. Identifiers shared with structured configuration keys create defaults/override
   candidates. Named constants create normal reverse/forward symbol candidates.
   Config-key extraction is explicitly bounded and may not infer external defaults.
7. Error, recovery, timeout and cancellation bodies are included through the same
   call/state rules, without defect-specific keywords or handpicked known paths.
8. Continue to depth 3; retain unresolved, ambiguous, fanout, depth, unit and edge
   limits in the receipt. Do not interpret a missing edge as proven irrelevance.

Large declarations are partitioned into consecutive ranges of at most 160 lines,
with original parent extent and partial-parent flags. Related parent ranges are
explicit candidates. Large files are never charged in full against transport
before extracting ranges. A scan cap (8 MiB/file, 64 MiB aggregate) is distinct
from transport and explicitly reported; no semantic claim can cross that cap.
Transport admits whole ranges or omits them with reasons, never clips lines,
fragments, complete diff, JSON records or source identities. JSONL fragments
retain exact line and part ordinal. Page size is 4,000 bytes including original line-number metadata. At most 256 pages, 262,144-byte prompt,
196,608-byte complete diff, 512 units, 4,096 edges, 24 candidates/symbol.

Receipt: contract/methodology/case/input/diff/prompt identity; each selected
path/side/range/parent/reason/depth/origin; page SHA/blob SHA/source SHA; every
candidate edge and its resolution, delivered targets, every omission and reason;
scan/transport limits, sizes and explicit semantic_completeness=false.
SCOPED_STATIC_CLOSURE means only the selected static search scope closed without
an unresolved candidate or budget omission. PARTIAL is expected in real projects.
Neither status proves semantic completeness or model attention. Base dependency
expansion is deliberately restricted to changed containing ranges; this is also
reported rather than presented as a complete base call graph.

Acceptance: independently re-read sealed historical blobs; verify every selected
line and fragment, page ordering, exact complete diff, hashes and range receipt;
reject missing/reordered/truncated/unreceipted content. Authenticate local transport
separately from telemetry. Offline transport never proves backend delivery,
model inspection, understanding or correctness. A partial input cannot support
an unqualified conclusion about a missing dependency.
