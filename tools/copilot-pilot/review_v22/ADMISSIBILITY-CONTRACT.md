# Ground Truth Admissibility Contract 1.0.0

Evaluator-only. Never imported by context selection or included in reviewer input.
This creates a new evaluation specification; original references and historical
v2.1.0 denominators/results remain immutable.

Separate three questions: does the defect exist; is it an admissible new-regression
reference at the exact reviewed SHA; is sufficient evidence present in a specific
reviewer input? Model detection is a fourth, later, independently scored question.
Machine checks bind identities, explicit adjudication and evidence hashes. They
do not establish semantic truth from an authenticated historical comment.

Every record binds exact distinct base/reviewed SHA, original source blob/range/
content hashes, causal reasoning, adjudicator, reproduction conditions and static
proof or observed reproduction, configuration/default assumptions, independently
reasoned severity and deduplication. Source evidence must be from base/reviewed
history; subsequent fixes are not causal proof. For a pre-existing determination,
record the equivalent base behavior separately, not just matching changed lines.
A static proof may establish a language-level path without executing historical
code; device/service assumptions remain conditional or indeterminate.

Statuses:

- ADMISSIBLE: defect supported at head, introduced by change, confirmed default
  assumptions, explicit reproducible causal proof and justified severity.
- CONDITIONAL: same requirements, but only in a confirmed specified configuration.
  Report separately; do not quietly include in a default-configuration denominator.
- PRE_EXISTING: supported at head but behavior already present before the change;
  exclude from new-regression denominator, retain as a separate truth record.
- INVALID: refuted defect or duplicate manifestation (link canonical record).
- INDETERMINATE: missing/contradictory introduction, conditions, causal proof,
  configuration, contract authority or severity. Historical reviewer authority
  alone does not resolve uncertainty.

Truth, introduction, severity and visibility remain separate fields, even if a
single admissibility status is required for aggregation. Missing/invalid hash,
revision or line identity is a validator error, not a fabricated classification.
Visibility is computed only after input generation by independently matching
necessary facts against exact diff/pages. Partial visibility is never treated as
truth refutation. Excluded references remain visible in sensitivity tables.

Scoring (future, no model scoring): pre-register admissible and conditional
strata, P1/P2 denominators, semantic trigger/root-cause/actionability matching,
duplicate handling, unsupported findings and clean-control false positives.
Do not retroactively alter published v2.1.0 recall. Development PUB examples are
engineering diagnostics, not independent holdout quality measurements.
