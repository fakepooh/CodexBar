# Changes relative to frozen v2.1.0

1. Replace whole-file transport admission with bounded containing-function and
   logical ranges. This directly addresses file-size rejection and prefix-page
   loss, without increasing the 262,144-byte input ceiling.
2. Expose forward/reverse/state/config candidate edges, ambiguity and missing
   context. Depth increases from two file hops to three structural-range hops;
   this is a different search unit, not a controlled depth-only comparison.
3. Pack whole ranges, with original line numbers encoded before size checks.
   Pages grow from 2,000 to 4,000 bytes and count cap from 40 to 256. The prompt
   ceiling still dominates. Never silently truncate a function range, line or diff.
4. Explicit changed-containing base ranges follow head seeds to audit removed
   guards and preconditions. Base expansion remains restricted and disclosed.
5. Separate coverage receipt and evaluator-only admissibility. Complete static
   candidate coverage is distinct from semantic completeness and model attention.
6. Keep review instructions, findings schema, pinned CLI 1.0.98, Auto flags,
   tool denial, read-only container and credential-frame mechanism unchanged.
   Only evidence selection/metadata and transport page capacities change.
7. No live entry, authorization issuance, budget update or model invocation in
   public offline workflow. Old freezes/results/guards are neither imported as
   new authorization nor modified.

This is an engineering intervention informed by RCA mechanisms, not proof of
better review recall. Same-case controlled diagnostics and independent curated
holdouts are separate subsequent experiments. v2.1.0 outcomes stay immutable.

Generic module-stem key references bridge string/enum registrations across files
and languages. Behavioral code/config ranges precede test/document supplements;
all such links remain bounded lexical candidates with explicit uncertainty.
