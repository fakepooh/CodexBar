# v2.2.1: monotonic evidence admission

Frozen v2.2.0 fixed large-file extraction but replaced old selected evidence.
The post-generation audit found context regressions. Its files/hash/results are
preserved, and this separate correction reuses its discovery algorithm unchanged.

Universal rule: retain all original v2.1 source-page lines, completing any split
line from the identical historical blob. Block if that closure exceeds unchanged
hard limits. Then admit bounded novel ranges, never duplicating lines already
present in the complete diff or previous pages. Admission is still atomic by
candidate range; no clipped lines, JSON records or cumulative diff.

Dependency coverage is computed against actual exact diff + source-page union,
not presence of a file or an intended range. The independent verifier recomputes
baseline retention and exact line identity. No known finding, case ID, SHA,
repository name or defect explanation is used in discovery/admission rules.

This is a generic coverage non-regression guard, not proof that extra context
improves model recall. Unresolved lexical links remain PARTIAL. Review prompt,
findings schema, Auto routing, CLI 1.0.98, security/budget policies are unchanged.
