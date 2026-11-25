# ADR-0001: Record architecture decisions with verification criteria

- **Status:** Proposed

## Context

Contributors need to know why Azuifer protects a behavior before they change it. Neither code nor an issue marked closed can explain all the rejected alternatives or show that a requirement is still true.

## Decision and scope

Record significant decisions under [this index](README.md). Find and link the existing decision before changing covered behavior; if none fits, open a proposal with explicit scope, alternatives, trade-offs, and observable exit criteria. Keep review status separate from implementation evidence. Reviewed decisions can be superseded, not silently rewritten. This covers architecture, protocol, persistence, security, distribution, and project-wide engineering constraints, not editorial corrections.

## Alternatives and consequences

Issue threads and PR descriptions are useful discussion records, but they are difficult to find from a checkout. Requiring a new ADR per patch would bury the decisions under duplicates. Reusing an ADR within its scope keeps the records useful at the cost of a small upfront review step.

## Verification criteria

- The public checkout links from its entry docs to the ADR index, numbered records, and template; all of those links resolve.
- For an implementation governed by a record, a reviewer can identify the invariant and run or inspect the evidence linked from the change. No status label is used as a substitute for that evidence.
