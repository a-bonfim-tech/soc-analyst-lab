# Scope and publication governance

This is an educational SOC portfolio, not a production monitoring service. Test only systems and data for which you have authorization. Preserve evidence before remediation; keep raw sensitive material outside Git.

## Evidence states

- **REAL CONTROLLED LAB:** endpoint/tool-generated laboratory evidence, with provenance and collection limits. Not production incident evidence.
- **SYNTHETIC:** authored fixtures, expected outcomes and bounded local models.
- **TRAINING-DERIVED:** defensive methodology or reported exercise observations; identify the source and avoid proprietary solutions.
- **PLANNED / PENDING EXECUTION:** not demonstrated by retained evidence.
- **NOT VERIFIED:** a reported action lacks inspectable supporting output.

Each investigation should separate observed facts, interpretation, alternatives, conclusion, confidence and unknowns. Hashes establish byte consistency, not source authenticity. Rule parsing is not backend execution; ADX is not Sentinel; lab activity is not professional experience.

## Before publishing or changing visibility

Review the current tree, all reachable branches/tags and full history, including deleted content. Run an independent secret scanner; also inspect training-answer patterns, personal/confidential data, binary metadata, screenshots, PR/issues/comments and available Actions logs/artifacts. The repository validator is a limited heuristic, not approval to disclose.

Exclude secrets, credentials, session material, unsafe personal data, proprietary datasets, flags, challenge answers and walkthroughs that substitute for the original exercise. Prefer independently written defensive reasoning and reviewed derivatives. Attribute training sources; attribution alone does not grant redistribution rights.

If sensitive content is found, halt publication, assess whether credentials require revocation/rotation and determine historical reachability. Deleting the latest file is insufficient. History rewriting requires a separately reviewed decision; never force-push merely to hide an audit problem.

Use focused branches and PRs. Review changes and completed checks for the exact candidate commit. Do not reinterpret failed checks as passes or weaken controls to merge. Verify public accessibility and security settings after an authorized visibility change.

[Security reporting](../SECURITY.md) · [Reuse decision](REUSE.md) · [Reproduction](../REPRODUCE.md)
