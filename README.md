# acl-audit

Broken-access-control hunting tool for authorized bug-bounty and GHSA work.

Point it at a cloned repository (and, for the proof lane, at two authenticated
sessions) and it reports where a user-controlled resource ID reaches a data
read or write without an ownership or permission check on the same value,
classified against a missing-authz taxonomy. The dynamic lane proves a hit by
replaying the same request as two identities: if identity B gets or changes
identity A's resource, that is the finding.

Status: **spec only**. Nothing is built yet. Read [docs/SPEC.md](docs/SPEC.md).

Not MCP-specific. MCP tool handlers are one adapter among Express/Next,
Django/DRF, Go handlers, axum extractors, and others. Sibling of
[mcp-ssrf-audit](https://github.com/beardthelion/mcp-ssrf-audit) (guard-completeness
for SSRF) and the IDOR/differential-replay sibling that
[dyetrace](https://github.com/beardthelion/dyetrace) deliberately left out of
scope.

Audience: the researcher auditing third-party apps and agent/MCP surfaces for
CWE-639 / CWE-284 / CWE-862 / confused-deputy findings that pay.
