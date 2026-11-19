# acl-audit

Design for a broken-access-control audit tool: find where a user-controlled resource ID reaches a data read or write without an ownership or permission check on that same ID, classify how the check is missing, and prove a hit by replaying the request as a second user.

**Status: spec only. There is no code in this repo yet.** Everything below describes the planned tool in [docs/SPEC.md](docs/SPEC.md). There is nothing to install or run.

## The problem

Insecure direct object references and missing authorization (CWE-639, CWE-284, CWE-862) include the confused-deputy case: an agent or MCP server holding broad credentials acts on whatever resource ID a caller or prompt hands it. Existing static rules mostly flag that a data sink exists; interactive proxies such as Burp Autorize test requests one at a time. The plan here is repo-first static classification plus a scripted two-identity proof.

## Planned design

Two lanes. Static finds and classifies; dynamic proves.

- **Static lane.** `scan <root>` looks for a request value used as a resource identifier that reaches a data sink (DB, ORM, object store, tenant files, API calls under ambient credentials) with no authorization check bound to the same identifier and the caller's identity in between.
- **Dynamic lane.** Given two authenticated sessions, replay the same request shape as identity B against identity A's resource. A hit is proven only when B reads or changes A's resource.
- **Adapters** for Express/Next, Django/DRF, Go handlers, axum and MCP tool handlers, in that rough build order.

Draft taxonomy of how the check is missing:

| Class | Name | Meaning |
|---|---|---|
| A0 | no check | Resource ID reaches a data sink with no authz call on the path |
| A1 | authn-only | Login required, but no ownership or permission check on the ID |
| A2 | wrong-object check | The check binds a different ID than the sink uses |
| A3 | check after use | Ownership check runs after the read or write |
| A4 | client-supplied owner | Owner or tenant taken from the request instead of the session |
| A5 | role without object | Role check with no per-object ACL |
| A6 | confused deputy | Ambient high-privilege credentials act on a caller-supplied ID |
| A7 | negative-path miss | Check on the read route but not on a mutating sibling |
| A8 | checklist | Cross-tenant list filters, mass assignment, GraphQL node IDs; hand review |

A site with a recognized complete check would be reported as `recognized_complete` for that taxonomy and ruleset version, never as plain "safe", and an unrecognized check shape as `unrecognized_guard`.

Planned output: a text report and `--json` with `findings[]` (A0 to A7, source, check and sink locations, optional dynamic verdict), `checklist[]` (A8) and a `coverage` block. Planned exit codes follow [mcp-ssrf-audit](https://github.com/beardthelion/mcp-ssrf-audit): `0` clean, `1` finding or unrecognized guard, `2` operational failure.

## Non-goals

- Not a runtime guard or proxy.
- Not authentication bypass, CSRF, or race hunting beyond the A3 static class.
- Not a claim of absence: unreported is not cleared.

## Related tools

- [mcp-ssrf-audit](https://github.com/beardthelion/mcp-ssrf-audit): the guard-completeness template this design copies, for SSRF
- [dyetrace](https://github.com/beardthelion/dyetrace): black-box tracer whose two-identity replay the dynamic lane plans to reuse; it leaves IDOR out of scope on purpose
- [autocatalytic-harness](https://github.com/beardthelion/autocatalytic-harness): the audit harness these tools plug into

## License

MIT. See [LICENSE](LICENSE).
