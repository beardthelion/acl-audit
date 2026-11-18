# acl-audit: Spec

Status: draft v0.1, 2026-10-27. Spec only; nothing built. Owner: beardthelion.

Hunting tool for bug bounties and GHSAs. Not a product, not a paid audit, not
a runtime guard. Analog of `mcp-ssrf-audit` for broken access control.

## 1. Gap check (why this repo exists)

Checked against the existing tools before creating anything.

| Tool | Path | What it does for ACL | Verdict |
|---|---|---|---|
| jevsec | jevsec repo | Call-graph + taint to sinks. `"auth"` is a **sink class** (reaching `authorize`/`checkPermission` is an auth-bypass candidate). `auth-middleware` / `privilege` are **boundary markings**, not required guards. Sanitizer list is escape/sanitize/quote only (`src/candidates/sanitizers.ts`). No model of "resource ID reaches data R/W without an ownership check on the same value." | Reusable engine; does **not** detect missing authz |
| dyetrace | [beardthelion/dyetrace](https://github.com/beardthelion/dyetrace) | Plants tracers, watches where they resurface. Second identity exists for **cross-context data leak** of planted content. SPEC.md §Out of scope: *"Race conditions and IDOR enumeration. Those are sibling tools (differential replay, race harness)."* | Explicitly outsopes IDOR; replay engine reusable |
| mcp-ssrf-audit | [beardthelion/mcp-ssrf-audit](https://github.com/beardthelion/mcp-ssrf-audit) | Guard-completeness taxonomy (G0–G10) for SSRF in MCP handlers. Exact architectural template. | Template only; SSRF not ACL |
| egress-plane | [beardthelion/egress-plane](https://github.com/beardthelion/egress-plane) | Maps egress sites. No authz. | Irrelevant |

**Decision: PARTIAL.** Reusable pieces exist (jevsec map/taint, dyetrace
replay + two-identity clients, mcp-ssrf classify/runner/corpus shape). No
existing tool detects or proves authorization bugs of the shape this repo
targets. Creating `acl-audit` is the right move; extending jevsec alone would
force a different finding model (required-guard-on-path vs. sink-reached) into
a tool whose `"auth"` sinks mean the opposite.

Citations (source at write time):

- `jevsec/src/map/types.ts` — `SinkClass` includes `"auth"`; `BoundaryKind`
  includes `"auth-middleware"` / `"privilege"`.
- `jevsec/src/map/detect.ts` — `authorize`, `checkPermission`, `hasPermission`,
  etc. registered as **sinks**; `AUTH_MIDDLEWARE_RE` marks boundaries.
- `jevsec/src/candidates/sanitizers.ts` — no ownership/permission names.
- `jevsec/rubrics/severity.md` — "auth-check sinks score on what skipping the
  check exposes" (bypass framing).
- `dyetrace/SPEC.md` — out-of-scope IDOR; cross-context = planted-tracer leak
  under a second identity, not resource-ID swap.
- `dyetrace/src/dyetrace/propagate.py`, `cli.py --second-session` — identity-2
  replay infrastructure to reuse.

## 2. Threat model (two sentences)

A request names a resource by an attacker-chosen ID (repo, org, tenant, file,
row, tool argument). The handler reads or writes that resource using ambient
credentials (session, service account, agent token) without checking that the
caller owns or may access it. Result: IDOR / broken access control (CWE-639,
CWE-284, CWE-862), including the confused-deputy case where an agent holds
broad credentials and acts on whatever ID a prompt hands it.

## 3. What a finding is

A site is a candidate when all of the following hold:

1. A user-controlled value (path param, query, body field, MCP tool arg,
   header) is used as a **resource identifier**.
2. That identifier reaches a **data sink**: DB read/write, object-store
   get/put/delete, filesystem read/write of tenant data, ORM
   `findById`/`get`/`update`/`destroy`, API call that fetches or mutates a
   named resource under ambient credentials.
3. No **authorization check bound to the same identifier** (and to the
   caller's identity) intervenes on the path before the sink.

A candidate becomes a **proven finding** only when the dynamic lane shows
identity B obtaining or mutating identity A's resource through the same
request shape.

A site with a recognized complete check is reported as
`recognized_complete` (scoped to taxonomy + ruleset version), never as an
unqualified "safe." An unrecognized check shape is `unrecognized_guard`,
never silent.

## 4. Taxonomy (A0–A8, draft)

Modeled on mcp-ssrf-audit's G0–G10: classify *how* the check is missing or
weak, not merely whether a sink exists. Sink detection alone is claimed
territory (Semgrep `security-audit`, CodeQL `MissingAuth*`, Burp Autorize /
AuthMatrix for dynamic). Novelty is the incomplete-check taxonomy plus the
two-identity proof gate.

| Class | Name | Meaning |
|---|---|---|
| A0 | no check | Resource ID reaches data sink; no authz call on the path |
| A1 | authn-only | Authentication present (`requireAuth`, session gate); no ownership/permission check on the resource ID |
| A2 | wrong-object check | Check binds a *different* ID (e.g. checks `req.user.id` equals itself, or checks org while fetching by `projectId`) |
| A3 | check after use | Ownership check runs after the read/write (TOCTOU / leak-then-deny) |
| A4 | client-supplied owner | Owner/tenant taken from request body/header instead of from the session (`body.userId`, `X-Tenant-Id`) |
| A5 | role without object | Role/scope check (`isAdmin`, `hasRole('user')`) with no per-object ACL |
| A6 | confused deputy | Ambient high-privilege credentials (service account, agent token, MCP server token) act on a caller-supplied resource ID with no caller-binding |
| A7 | negative-path miss | Check present on GET/read but absent on mutating sibling (PUT/PATCH/DELETE), or present on one route of a resource family |
| A8 | checklist | Cross-tenant list/search filters, mass-assignment of permission fields, GraphQL node ID authz — need hand review |

Precedence at a site (same idea as mcp-ssrf classify): deterministic weak
class (A1–A7) > A0 > unrecognized_guard > recognized_complete. A8 is
checklist-only, never auto-deterministic.

"Complete" means: the check (a) takes the same resource identifier the sink
uses, (b) takes the caller's authenticated identity from the session/token
(not from the request body), (c) denies before the sink runs, (d) covers every
method/entry that reaches that sink.

## 5. Architecture

Two lanes. Static finds and classifies; dynamic proves. Neither alone is a
submission.

### 5.1 Static lane (guard-completeness)

Shape copied from mcp-ssrf-audit:

```
scan <root>
  → runner (Semgrep taint / jevsec graph adapters)
  → classify (A0–A8 resolution per site)
  → report (text + versioned JSON)
```

Per language/framework **adapter** registers:

- **Sources**: request params that look like resource IDs
  (`:id`, `pk`, `uuid`, `*Id`, `*Slug`, MCP tool args named like resources).
- **Sinks**: data read/write call shapes (ORM get/update/delete, SQL with ID
  bind, S3/GCS get/put, `fs` under tenant paths, outbound API calls that
  fetch a named resource with ambient creds).
- **Complete checks**: known-good call shapes that bind (resource ID,
  caller identity) — Express/Next middleware + explicit
  `assertCan(user, resource)`, Django/DRF permission classes +
  `get_object` ownership, Go handler helpers, axum extractors, MCP tool
  handlers that compare `context.user` to resource owner.

Adapters (v0 order):

1. TypeScript/JavaScript — Express, Next.js route handlers, Fastify
2. Python — Django, DRF, FastAPI
3. Go — net/http, chi, echo handlers
4. Rust — axum extractors
5. MCP / agent-tool handlers (Python + TS) — confused-deputy A6 focus

v0 ships adapters 1 and 5. 2–4 follow once the classify/report loop is
stable. Semgrep CE taint is intra-function/intra-file (same limit as
mcp-ssrf-audit); helper-factored checks resolve to `unrecognized_guard`.
Where jevsec's call graph already covers the language, an optional
`--backend jevsec` path can feed candidates into the same classify step
(resource-ID source → data sink, then ask "is there an authz check on this
path bound to the same value?"). That is an adapter over jevsec, not a
fork of it.

### 5.2 Dynamic lane (two-identity differential replay)

The sibling dyetrace named and left out.

Inputs:

- Session A and session B JSON (cookies + auth headers + base URL), same
  shape dyetrace uses (`--session`, `--second-session`).
- Optional: static candidates (`candidates.json` from the static lane or
  from jevsec), mapping each to a recorded request + the resource-ID
  field to swap.

Procedure:

1. Record or accept a HAR/session of identity A exercising resource
   endpoints.
2. For each candidate request that carries a resource ID owned by A,
   replay it as identity B with A's resource ID substituted (and the
   inverse: A's session with B's ID).
3. Verdict per candidate:
   - `PROVEN` — B receives A's resource body, or a mutating replay as B
     changes A's resource (confirmed by a follow-up read as A).
   - `DENIED` — B gets 401/403/404 consistently; not a finding.
   - `INCONCLUSIVE` — redirect to login, CAPTCHA, rate limit, or response
     identical for unrelated reasons; needs hand review.
   - `unexercised` — request never reached the handler.

Reuse from dyetrace without forking its threat model: `IdentityClient`
(`src/dyetrace/net.py`), session schema, allowlist/rate-limit/fail-closed
rules, HAR → session helper. Do **not** plant tracers; this lane swaps
identifiers, it does not dye content.

Gate: a static A0–A7 without a `PROVEN` dynamic verdict is a lead, not a
submission. Match the jevsec/dyetrace "proof or it did not happen" bar.

### 5.3 Confused-deputy adapter (MCP / agent)

Special case of A6, not a separate product:

- Source: tool-handler argument that names a resource (repo, file path,
  tenant, URL-of-resource, mailbox id).
- Sink: call made with the **server's** or **agent's** credentials
  (GitHub App token, cloud role, DB pool user).
- Complete check: tool explicitly binds the resource to the invoking
  user's identity before the privileged call (e.g. compares
  `context.auth.user` to resource owner, or uses a user-scoped token
  minted for that call).

This is where "like mcp-ssrf-audit but for ACL" is literal: same handler
registration shapes mcp-ssrf already knows, different sink and check
model.

## 6. Non-goals

- Not a runtime guard or proxy that blocks tool calls in production.
  Hunting tool only.
- Not authentication-bypass hunting (credential stuffing, JWT alg=none,
  session fixation). Adjacent; out of scope.
- Not CSRF, and not race/TOCTOU beyond the A3 "check after use" static
  class.
- Not a replacement for Burp Autorize / AuthMatrix / Autorepeater. Those
  are interactive. This is repo-first static + scripted two-identity
  proof.
- Not a claim of absence. Unreported is not cleared.
- Not MCP-only. MCP is one adapter.

## 7. Output

Text report (default) and `--json` with:

- `schema_version`: `acl-audit/v1`
- `taxonomy_version`: `a0-a8/v1`
- `ruleset_version`, tool version, target
- `findings[]`: deterministic A0–A7 with file:line for source, check (or
  absence), sink; optional `dynamic_verdict`
- `checklist[]`: A8 items
- `coverage`: files scanned per language, handlers recognized, sinks
  inside/outside handlers, unrecognized guards, per-state counts

Exit codes mirror mcp-ssrf-audit: `0` clean/checklist-only, `1` at least
one deterministic finding or unrecognized guard, `2` operational failure
including `analysis_incomplete`.

## 8. Corpus and gating

Ship a corpus of minimal fixtures per class per adapter language, same
contract as mcp-ssrf-audit's `corpus/`: each fixture declares expected
classes; CI fails on miss or misclassified-extra. Include:

- A0 unguarded `getById`
- A1 authn-only
- A2 wrong-object check
- A4 client-supplied owner
- A6 MCP confused deputy (server token + user-supplied repo id)
- A recognized-complete positive (must not alert)
- A benign lookalike (ID used only for logging)

Dynamic fixtures: a tiny loopback app with two users and one resource;
the lane must return `PROVEN` on the unguarded route and `DENIED` on the
guarded one.

## 9. Build order

1. Taxonomy + JSON schema + report renderer (no rules yet).
2. TypeScript Express/Next adapter: A0, A1, A4, A5 deterministic rules
   on Semgrep CE taint; corpus green.
3. MCP/agent adapter: A6; reuse mcp-ssrf handler-registration source
   shapes.
4. Dynamic lane v0: two-session differential replay against loopback
   fixtures; wire `dynamic_verdict` onto static findings.
5. Python Django/DRF adapter.
6. Optional `--backend jevsec` candidate ingest.
7. Go and Rust adapters.

Do not ship a public PyPI/npm package until the corpus gate is green on
adapters 1 and 3 and the dynamic lane has a `PROVEN`/`DENIED` pair on
fixtures. Private repo until then.

## 10. Relationship to siblings

| Sibling | Relationship |
|---|---|
| mcp-ssrf-audit | Architectural template (classify / runner / corpus / taxonomy). Different threat model. |
| jevsec | Optional static backend for multi-language graphs. Do not overload its `"auth"` sink class. |
| dyetrace | Replay and two-identity client reuse. Its cross-context tracer leak stays its finding; IDOR stays ours. |
| egress-plane | Unrelated. |

## 11. Open questions

- Exact Semgrep vs. jevsec-graph split for v0: prefer Semgrep-only for
  adapters 1 and 3 to ship faster, jevsec later?
- Should A3 (check after use) require intra-procedural ordering evidence
  only, or also inter-procedural?
- Naming of the dynamic CLI: `acl-audit prove` subcommand vs. a separate
  `acl-replay` binary that shares the session schema with dyetrace?
- Public vs. private corpus of real advisory reconstructions (mcp-ssrf
  keeps a corpus; same question here for A6 MCP cases).

Resolve during build, not in this draft.
