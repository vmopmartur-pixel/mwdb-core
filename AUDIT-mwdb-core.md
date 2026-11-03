# mwdb-core — Defensive Source-Code Security Audit

**Target:** CERT Polska mwdb-core (local clone, branch `claude/mwdb-core-security-audit-12425p`)
**Type:** Static source review (no third-party/production systems touched)
**Date:** 2026-11-03
**Scope:** Backend (Flask/SQLAlchemy/Marshmallow), React/TS frontend, search parser, ACL/sharing, auth, OIDC, file handling, remotes, config/deployment.

---

## 0. Bounty-scope reassessment (NASK PIB / CERT.pl program)

After re-reading the published program scope, most of the original findings fall into **explicitly excluded** or **informational** buckets. Honest mapping:

| # | Finding | Program scope verdict |
|---|---------|----------------------|
| F1 | `/config/stats` cross-group family metadata | **Borderline.** Could be argued under §3.3 (mass read of system data across the isolation boundary), but the review team may dismiss it under exclusion §2.3 "metadata/public-data leak". Submit, expect **low/informational**. |
| F2 | Expensive-query DoS | **Excluded.** §10.1 "all forms of DoS are prohibited", §10.2 load testing. Do not submit. |
| F3 | User enumeration + weak brute-force protection | **Excluded.** §2.2 user enumeration, §10.3 missing rate-limiting without an account-takeover path. Do not submit. |
| F4 | `UserPendingResource` missing `@requires_authorization` (→500) | **Excluded/low.** Not an auth bypass (no state change, no data read); degrades to 500. At best §11.2 informational. |
| F5 | `GroupMemberResource.delete` ordering (→500) | **Excluded.** No privilege escalation; pure 500/robustness. |
| F6 | Peer email + last-login via `/profile/<login>` | **Low.** Email is PII (§3.1), but access requires sharing a workspace group with the victim and is arguably intended. Submit only as **low**, strongest if a community/multi-org workspace group exists. |
| F7 | Missing `nosniff` on downloads | **Excluded.** §3.1 missing security headers. |

**Verdict against the rewarded classes** (RCE, account takeover, IDOR/broken access control to other users' private data, privilege escalation, SQLi, SSRF, SSTI, XSS, file-upload→RCE, mass assignment, XXE, CORS-with-data-theft, path traversal): by **static review of this version I did not find a clearly-rewardable vulnerability.** The sensitive surfaces are hardened (see §4). Reaching a payout-grade bug on this target most likely requires **dynamic testing** against a live instance with specific group/sharing/plugin/OIDC configuration — which is out of scope for this static review. §8 lists where that effort should focus.

---

## 1. Executive summary

mwdb-core is a **mature, well-hardened** codebase. The areas that are classically the most dangerous for this kind of application — the custom Lucene→SQL search parser, the rich-attribute Markdown renderer, object access control, JWT handling, and file storage — have all clearly been hardened in response to earlier bug classes and held up under review. I did **not** find SQL injection, jsonpath injection, stored/reflected XSS, path traversal, authentication bypass, JWT forgery, or arbitrary cross-group object read.

The findings below are therefore mostly **medium/low**: one genuine cross-sharing-group metadata disclosure, a cluster of error-handling/ordering bugs that degrade to HTTP 500 (DoS-ish, not auth bypass), weak-by-default anti-automation on authentication, and some defense-in-depth gaps. Several are **configuration-dependent** (rate limiting and statement timeout are off by default).

| # | Title | Severity | Confidence |
|---|-------|----------|------------|
| F1 | Config family statistics leak across sharing groups (missing ACL filter) | Medium | Confirmed |
| F2 | Unbounded/expensive search queries + no statement timeout by default → DoS | Medium | Likely |
| F3 | Account/username enumeration + weak default brute-force protection on auth | Low–Medium | Confirmed |
| F4 | `UserPendingResource` missing `@requires_authorization` → 500 + None deref | Low | Confirmed |
| F5 | `GroupMemberResource.delete` auth-check / existence-check ordering → 500 | Low | Confirmed |
| F6 | User email & last-login disclosed to any same-group member | Low | Confirmed |
| F7 | Download responses lack `X-Content-Type-Options: nosniff` (defense-in-depth) | Info/Low | Confirmed |

---

## 2. Endpoint authorization matrix (selected / security-relevant)

Resolution of `g.auth_user`: `mwdb/app.py:202 require_auth()` sets `g.auth_user` from a Bearer token (session JWT → API-key JWT → legacy JWT), else `None`. Disabled/maintenance checks applied there.

| Endpoint | Method | Auth decorator | Capability | ACL on object | Notes |
|---|---|---|---|---|---|
| `/auth/login` | POST | public | — | — | password check |
| `/auth/register` | POST | public | — | — | gated by `enable_registration` |
| `/auth/recover_password` | POST | public | — | — | needs `manage_profile` on target |
| `/auth/change_password` | POST | public | — | — | set-password token |
| `/object`, `/<type>` | GET | `requires_authorization` | — | **yes** (`has_access_to_object`) | search + list |
| `/<type>/count` | GET | `requires_authorization` | — | **yes** | |
| `/config/stats` | GET | `requires_authorization` | — | **NO** | **F1** |
| `/object/<id>` | GET | `requires_authorization` | — | `Object.access` | |
| `/<type>/<id>/comment` | GET/POST | auth (+`adding_comments`) | — | `access_object` | |
| `/<type>/<id>/share` | GET/PUT | `requires_authorization` | — | `access_object` + group membership | |
| `/<type>/<id>/attribute` | GET/POST | `requires_authorization` | per-key perms | `access_object` | hidden gated by `reading_all_attributes` |
| `/file/<id>/download` | GET | token OR auth+`downloading_files` | — | token bound to hash, or `File.access` | |
| `/search` | POST | `requires_authorization` | — | **yes** | deprecated |
| `/user/<login>/pending` | POST/DELETE | **`requires_capabilities` only** | `manage_users` | — | **F4** (missing `requires_authorization`) |
| `/user/<login>` | GET/POST/PUT/DELETE | auth + `manage_users` | `manage_users` | — | |
| `/profile/<login>` | GET | `requires_authorization` | — | same-group filter | **F6** schema leak |
| `/group/<name>` | PUT/DELETE/POST | auth + `manage_users` | `manage_users` | — | capabilities edit = admin-only ✔ |
| `/group/<name>/member/<login>` | DELETE | `requires_authorization` only | `manage_users` **or** group_admin | — | **F5** ordering bug |
| `/remote/<name>/api/<path>` | * | `requires_authorization` | — | remote in allowlist | SSRF-safe (allowlist) |
| `/varz` (Prometheus) | GET | auth + `access_prometheus_metrics` | ✔ | — | |
| `/server` | GET | public | — | — | only public flags |
| `/server/admin` | GET | auth + `manage_users` | ✔ | — | |

---

## 3. Findings

### F1 — Config family statistics leak across sharing groups
- **Severity:** Medium — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N` (≈5.0)
- **Affected:** `mwdb/resources/config.py:27 ConfigStatsResource.get` (lines 68–80)
- **Confidence:** Confirmed (code review)

**Root cause.** Every other listing/aggregation path filters rows by the caller's access using `g.auth_user.has_access_to_object(...)` (e.g. `mwdb/resources/object.py:236`, `:415`; `mwdb/resources/tag.py:69`; `mwdb/resources/search.py:60`). The config-stats query does **not**:

```python
# mwdb/resources/config.py:68
query = db.session.query(
    Config.family, func.max(Config.upload_time).label("maxdate"), func.count()
).group_by(Config.family)
if from_time != "*":
    query = query.filter(Config.upload_time > (datetime.now() - timedelta(hours=from_time)))
```

There is no join to `ObjectPermission` and no `has_access_to_object` filter, so the aggregation runs over **all** configs in the instance regardless of sharing group.

**Impact.** Any authenticated user — including the lowest-privileged registered user, with no special capability — can enumerate, across the whole multi-tenant instance: the set of **malware family names** that exist, the **count** of configs per family, and the **most-recent upload time** per family. In a shared deployment (e.g. mwdb.cert.pl with multiple isolated sharing groups) this crosses the sharing-group isolation boundary and reveals what families other tenants track and their activity cadence. Config contents are not exposed — only this aggregate metadata. (On a single-tenant deployment the leak is immaterial, which is why it has gone unnoticed.)

**Reproduction.**
```
GET /api/config/stats?range=*        (any valid session/API token)
→ 200 [{ "family": "<family from another group>", "count": N, "last_upload": "..." }, ...]
```

**Fix.** Apply the same ACL filter used everywhere else, e.g.:
```python
query = (
    db.session.query(Config.family, func.max(Config.upload_time), func.count())
    .filter(g.auth_user.has_access_to_object(Config.id))
    .group_by(Config.family)
)
```
If a global view is genuinely intended for operators, gate it behind a capability (e.g. `access_uploader_info` / a new `access_global_stats`) instead of exposing it to every account.

---

### F2 — Unbounded/expensive search queries with no statement timeout by default (DoS)
- **Severity:** Medium — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (≈6.5 when `statement_timeout=0`)
- **Affected:** `mwdb/core/search/fields.py:217 JSONBaseField._get_json_condition` (full-table `cfg::text LIKE '%…%'` / `jsonb_path_query` function scan), `mwdb/core/config.py:49 statement_timeout` (default `0`)
- **Confidence:** Likely

**Root cause.** Inner-match config/blob queries deliberately perform a full-table scan (`cast(self.column, Text).like(...)` plus a `jsonb_path_query` function scan — see the in-code comment at `fields.py:283`: *"Queries above perform very slow full table scan"*). The only backstops are PostgreSQL `statement_timeout` and `listing_endpoints_count_limit`. `statement_timeout` **defaults to `0` (disabled)** (`config.py:49`), and `count()`/stats paths are not bounded by the listing limit at all.

**Impact.** A low-privileged user can submit crafted wildcard queries (e.g. `cfg:"*aaaa*"` over a large config corpus, or repeated `/config/count?query=…`) that pin a backend worker/DB connection for a long time. With the default `statement_timeout=0` there is no server-side cap; rate limiting is also off by default (F3). Repeated requests can exhaust DB connections / workers → denial of service.

**Reproduction.** On an instance with a non-trivial config corpus and default config:
```
GET /api/config?query=cfg:%22*0*%22&count=1000
GET /api/config/count?query=cfg:%22*0*%22   (repeat concurrently)
```

**Fix.** Ship a sane non-zero `statement_timeout` default (document the trade-off), and/or cap/deny pure leading-wildcard inner-match searches for users without an elevated capability; ensure count/stats endpoints also run under the timeout. Enable rate limiting in production profiles (it already is in `gen_vars.sh` non-test path).

---

### F3 — Account/username enumeration + weak default brute-force protection on authentication
- **Severity:** Low–Medium — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (≈5.3)
- **Affected:** `mwdb/resources/auth.py:49 LoginResource` (no dummy hash on unknown user), `:131 RegisterResource` (`409 "Name already exists"`), `:321 RecoverPasswordResource` (`403 "Invalid login or email address."`); `mwdb/core/rate_limit.py` (disabled unless `enable_rate_limit`, and only coarse `post` limits — no login-specific throttle or lockout)
- **Confidence:** Confirmed

**Root cause / impact.**
- **Enumeration (timing):** `LoginResource.post` returns immediately for an unknown login (`NoResultFound → Forbidden`), but performs an expensive bcrypt comparison for a known login. The measurable timing difference (bcrypt cost 12) distinguishes valid from invalid usernames even though the message is generic.
- **Enumeration (messages):** registration returns `409 "Name already exists"` for existing logins/groups; password recovery returns a distinct `403` only when login+email don't match. Both confirm account existence.
- **Brute force:** rate limiting is opt-in (`enable_rate_limit=False` by default). Even when enabled, there is no login-specific limit — `LoginResource` inherits the generic `post` bucket (`100/10second` per IP = up to 600/min), and there is no per-account lockout. reCAPTCHA is optional.

**Fix.** Perform a constant-time dummy bcrypt check when the user is absent; keep responses uniform. Add a dedicated, strict limiter key for `loginresource`/`recoverpasswordresource` (e.g. `mwdb_limiter.loginresource_post`) and consider per-account failed-attempt backoff. Recommend enabling rate limiting and reCAPTCHA in the production configuration guide.

---

### F4 — `UserPendingResource` methods omit `@requires_authorization` (500 + None dereference)
- **Severity:** Low — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (≈5.3, availability/robustness only)
- **Affected:** `mwdb/resources/user.py:81 post` and `:162 delete` (decorated with `@requires_capabilities(Capabilities.manage_users)` but **not** `@requires_authorization`); also `:125 user.pending = False` runs before any `None` check.
- **Confidence:** Confirmed

**Root cause.** Unlike every other admin endpoint, these two methods lack `@requires_authorization`. For an unauthenticated request `g.auth_user` is `None`, so `requires_capabilities` executes `None.has_rights(...)` → `AttributeError` → generic `500`. This is **not an auth bypass** (the request still fails and the capability is still effectively required), but it returns `500` + logs an exception instead of a clean `401`. Separately, `POST` fetches the pending user with `.first()` and immediately does `user.pending = False` with no `None` guard (`user.py:120-125`), so a well-formed-but-nonexistent login (authorized admin call) throws `AttributeError` → `500` rather than `404`.

**Fix.** Add `@requires_authorization` above `@requires_capabilities` on both methods (matching the rest of the file), and add an explicit `if user is None: raise NotFound(...)` before mutating.

---

### F5 — `GroupMemberResource.delete`: authorization and existence checks in wrong order (500)
- **Severity:** Low — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` (≈3.1)
- **Affected:** `mwdb/resources/group.py:509 delete` (lines 558–584)
- **Confidence:** Confirmed

**Root cause.** The handler dereferences `group` and `member` before confirming they exist:
```python
group = db.session.query(Group)...first()
if not (g.auth_user.has_rights(Capabilities.manage_users)
        or g.auth_user.is_group_admin(group.id)):   # group may be None → AttributeError (500)
    raise Forbidden(...)
if group is None:
    raise NotFound("No such group")                 # unreachable if group is None
...
if g.auth_user.login == member.login:               # member may be None → AttributeError (500)
    raise Forbidden(...)
if member is None:
    raise NotFound("No such user")
```
Additionally `User.is_group_admin(group_id)` (`mwdb/model/user.py:247`) does `.first().group_admin`, which throws for a non-member caller instead of returning `False`. Net effect: a non-admin, non-`manage_users` user calling DELETE on a group they don't belong to — or an admin passing a nonexistent group/member — gets `500` instead of `403`/`404`. No privilege escalation (the capability/admin requirement still holds), but noisy failures and a minor DoS/error-oracle.

**Fix.** Reorder: resolve `group`, `raise NotFound` if `None`, then authorize, then resolve `member`, `raise NotFound` if `None`, then the self-removal guard. Make `is_group_admin` return `False` when no membership row exists.

---

### F6 — User email and last-login disclosed to any same-group member
- **Severity:** Low — CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (≈3.5)
- **Affected:** `mwdb/resources/user.py:652 UserProfileResource.get` + `mwdb/schema/user.py:119 UserProfileResponseSchema` (exposes `email`, `registered_on`, `logged_on`)
- **Confidence:** Confirmed

**Root cause / impact.** A user without `manage_users` may read `/profile/<login>` for any user who shares at least one non-`public` group, and the response schema includes that user's **email address** and **last-login timestamp**. Depending on deployment policy this is more PII than a group peer needs (harvestable for phishing / activity profiling). If the intent is only to render display names/capabilities, drop `email`/`logged_on` from `UserProfileResponseSchema` and keep them in `UserOwnProfileResponseSchema` / the `manage_users` views only.

---

### F7 — File download responses lack `X-Content-Type-Options: nosniff`
- **Severity:** Info/Low — CVSS 3.1 `AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N` (≈2.6)
- **Affected:** `mwdb/resources/file.py:472-493`, `:612-616`; `mwdb/resources/download.py:54-58`
- **Confidence:** Confirmed

**Root cause / impact.** Downloads are served `Content-Type: application/octet-stream` with `Content-Disposition: attachment; filename=<sha256>` (filename is a fixed hash, so no header-injection and no sniffable name). That already blocks most issues, but the responses do not set `X-Content-Type-Options: nosniff`. As defense-in-depth for a service that stores attacker-controlled bytes, add `nosniff` (and a restrictive CSP on the web tier). Note the download is XORed in the UI preview path (`File.iterate(obfuscate=True)`), which is anti-EDR, not a security control.

---

## 4. Areas reviewed with **no findings** (hardening confirmed)

- **Lucene→SQL search parser (SQLi / jsonpath injection):** `mwdb/core/search/*`. String values are bound as parameters (`column.op("@?")(jsonpath)`, `.like()`, `jsonb_path_query(col, selector)`); jsonpath literals and field keys are escaped via `jsonpath_quote` (escapes `"` and `\`); raw-interpolated values are constrained to numeric/boolean by `is_nonstring_object`'s strict regex. No breakout found. LIKE wildcards and SQL metacharacters are correctly escaped in `transform_for_*` helpers.
- **Object access control / sharing isolation:** `has_access_to_object`, `Object.access`, `ObjectPermission.get_uploaders_filter/get_shares_filter`, `RelationField`, tag/attribute/comment paths all enforce membership-based ACL. Permission inheritance through relations is handled carefully.
- **Rich-attribute Markdown (stored XSS):** `MarkedMustache.tsx` / `MarkdownRenderer.tsx` render into React elements (no `dangerouslySetInnerHTML`; raw `html` tokens are emitted as **text**), links pass through `sanitizeUrl` (allowlist http/https after WHATWG-style normalization of tab/newline/control chars), images are not rendered. No XSS sink found in the frontend.
- **JWT / tokens:** `HS512` pinned (no `alg` confusion), audience + scope verified, session tokens bind `password_ver`/`identity_ver` (capability/password change invalidates sessions), download tokens are 60 s and hash-bound, API-key tokens are DB-revocable. Secret key and admin password are generated with 144-bit entropy from `/dev/urandom` (`gen_vars.sh`); no default/weak secret.
- **File storage / path traversal:** storage path derived from validated `sha256`; `secure_filename` on uploaded names; alt-names handled via parameterized ARRAY ops.
- **SSRF via remotes:** `RemoteAPI` restricts to an admin-configured allowlist (`app_config.mwdb.remotes`); host/scheme are fixed, only path/query forwarded.
- **Attribute permission model:** `query_for_read`/`query_for_set` enforce per-key group permissions unless `reading_all_attributes`/`adding_all_attributes`; search path reuses `query_for_read` (so no hidden-attribute oracle for unauthorized keys).

## 5. Areas **not** reviewed / limited coverage

- No dynamic testing against a running instance (static review only); findings are code-grounded.
- Plugin ecosystem code and Karton **worker-side** consumers (only the producer/trust boundary in `mwdb/core/karton.py` and `resources/karton.py` were skimmed). Malicious-plugin RCE is by-design trust (admin-installed) and out of scope.
- OIDC: the `state`/`nonce` flow relies on the frontend echoing values back and the IdP-bound `nonce` in the id_token (`core/oauth/client.py:parse_id_token`); a deeper login-CSRF / session-fixation analysis would benefit from dynamic testing. No concrete bug confirmed.
- Full dependency / supply-chain audit (`pip-audit`, `npm audit`, `bandit`, `semgrep`, `trivy`) was **not** executed in this environment; `uv.lock`/`package.json` pinning was only spot-checked. Recommend running these in CI and triaging.
- Frontend deps and build config beyond targeted grep.

## 6. Hardening recommendations & regression tests

1. **F1:** add ACL filter to `/config/stats`; add a test asserting a user in group A cannot see family counts for configs only shared with group B.
2. **F2:** set a non-zero default `statement_timeout`; add a guard/cap on leading-wildcard inner-match searches; enable rate limiting in prod profiles.
3. **F3:** constant-time login for unknown users; dedicated strict limiter keys for login/recover; uniform responses; document enabling reCAPTCHA.
4. **F4/F5:** add `@requires_authorization`, reorder existence-vs-authorization checks, add `None` guards; add tests that unauthenticated and non-admin callers get `401`/`403`/`404` (not `500`) on `/user/<login>/pending` and `/group/<name>/member/<login>` DELETE.
5. **F6:** trim `UserProfileResponseSchema` to non-PII fields.
6. **F7:** add `X-Content-Type-Options: nosniff` to all download responses; add a strict CSP + `X-Frame-Options`/`frame-ancestors` on the web tier.
7. **General:** make `requires_capabilities` fail safe (raise `Unauthorized` if `g.auth_user is None`) so a missing `requires_authorization` can never degrade to `500`.

## 7. Responsible disclosure

The repo has **no `SECURITY.md`**. Report confirmed issues (primarily **F1**) privately to CERT Polska via a **GitHub Security Advisory** on `CERT-Polska/mwdb-core` (and/or `info@cert.pl`) **before** any public disclosure, and allow time for a fix/release. Do not publish reproduction details until a patched version is available.

---

## 8. Where payout-grade bugs are most likely (dynamic-test focus)

Static review found the core hardened. If pursuing a rewardable bug on a live instance, concentrate here — each needs runtime/config that static review can't settle:

1. **OIDC token/state binding (account takeover, §2).** `OpenIDAuthorizeResource`/`...Authenticate` create a *fresh, stateless* `OAuth2Session` per request (`core/oauth/provider.py:37`), so CSRF/replay protection rests entirely on the client echoing `state` and the `nonce` baked into the id_token (`core/oauth/client.py:parse_id_token`). Worth testing live: login-CSRF / code-injection by replaying another session's `code`+`state`, missing `state` binding, `nonce` reuse, and whether `fetch_id_token` rejects a token whose `aud`/`azp` differs. Also `iter_user_name_variants` → can a controlled `preferred_username` claim collide with / pre-empt a privileged login during `enable_oidc_registration`?
2. **`share_queried_objects` / dedup access model (§9 IDOR).** `Object.access` auto-shares any object to a querying group that holds `share_queried_objects` (`model/object.py:609`), and re-uploading a known sample grants access via dedup. Probe whether these can be chained to read objects across groups without the intended capability, and whether relation-link permission propagation (`add_parent`/`uninherit_share`) can be driven to widen or revoke others' access.
3. **Attribute `rich_template` / `url_template` rendering (§8 XSS).** The MarkedMustache renderer and `sanitizeUrl` are hardened, but a live test should fuzz attribute values against admin-defined rich templates (and the dagre-d3 `labelType:"html"` round-trip in `DagreD3Plot.tsx`) for a DOM-XSS escape, plus any `fromPlugins("mustacheExtensions")` lambdas a deployment loads.
4. **Plugins (§1 RCE).** Out of the box this is admin-trusted, but on a target running community plugins, review each plugin's own endpoints/hooks for the usual classes — they inherit full app context.
5. **Config/blob full-text search operators.** The parser is parameterized; still worth live-fuzzing `cfg:`/blob queries with exotic `jsonb` path and LIKE inputs for parser edge cases (confirm no injection, not DoS).

None of the above is a confirmed vulnerability — they are the highest-value places to spend dynamic-testing time.
