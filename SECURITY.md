# IntentLatch security model

## Scope

Hosted v1 is a security demonstration with one exact same-project harmless target. It is not a general relay and is not appropriate for high-impact actions.

## Assets and attackers

IntentLatch protects the integrity of the reviewed action, the server network boundary, destination availability, and response consumers. Inputs are hostile. Threats include malformed parsers, SSRF and DNS rebinding, redirects/upgrades, scanner and prefetch activation, payload leakage, response smuggling, duplicate submission, timeouts, and abusive relay use.

## Trust boundaries

- Caller input is untrusted and non-confidential.
- CDN and Vercel infrastructure necessarily process prepare URLs.
- Public DNS can change between requests; commit resolves afresh, rejects the whole set if any address is special-use, and pins one vetted address.
- The controlled demo is trusted only to be harmless. Its receipt is not durable execution state.

## Invariants

- `GET /api/v1/prepare` performs no network fetch and no action.
- `POST /api/v1/commit` is the only dispatch route.
- The allowlist is compiled into `lib/policy.js` as exact origin/path/schema values.
- Commit verifies strict JSON, canonical digest, two-minute expiry, UUIDv4, method, body schema, denied key names, target, and DNS.
- Outbound requests use fixed headers and HTTPS:443 with pinned IP plus original Host/SNI/certificate verification.
- No redirect following, retries, compression, upgrades, streaming, action query, caller headers, or raw upstream response.
- All API success and error responses are no-store, noindex, attachment JSON with restrictive browser headers and no CORS.
- Source contains no application logging calls.

## Privacy

All prepare URL input is public and may appear in browsers, network infrastructure, CDN, or Vercel logs. Never include secrets or personal data. The recursive credential-like key-name denylist is hygiene, not reliable secret detection: a secret can be mislabeled, encoded, split, or embedded in a normal-looking value.

## Impossibility and remaining risk

There is no generally safe, public, anonymous, arbitrary side-effecting GET relay. Headers cannot reliably distinguish intentional navigation from a scanner. IntentLatch therefore makes GET inert and requires POST.

No atomic store or secret exists in hosted v1, so the service makes no one-use, encrypted-capsule, durable idempotency, rate-accounting, or exactly-once claim. The stable idempotency key is the caller's `request_id`; it only helps if the destination atomically binds that ID to the first accepted body/digest and rejects conflicting reuse. A timeout means the outcome is unknown and no retry is attempted.

**Strongest remaining failure mode:** if a valid commit POST is submitted more than once and a future destination does not enforce the stable request-ID key, it can execute more than once. A destination that accepts one `request_id` with two different bodies also collapses integrity into replay handling; it must reject the conflict rather than select a winner. That is why the public allowlist contains only the harmless no-side-effect demo. Platform-level request replay before/around function execution is also outside process-local control.

Other residual risks include infrastructure URL retention, newly allocated special-use IP ranges not yet reflected in the source list, DNS resolver compromise, platform termination after request bytes leave but before a reply, and denial-of-service against free hosting limits.

## Before adding any real endpoint

Require all of the following: exact manual admission; a fixed strict schema; same-origin, no-redirect manifest opt-in revalidated at commit; strongly consistent atomic claim/replay/rate storage; destination enforcement of same-key/same-body semantics; operational quotas and revocation; controlled deployed-runtime pinning/TLS tests; and a risk review excluding payment, deletion, publication, messaging, credentials, and security/account changes.

## Reporting

Use GitHub private vulnerability reporting. Do not test arbitrary third-party origins or include credentials, personal data, or live exploit secrets in reports.
