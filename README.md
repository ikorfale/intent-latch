# IntentLatch

**Prepare with GET. Commit with POST.**

IntentLatch is a deliberately narrow, security-conscious response to GET-mediated write relays. It is not a clone and not a general open proxy. Hosted v1 can dispatch only to its same-project harmless demo endpoint.

## Why

HTTP defines GET as safe so scanners, previews, crawlers, and prefetchers may retrieve it without harm. There is no generally safe, public, anonymous, arbitrary side-effecting GET relay. IntentLatch does not expose one: `GET /api/v1/prepare` is inert; only `POST /api/v1/commit` can dispatch.

## Contract

1. Prepare using exactly five query parameters: `origin`, `path`, `method`, `request_id`, `body`.
2. Review the canonical intent, SHA-256 digest, expiry, warnings, and exact commit template.
3. POST the template body to `/api/v1/commit` before its two-minute expiry.

`body` is unpadded base64url of strict UTF-8 JSON, maximum 4 KiB. Hosted schema:

```json
{"message":"A harmless message of 1–280 characters","request_id":"matching UUIDv4"}
```

Hosted origin/path are exactly `https://intent-latch-two.vercel.app/api/v1/demo-target`. Methods are POST, PUT, or PATCH. Unknown/duplicate parameters and JSON keys, invalid Unicode, excessive depth, noncanonical paths, queries, credentials, forbidden field names, other destinations, and other methods fail closed.

The prepare response returns `commit_template`, but never an executable GET URL, redirect, hyperlink, or subresource. The template places the full intent and confirmation digest in a JSON POST body.

## Security properties

- Prepare performs no outbound network request.
- Commit re-canonicalizes and verifies digest, expiry, method, path, schema, fixed allowlist, and DNS.
- Every A/AAAA answer must be global; one vetted IP is pinned into Node HTTPS while preserving Host, SNI, and certificate verification.
- Fixed outbound headers only: JSON content/accept, identity encoding, user agent, content length, stable logical-request idempotency key, full intent digest, and relay hop marker.
- No retries, redirects, compression, streaming, protocol upgrades, arbitrary caller headers, action query strings, binary, multipart, or copied upstream headers.
- Overall action deadline is five seconds; response body maximum is 64 KiB and always base64-encoded in a synthetic JSON envelope. 3xx is terminal data.
- HEAD, OPTIONS, incoming relay recursion, and declared prefetch never dispatch.
- No CORS is emitted. API responses use no-store, noindex, attachment, CSP, referrer, CORP, and nosniff headers.
- Application code has no logging calls and never logs URLs, payloads, intents, digests, or responses.

See [SECURITY.md](SECURITY.md) for the threat model and [OpenAPI](public/openapi.json) for wire details.

## Privacy

All prepare URL input is public and non-confidential and may appear in browser history, CDN/Vercel logs, network tooling, or copied links. Never put secrets, credentials, cookies, passwords, tokens, API keys, sessions, JWTs, signatures, personal data, or private URLs there. Recursive case/dash/underscore-insensitive forbidden-key checks are hygiene, not reliable secret detection.

## Honest limitations

Hosted v1 intentionally has no external atomic store. It does **not** claim durable one-use, rate accounting, encrypted capsules, or exactly-once delivery. The stable idempotency key is the caller's `request_id`; it only helps if the destination atomically binds that ID to the first accepted body/digest and rejects conflicting reuse. A timeout means the outcome is unknown. Never automatically retry.

The demo checks that its idempotency key equals the body's `request_id` and returns a derived receipt, but it has no durable replay memory. It never messages, posts, emails, deletes, spends, publishes, uploads, or changes accounts.

Self-hosters may edit `lib/policy.js`, but real destinations require a fixed endpoint schema, same-origin manifest opt-in, an atomic replay/rate store, operational revocation, and destination-enforced idempotency before use. This design is not production-suitable for payments, deletion, messaging, publication, access/security changes, or other high-impact actions.

## Development

Requires Node 24 and no npm dependencies.

```sh
npm test
npm run lint
npm run build
npm run dev
```

All network behavior tests use injected resolvers/transports or local fixtures; tests never send arbitrary outbound action requests.

## Deployment and rollback

`package.json` selects Node 24 while `vercel.json` sets routes and static security headers. Production is deployed from GitHub through Vercel Hobby with no database, paid service, custom domain, or secret.

Rollback: use Vercel's deployment history to promote the previous verified deployment, or revert the offending Git commit and push `main`. To disable all dispatch immediately in source, remove the hosted entry in `validateHostedTarget`, redeploy, and verify `destination_not_allowed` before restoring traffic.

## License

MIT. This project was independently authored; no code was copied from the unlicensed reference reviewed during design.
