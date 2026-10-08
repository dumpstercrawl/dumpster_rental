# V4 secure identification storage

## What changed
V4 is now a staff-operated management interface. Customers continue to use https://book.dumpstercrawl.com. GitHub Pages cannot run the secure API: without a configured backend, V4 fails closed and cannot report successful creation. No service credentials belong in HTML or GitHub.

The Worker stores actual document bytes in a private R2 bucket, with an unpredictable object key linked to a server-generated rental UUID in D1. Customers, addresses, signatures, and agreements are central D1 records, not browser-local records. A rental is not marked photoIdReceived until object storage and the database transaction succeed. Database failure deletes the uploaded object; capacity conflicts also delete it. D1 conditionally allocates one of the existing six units without overwriting an overlapping active rental.

Acceptance evidence includes the typed legal name, server UTC timestamp, exact agreement HTML snapshot, version, SHA-256 of the agreement and document, and acceptance flag. Status updates cannot replace this evidence. The worker/agreement.js snapshot must be versioned alongside any future terms change. This preserves evidence; it does not authenticate a person's identity or verify their ID's authenticity.

Every record, document, agreement, and status route requires a server-stored staff session. Sessions expire after eight hours, logout revokes them server-side, and only hashed random tokens are stored. Cookies are Secure, HttpOnly and SameSite=Strict. Mutations require the same Origin. Login is throttled to five attempts per 15-minute IP window. Document downloads are attachments with no-store, nosniff and a sandbox policy. Server-side validation checks size, required signature/consent, allowed MIME types and file magic. Bodies are bounded even without Content-Length. File magic is not malware scanning; add a scanning/quarantine service before expanding upload access beyond staff.

Audit rows record login, creation, document/evidence access and status updates without logging IDs or document contents. This version has a single staff role/password, not named employee identities. Use an identity provider with MFA and individual roles before extending access to additional personnel; current audit events cannot identify individual staff members sharing that credential.

## Infrastructure and deployment
1. Provision a dedicated D1 database and private R2 bucket. Disable both r2.dev public access and public/custom bucket domains. Do not reuse the live booking app's tables or bucket implicitly.
2. Copy wrangler.example.jsonc to a local deployment configuration and fill in the real database ID/bucket name. Keep the Worker and index.html on the same HTTPS origin. npm run build copies only index.html into public assets, never database files or secrets.
3. Apply migrations/0001_secure_rentals.sql to the provisioned D1 database before serving traffic. Configure DB, BUCKET and ASSETS bindings.
4. Set STAFF_PASSWORD using the hosting secret manager to a unique randomly generated value of at least 20 characters. No default or frontend password is supplied. Store secrets outside the repository; never distribute storage credentials to browsers. Restrict infrastructure access to the owner.
5. Deploy the Worker after review. GitHub Pages alone remains unsupported. Establish encrypted backups, tested restoration, retention/deletion rules, key/access rotation, monitoring and separate test/production environments before accepting real IDs. R2/D1 provide platform encryption at rest; use HTTPS in transit. Protect exported backups separately.
6. Verify on staging with synthetic IDs: sign in, create a rental, retrieve the exact bytes and evidence, sign out and ensure retrieval fails; verify bucket URLs are inaccessible. Then repeat with production synthetic fixtures after deployment. Do not test with a real customer's ID or payment card.

Existing V3/V4 localStorage records are intentionally not silently imported or deleted. Their filenames/received flags cannot recover missing ID bytes. Inventory/customer/signature migration requires an owner-reviewed export from the original browser and a controlled import process; do not assume an old received flag proves an ID exists. Never upload an export to a public repository. This PR does not provision resources, deploy, migrate production records, or change the hosted booking app.

## Test scope
npm test uses actual SQLite SQL and transactions via Python's standard library with D1-shaped adapters and a byte-preserving R2 adapter. It tests association, byte retrieval, evidence preservation, server-side validation, unconfigured storage, forged/expired sessions, logout, CSRF, rate limits and cleanup on failure. It is not a live Cloudflare integration test. Python 3 and Node 22+ are required for tests; the deployed Worker needs neither Python nor npm dependencies. npm run build and Node syntax checks validate the frontend script/backend source.

## Hosted booking app investigation — October 7, 2026 (America/Chicago)
The inspected source commit is b3dcb287fb7f53194e7e4dc0f73cbb18d2bc953d, matching the latest saved Site version 37. Source is a separate repository from GitHub V4. .openai/hosting.json declares DB (D1) and BUCKET (R2).

worker/index.js uploads the actual photo.stream() to BUCKET with a booking UUID and random key (around lines 550–553); the bookings row records photo_id_key/name/type, signature, agreement_accepted_at and agreement_version. Its owner dashboard links to /api/bookings/:id/photo-id, and this route checks hasOwnerSession before reading storage (around lines 500–506). Thus the hosted implementation already addresses V4's missing document upload and centralized storage.

Remaining source-review concerns:
- Owner session is a deterministic hash of a shared secret. Max-Age limits the browser cookie but the server accepts the token indefinitely; logout does not revoke it. Login has no rate limiting in the inspected route.
- Upload validation trusts declared MIME type and size; no file-content verification was found.
- Payment is charged before document/database persistence. A later storage failure leaves a paid booking requiring manual recovery.
- Agreement version is stored, but an immutable per-booking terms snapshot/hash and document-read audit are not present in these routes.

A read-only unauthenticated request to a synthetic nonexistent photo-ID URL returned HTTP 403 without a redirect. That may be an edge access restriction, so it does not independently establish application-level authorization. No real customer record was retrieved and no payment or production booking was made. Owner-authenticated live upload/retrieval, bucket privacy configuration and backup/retention controls remain unverified. Do not label the hosted application fully security-verified based on this source inspection.

Provider references: [D1 data security](https://developers.cloudflare.com/d1/reference/data-security/), [R2 data security](https://developers.cloudflare.com/r2/reference/data-security/), [R2 public access controls](https://developers.cloudflare.com/r2/buckets/public-buckets/).
