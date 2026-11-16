# Sentra engine 1.0

Private, single-owner pilot for authorized public configuration checks of atlasclipping.com. No AI API key or paid scanning API is required.

## What works

- Real Worker-side GET requests, streamed progress, and stop requests.
- HTTPS response, HTTP upgrade, HSTS, CSP, embedding protection, MIME protection, referrer policy, cookie flags and static insecure resource references.
- Fixed hostname enforced on the server; no client-supplied targets, custom headers, credentials or payloads.
- Six-request maximum, bounded redirects, 1.1-second pacing, eight-second request timeouts and 25-second overall budget.
- DNS preflight blocks nonpublic answers. Worker fetch resolves independently; this is NOT a generic URL-fetch service or DNS-rebinding-proof scanner. The fixed allowlist is intentional.
- Shared R2 conditional lease gives a 60-second cooldown across isolates.
- R2 report storage, latest 30 retained; JSON/Markdown export and printable report.
- Cancellation between stages; in-flight work may last until its timeout.
- Stop without retry on HTTP 429 or 5xx; incomplete checks never become passes.

## Development

Node 22+; no dependencies required.

    npm test
    npm run build

Source: engine/ (policy, transport, checks), worker/ (authenticated API and storage), public/ (UI). Build embeds static assets in the Worker module at dist/server/index.js. The Sites platform owns sign-in and owner-private access. R2 binding BUCKET is required; API fails closed without it.

ENGINE_SERVICE_TOKEN is a server-only secret for authorized deployment verification/service access. A service caller ALSO needs platform private-Site access. Browser callers use platform-injected signed-in identity and same-origin requests. Never place either credential in browser code, source, or reports.

## Boundaries

This is a public-configuration engine, not a penetration-testing replacement. No authenticated flow testing, tenant-isolation tests, injection attempts, dependency audit, port scanning, exploit verification, load testing, or automatic code patches. Header presence is not proof of effectiveness; absence is not proof of exploitability. Cookie values are redacted and raw HTML is not persisted.

Authorization for the fixed target was explicitly provided by its owner in this project. New-customer onboarding, DNS ownership challenges, multi-tenant isolation, unattended scheduling, alert delivery and production billing are not implemented. Do not change this private pilot to a public service without those controls and an independent review.

The scan UI uses server progress events. It has no fabricated timing or findings. Reports include actual timestamps and incomplete coverage when requests fail. Browser visual QA is unavailable in this execution environment; engine/API checks run through Node tests and hosted smoke checks.

## Verified deployment
A hosted check on 2026-11-16 completed with two website requests, three positive observations, five configuration review items, and one not-observed result. Report persistence and a subsequent HTTP 429 cooldown rejection were verified. The Worker-compatible DNS preflight uses a fixed Google DNS JSON endpoint with manual redirect handling. Earlier failed preflights remain in report history as incomplete checks.

## Account connector
Test accounts page and server endpoints support staging adapter health checks, idempotent provisioning of three synthetic identities, account-reference storage, and cleanup. All operations are disabled until ACCOUNT_CONNECTOR_URL, ACCOUNT_CONNECTOR_TOKEN and ACCOUNT_AUTOMATION_ENABLED are configured server-side. Target is restricted to staging.atlasclipping.com. See public/integration-guide.txt for the app-side contract. No Atlas staging adapter exists in this repository and no accounts have been created. Browser login, secure session handoff and authenticated tests are not implemented.

## GitHub source and deployment

This repository contains the complete authored source, tests, UI, and account-connector instructions. Generated dist output, credentials, scan reports, and raw evidence are excluded. Run `npm run build` to regenerate the deployable Worker.

The `.openai/hosting.json` manifest identifies the existing private Sites deployment. This repository does not automatically deploy GitHub commits. Publish through the Sites workflow after testing. Never expose the Worker directly behind an untrusted proxy: its identity headers depend on Sites enforcing authentication and stripping spoofed headers.

The UI provides a dark report, custom SVG symbols, status filters, print/PDF output, and JSON/Markdown exports. Passed means an expected signal was observed; configuration issues are not confirmed vulnerabilities.

See `.env.example` for server-setting names and `public/integration-guide.txt` for the staging adapter contract. No passwords or API keys are included. Browser signup, verification-email automation, Playwright workers, and authenticated security testing remain future work.
