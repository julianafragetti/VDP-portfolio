# Authentication Bypass & Information Disclosure in a Fortune 500 Company's External API

**Author:** [YOUR NAME]  
**Date:** May 2026  
**Program:** VDP (Vulnerability Disclosure Program) — Major Beverage Corporation  
**Platform:** HackerOne  
**Severity:** Medium (disputed as Informative)  
**Status:** Closed — Informative

---

## Summary

During a routine reconnaissance exercise, I identified a publicly indexed external API gateway belonging to a Fortune 500 beverage company. The gateway exposed full internal API documentation — including schemas for sensitive financial operations — and exhibited inconsistent authentication enforcement across endpoints, constituting an Authentication Bypass and Information Disclosure vulnerability.

---

## Reconnaissance

### Step 1 — Google Dorking

Using targeted Google dorks, I identified an externally accessible API subdomain that had been indexed by search engines:

```
site:[company].com inurl:api [internal system keyword]
```

The search results revealed a publicly accessible help/documentation page listing all available API endpoints of the company's **NextGen Digital Imaging External Gateway**.

### Step 2 — Shodan Validation

I confirmed the host was live and internet-facing using Shodan, which also revealed infrastructure details exposed via HTTP response headers:

- **Server:** Microsoft-IIS/10.0
- **X-Powered-By:** ASP.NET
- **X-AspNet-Version:** 4.0.30319

These headers disclose the exact technology stack and version, enabling targeted exploitation.

---

## Vulnerability Analysis

### Step 3 — Authentication Inconsistency

I tested two endpoints from the same API to compare authentication enforcement:

**Endpoint A — Health Check (unauthenticated):**
```bash
curl -i https://[redacted]/api/StorageObject/IsAlive
```
Response: `HTTP/2 200 OK`

**Endpoint B — Authenticated Control (correctly protected):**
```bash
curl -i https://[redacted]/api/StorageObject/IsAliveAuthenticated
```
Response: `HTTP/2 302 → Redirect to Okta/OAuth2 login`

**Endpoint C — Document Download (authentication bypass):**
```bash
curl -i -X POST https://[redacted]/api/StorageObject/GetImagingDocuments \
  -H "Content-Type: application/json" \
  -d '{"Vendor_Name": "test", "Vendor_UserID": "test", "BA_Id": "test", "SystemId": 1}'
```
Response: `HTTP/2 500 Internal Server Error`  
Body: `{"Message": "An error has occurred."}`

The 500 response confirms the request **bypassed the Okta redirect** and reached the backend processing layer — proving the authentication check was not applied uniformly.

### Step 4 — Information Disclosure via Public Documentation

The API help page (`/help` and root `/`) exposed a complete map of internal methods, including:

| Endpoint | Description |
|----------|-------------|
| `GET api/StorageObject/GetTPMSolixDocuments/{userGpid}/{systemId}/{businessAreaName}/{claimNum}` | TPM/SOLIX document retrieval |
| `GET api/StorageObject/GetAAMDocuments/{systemId}/{documentId}` | AAM document retrieval |
| `POST api/StorageObject/GetInvoiceDocuments/{guid}` | Invoice and POD document retrieval |
| `GET api/StorageObject/GetDocumentStream/{vendorName}/{systemId}/...` | Document stream access |
| `GET api/StorageObject/GetAuthorized` | Authorization check endpoint |

This documentation reveals internal parameter names (`Vendor_Name`, `Statement_Id`, `BA_Id`, `SystemId`) used in financial and imaging operations — providing a complete attack blueprint for **BOLA (Broken Object Level Authorization) / IDOR** attacks.

---

## Impact

1. **Information Disclosure** — Internal API architecture, financial document schemas, and vendor parameter structures were publicly accessible without authentication.

2. **Attack Surface for BOLA/IDOR** — With knowledge of the parameter structure (e.g., `?code=`, `{guid}`, `{documentId}`), an attacker could enumerate valid identifiers to access internal documents, invoices, and vendor records.

3. **Infrastructure Fingerprinting** — Exposed headers reveal outdated software versions (IIS 10.0, ASP.NET 4.0.30319), enabling targeted exploitation of known CVEs.

---

## Evidence

- Google Dork results showing indexed API documentation
- Shodan confirmation of live host and exposed headers
- Terminal screenshots showing HTTP 200 (IsAlive), HTTP 302 (IsAliveAuthenticated), and HTTP 500 (GetImagingDocuments)
- Video recording of full API documentation page listing sensitive endpoints
- curl command outputs demonstrating authentication bypass

---

## Recommended Fixes

1. **Enforce authentication uniformly** — Apply the `[Authorize]` attribute (or equivalent middleware) to all endpoints in the `StorageObjectController`, not selectively.
2. **Remove public API documentation** — The `/help` and root documentation pages should require authentication or be taken offline entirely.
3. **Suppress technology headers** — Remove `X-Powered-By`, `X-AspNet-Version`, and `Server` headers from all HTTP responses to prevent fingerprinting.
4. **Implement generic error handling** — Replace verbose 500 error messages with generic responses to avoid leaking internal stack details.

---

## Timeline

| Date | Event |
|------|-------|
| April 25, 2026 | Initial report submitted with full PoC |
| May 7, 2026 | Follow-up submitted after triager couldn't access original URL — provided alternative reproduction steps and re-located full API documentation |
| May 8, 2026 | Triager closed as Informative, citing no "demonstrable access to protected resources" |
| May 8, 2026 | Researcher disputed closure, arguing Information Disclosure and BOLA attack surface were demonstrated |
| May 2026 | Closed as Informative (disputed) |

---

## Researcher's Note

This report was closed as **Informative** by the triage team on the basis that no protected data was directly accessed. I respectfully disagree with this classification.

The combination of:
- Publicly indexed internal API documentation with financial operation schemas
- Inconsistent authentication enforcement (some endpoints correctly redirect to Okta; others do not)
- Infrastructure version disclosure via HTTP headers

...constitutes a **Medium severity** finding under both OWASP API Security Top 10 (API3:2023 Broken Object Property Level Authorization, API8:2023 Security Misconfiguration) and common VDP assessment standards.

The requirement for a live `200 OK` with sensitive data in hand before validating an authentication bypass sets a dangerous precedent — it incentivizes researchers to go further than responsible disclosure allows.

---

*All sensitive identifiers, domain names, and endpoint paths have been redacted in accordance with responsible disclosure practices.*
