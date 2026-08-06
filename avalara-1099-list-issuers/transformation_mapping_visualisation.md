# Transformation Mapping — List Issuers Workflow

**Integration:** End User → Avalara 1099 API (`GET /1099/issuers`)  
**Workflow file:** `src/workflows/list-issuers.ts`  
**Last updated:** 2026-06-01

---

## Overview

The workflow acts as a transparent proxy between an end user's request and the Avalara 1099 API. The only material transformation is **token normalisation** — the workflow guarantees a consistently formatted `Authorization` header regardless of what the caller sends. All other request enrichment (filters, required API headers) is additive. The response is returned raw, with no shape changes.

---

## Step 1 — Token Extraction & Normalisation (`extract-bearer-token`)

### Input

| Field | Source | Notes |
|---|---|---|
| `Authorization` header | Incoming HTTP request | Accepted case-insensitively (`authorization` or `Authorization`) |

### Validation Rules

| Rule | Behaviour on Failure |
|---|---|
| `Authorization` header must be present | Workflow aborts with `400`-style error: _"Missing Authorization header"_ |
| Header value must be non-empty after stripping the `Bearer` prefix | Workflow aborts with error: _"Authorization header is present but contains no token value"_ |

### Normalisation Transform

| Scenario | Raw Inbound Value | Outbound `bearerToken` |
|---|---|---|
| Caller includes the prefix | `Bearer eyJ...` | `Bearer eyJ...` (unchanged) |
| Caller omits the prefix | `eyJ...` | `Bearer eyJ...` (prefix added) |
| Caller uses wrong casing | `bearer eyJ...` | `Bearer eyJ...` (re-cased) |

**Rule:** Any existing `Bearer ` prefix (any casing) is stripped, then `"Bearer "` is unconditionally prepended. The outbound token is **always** `Bearer <raw_token>`.

---

## Step 2 — Avalara API Request Construction (`fetch-issuers`)

### Outbound Request

| Property | Value |
|---|---|
| Method | `GET` |
| Endpoint | `/1099/issuers` |
| Connection | `avalara_1099` |

### Query Parameters (Filters)

| Parameter | Value | Purpose |
|---|---|---|
| `$top` | `100` | Limit results to 100 issuers per page |
| `$count` | `true` | Include `@recordSetCount` total in the response |
| `$orderBy` | `name ASC` | Sort issuers alphabetically by name |

### Outbound Headers

| Header | Value | Source |
|---|---|---|
| `Authorization` | `Bearer <normalised_token>` | Forwarded from `extract-bearer-token` step |
| `avalara-version` | `2.0` | Hardcoded — required by Avalara 1099 API |
| `X-Correlation-Id` | UUID v4 (generated per request) | Used by Avalara for server-side tracing |
| `Accept` | `application/json` | Hardcoded |

### Error Handling

| Condition | Behaviour |
|---|---|
| Avalara returns a non-2xx status | Workflow throws `"Avalara API error <status>: <body>"` and the error is caught by the `.catch()` handler |
| `.catch()` fires for any step error | Returns `{ "error": "<message>" }` as the sync webhook response body |

---

## Response Mapping

The Avalara JSON response body is returned **as-is** to the calling client — no fields are added, removed, or renamed.

| Avalara Response Field | End-User Response Field | Transform |
|---|---|---|
| `value[]` | `value[]` | Passthrough |
| `@recordSetCount` | `@recordSetCount` | Passthrough (present when `$count=true`) |
| All other fields | All other fields | Passthrough |

---

## Data Flow Diagram

```
End User Request
│  Authorization: Bearer eyJ...
│
▼
[list-issuers] ── webhook entry point (sync mode)
│
▼
[extract-bearer-token]
│  • Validates Authorization header presence
│  • Normalises token → always "Bearer <token>"
│
▼
[fetch-issuers]
│  • Adds query filters ($top, $count, $orderBy)
│  • Adds Avalara-required headers (avalara-version, X-Correlation-Id)
│  • Calls GET /1099/issuers on Avalara 1099 API
│
▼
Raw Avalara JSON response returned to End User
```
