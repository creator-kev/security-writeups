# PortSwigger SSRF Lab #1 — Basic SSRF Against the Local Server

## Lab Metadata
- **Platform:** PortSwigger Web Security Academy
- **Lab:** Basic SSRF against the local server
- **Date:** 2026-06-24
- **Category:** Server-Side Request Forgery (SSRF)
- **Difficulty:** Apprentice

---

## Vulnerable Feature
Stock check functionality accepts a user-supplied URL and makes a server-side request to it.

## Goal
Change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

---

## Analysis

### Application Behavior
- The application provides a stock check feature that fetches data from a provided URL.
- The server-side request is made from the backend, not the browser.
- The admin interface is only reachable from the server itself at `http://localhost/admin`.

### Attack Chain
1. Identify that the stock check parameter accepts arbitrary URLs.
2. Submit `http://localhost/admin` as the stock check URL.
3. The backend requests `http://localhost/admin` on behalf of the attacker.
4. The admin interface responds to the server-side request.
5. Forge a request to delete the target user:
   `http://localhost/admin/delete?username=carlos`

### Why This Works
- SSRF against `localhost` / `127.0.0.1` / `0.0.0.0` bypasses external access controls.
- Internal admin panels are often bound only to the loopback interface.
- If the backend does not validate or restrict the URL scheme/host, an attacker can reach internal services.

---

## Exploitation Steps

### Step 1: Confirm SSRF to localhost
Submit `http://localhost/` in the stock check feature. Observe that the server returns content from the local server rather than the external stock API.

### Step 2: Access the admin interface
Submit `http://localhost/admin`. Confirm that the admin panel HTML/response is returned to the stock check result.

### Step 3: Trigger the delete action
Submit `http://localhost/admin/delete?username=carlos` in the stock check feature.

### Step 4: Solve the lab
If the admin action is executed server-side, the user `carlos` is deleted and the lab should report success.

---

## Impact
- Unauthorized administrative actions (user deletion, config changes).
- Potential full admin panel takeover if SSRF allows state-changing requests (POST).
- In some cases, chainable to RCE via internal services (Redis, Flask/Django debug, metadata APIs).

---

## Remediation
- **URL allowlisting:** Only permit requests to known external hosts.
- **Block private IP ranges:** Reject requests to `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `[::1]`.
- **Block non-HTTP schemes:** Reject `file://`, `gopher://`, `dict://`, `ftp://`.
- **Disable unnecessary internal services** on the same host.
- **Segmentation:** Admin interfaces should not be reachable from the app server loopback unless explicitly required and protected by auth tokens.

---

## Detection (SOC Perspective)
- Monitor outbound HTTP requests from web servers to `localhost`, `127.0.0.1`, and link-local addresses.
- Alert on SSRF-like URL patterns in application parameters: `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]`.
- Check for chained request patterns (GET to admin endpoints from unexpected sources).
- Web firewall rules: inspect query strings and body for internal addresses.

---

## Related CVEs / References
- CWE-918: Server-Side Request Forgery (SSRF)
- PortSwigger: SSRF filter bypass cheat sheet
- OWASP: SSRF Prevention Cheat Sheet

---

## Notes
- This lab is a minimal reproduction of localhost SSRF.
- Advanced SSRF labs introduce cloud metadata endpoints (`169.254.169.254`), blind SSRF, and protocol smuggling.
