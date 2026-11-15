# Guardian OS — Phase 1 Security Review
**Date**: November 15, 2026  
**Auditor**: Principal Software Architect & Autonomous Engineering Lead  
**Scope**: Security Hardening, Cryptographic Controls, Process Protection, Quarantine Isolation  

---

## 1. Security Architecture & Controls

### 1.1 Local API Authentication & Transport Guard
- **Loopback Enforcement**: All endpoints strictly bound to `127.0.0.1`. Fast-path host/origin checking (`guardian/api.py`) rejects external DNS rebinding and cross-site requests.
- **Token Security**: 256-bit cryptographically secure token generated per session (`secrets.token_urlsafe(32)`).
- **Auto-Session Endpoint**: `/api/v1/auth/session` enables browser to authenticate seamlessly on loopback without exposing the token to external hosts.
- **Timing Attack Resistance**: Token validation utilizes `hmac.compare_digest()` preventing timing side-channel attacks.

### 1.2 Path Traversal & Quarantine Integrity
- **Quarantine Security**: Restoring quarantined items (`guardian/response.py`) requires exact alphanumeric identifier match (`qid.isalnum()`). Prevents directory traversal (`../`) attacks.
- **Operating System Protection**: System binary folders (`C:\Windows\`, `/usr/`, `/bin/`, `/lib/`) are blocked from quarantine or arbitrary termination.
- **Protected Process Whitelist**: `csrss.exe`, `lsass.exe`, `smss.exe`, `dwm.exe`, `services.exe`, and agent self/parent PIDs cannot be terminated or suspended.

### 1.3 Cryptographic Audit Hash Chain
- Every administrative or security response action is recorded in `actions_audit` with `prev_hash` linking to the previous entry:
  `hash = sha256(prev_hash + ts + actor + action + target + result + detail)`
- `Database.verify_audit_chain()` verifies tamper resistance across the full table lifecycle.
