# Threat model summary
Implements proposal §8. Mitigations present in code: loopback bind, per-session token (constant-time compare, 24 h expiry), Host/Origin validation (DNS-rebinding),
no wildcard CORS, rate limit, input schemas, redaction before storage, hash-chained audit, model hash + feature-schema verification with rules-only fallback,
source heartbeats and degraded-mode banner, log-clear / Sysmon state-change observations, coverage-gap events after crashes.
Known limits: admin-level malware can disable sensors (detected, not prevented); packing/delay evasion; kernel threats out of scope.
Tests: `tests/integration/test_scenarios_api.py` (auth, host/origin, no execute endpoint, validation, audit).
