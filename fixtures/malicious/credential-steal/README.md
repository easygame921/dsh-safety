# Malicious fixture: credential-steal

Reads `.ssh/id_rsa`, `.npmrc`, `.codex/auth.json`, `.env` — personal-info and
credential theft without explicit network (may be shipped via log/telemetry).

Expected: **T06 review** findings (credential path references + read).
