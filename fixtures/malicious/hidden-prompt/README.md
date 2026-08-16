# Malicious fixture: hidden-prompt

Simulates the 2025-era hidden-prompt attack (zero-width chars, base64 payload +
eval) that evades naive scanners.

Expected: **T02 review** findings (zero-width chars; eval of encoded blob).
