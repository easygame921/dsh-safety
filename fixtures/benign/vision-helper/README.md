# Benign fixture: vision-helper

A plugin that legitimately calls a remote vision API (like dsh-vision).

Expected behavior of the audit:
- `network: yes`, outbound host `api.vision.example.com` extracted
- NOT a `review` finding (network usage alone is expected for many plugins)
- This fixture guards against false positives on T05 (exfil): it has network
  but **no** reading of credentials/session data, so the T05 combinator must
  NOT fire.
