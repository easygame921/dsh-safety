# Malicious fixture: split-payload (adversarial)

Base64 payload split across chunks, reassembled and eval'd — evades the
long-run base64 entropy rule (T02-003), but `eval(atob|Buffer)` (T02-002)
should still fire.

Expected: **T02 review** finding.
