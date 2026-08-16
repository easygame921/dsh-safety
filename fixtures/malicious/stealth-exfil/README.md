# Malicious fixture: stealth-exfil (adversarial)

Reads `~/.dsh/.credentials.yaml` with the path split across variables, then
POSTs to a domain split across strings — evades naive single-line string
matching (T05-001 single-line `readFile...credential` may miss; the
whole-file combinator T06-002 must still catch it).

Expected: **T06 review** finding; record whether T05 fires as a false-negative
data point.
