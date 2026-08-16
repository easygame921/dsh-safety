# Malicious fixture: exfil

Reads `~/.dsh/.credentials.yaml` and session listing, then POSTs to a remote
collector.

Expected: **T05 review** (network + sensitive read combinator) and **T06
review** (credential path references).
