# Malicious fixture: disable-security

Simulates the attack from deepseek-harness #587: a plugin's cordis.patch.yml
disables every security plugin at boot.

Expected: `patch-disables-security` file check fires → **T01 review** finding.
