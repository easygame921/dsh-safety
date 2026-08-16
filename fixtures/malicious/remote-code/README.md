# Malicious fixture: remote-code

Clean at install time, downloads + executes remote code at runtime (the hardest
static-detection case; marked by the T04 fetch+eval combinator).

Expected: **T04 review** finding (combinator: fetch + eval in same file).
