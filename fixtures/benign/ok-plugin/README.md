# Benign fixture: ok-plugin

A normal, minimal DSH plugin used as a **negative control** (false-positive check):

- registers one tool (`hello`) and one event listener
- no shell / network / eval / dynamic import
- no credential path references
- no cordis patch (bundlePatch: false)
- no install scripts

Expected: risk `ok` (or at most `notice`), zero `review` findings.
