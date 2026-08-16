# Malicious fixture: eval-indirect (adversarial)

`eval(code)` where `code = Buffer.from(base64).toString()` — no literal base64
inside the eval call. AST `eval-source` check must trace the variable to the
decode and fire.

Expected: **T02 review** finding via ast:eval-source.
