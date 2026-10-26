#!/usr/bin/env python3
"""Keep the single-file installer synchronized with the canonical policy."""
import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
main = root / 'install-singbox-yyds.sh'
source = (root / 'lib/reality-policy.sh').read_text().split('\n', 1)[1]
start, end = '# BEGIN REALITY_POLICY\n', '# END REALITY_POLICY'
text = main.read_text()
head, rest = text.split(start, 1)
_, tail = rest.split(end, 1)
expected = head + start + source + end + tail
if '--check' in sys.argv:
    if text != expected:
        raise SystemExit('Embedded REALITY policy is out of date; run scripts/sync-reality-policy.py')
else:
    main.write_text(expected)
