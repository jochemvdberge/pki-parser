#!/bin/bash
cd /workspaces/pki-parser
git status --short
git add -A
git commit -m "Implement certificate display formatting updates

- Change commonName abbr: 'C' → 'CN' for clarity
- Format serial_number with colon separators (e.g. 67:d3:b0:43)
- Display sha256_fingerprint in uppercase

Also regenerate test fixture with valid certificate."

git checkout -b feature/certificate-display-formats 2>/dev/null || true
git push -u origin feature/certificate-display-formats
